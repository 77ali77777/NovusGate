package rest

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// Legacy (v1) firewall endpoints in nft mode. They keep the request and
// response shapes the existing panel uses, but read and write the engine's
// tables. They apply immediately (no confirmation UI exists for them); the
// lockout guard still protects every change.

// displayPrefix shows single addresses without their /32 or /128.
func displayPrefix(p string) string {
	return strings.TrimSuffix(strings.TrimSuffix(p, "/32"), "/128")
}

// v1Entry is one synthesized INPUT rule with the record it came from.
type v1Entry struct {
	rule      FirewallRule
	serviceID string
	ipRuleID  string
}

// v1Entries lists the INPUT chain the legacy panel shows: structural rules
// managed by NovusGate (protected) first, then services and IP rules.
func (s *Server) v1Entries(ctx context.Context) ([]v1Entry, error) {
	host, err := s.firewall.Detect()
	if err != nil {
		return nil, err
	}
	st, err := s.firewall.LoadState(ctx)
	if err != nil {
		return nil, err
	}
	var out []v1Entry
	add := func(e v1Entry) {
		e.rule.Number = len(out) + 1
		e.rule.Chain = "INPUT"
		if e.rule.Source == "" {
			e.rule.Source = "anywhere"
		}
		e.rule.Destination = "anywhere"
		out = append(out, e)
	}
	for _, p := range host.SSHPorts {
		add(v1Entry{rule: FirewallRule{Target: "ACCEPT", Protocol: "tcp", Port: strconv.Itoa(int(p)), Options: "SSH", Protected: true}})
	}
	add(v1Entry{rule: FirewallRule{Target: "ACCEPT", Protocol: "udp", Port: "51820:51900", Options: "WireGuard", Protected: true}})
	networks, err := s.store.ListNetworks(ctx)
	if err != nil {
		return nil, err
	}
	for _, n := range networks {
		if n.ListenPort > 0 && (n.ListenPort < int(nft.LegacyWireGuardRange.From) || n.ListenPort > int(nft.LegacyWireGuardRange.To)) {
			add(v1Entry{rule: FirewallRule{Target: "ACCEPT", Protocol: "udp", Port: strconv.Itoa(n.ListenPort),
				Options: "WireGuard " + n.InterfaceName, Protected: true}})
		}
	}
	for _, p := range nft.AdminPorts {
		add(v1Entry{rule: FirewallRule{Target: "ACCEPT", Protocol: "tcp", Port: strconv.Itoa(int(p)),
			Interface: nft.AdminInterface, InInterface: nft.AdminInterface, Options: "admin VPN only", Protected: true}})
	}
	for _, p := range nft.APIPorts {
		add(v1Entry{rule: FirewallRule{Target: "ACCEPT", Protocol: "tcp", Port: strconv.Itoa(int(p)),
			Interface: nft.VPNInterfacePattern, InInterface: nft.VPNInterfacePattern, Options: "VPN only", Protected: true}})
	}
	for _, svc := range st.Services {
		port := strconv.Itoa(svc.PortFrom)
		if svc.PortTo != svc.PortFrom {
			port = fmt.Sprintf("%d:%d", svc.PortFrom, svc.PortTo)
		}
		add(v1Entry{serviceID: svc.ID, rule: FirewallRule{Target: "ACCEPT", Protocol: svc.Protocol, Port: port,
			Source: strings.Join(svc.Sources, ","), Interface: svc.Interface, InInterface: svc.Interface, Options: svc.Comment}})
	}
	now := time.Now()
	for _, r := range st.IPRules {
		if r.ExpiresAt != nil && !r.ExpiresAt.After(now) {
			continue
		}
		target := "ACCEPT"
		if r.Action == "block" {
			target = "DROP"
		}
		proto := r.Protocol
		if proto == "" {
			proto = "all"
		}
		add(v1Entry{ipRuleID: r.ID, rule: FirewallRule{Target: target, Protocol: proto, Port: r.Ports,
			Source: displayPrefix(r.Prefix), Options: r.Comment}})
	}
	return out, nil
}

func (s *Server) handleFirewallGetRulesNft(w http.ResponseWriter, r *http.Request, chains []string) {
	entries, err := s.v1Entries(r.Context())
	if err != nil {
		engineError(w, err)
		return
	}
	result := FirewallStatus{Chains: []ChainInfo{}}
	for _, name := range chains {
		chain := ChainInfo{Name: name, Policy: "ACCEPT", Rules: []FirewallRule{}}
		if name == "INPUT" {
			chain.Policy = "DROP"
			for _, e := range entries {
				chain.Rules = append(chain.Rules, e.rule)
				if e.rule.Target == "DROP" && e.rule.Source != "anywhere" {
					result.BlockedIPs++
				}
				if e.rule.Target == "ACCEPT" && e.rule.Port != "" {
					result.OpenPorts++
				}
			}
		}
		result.TotalRules += len(chain.Rules)
		result.Chains = append(result.Chains, chain)
	}
	jsonResponse(w, http.StatusOK, result)
}

func (s *Server) handleFirewallOpenPortNft(w http.ResponseWriter, r *http.Request, req OpenPortRequest, protocols []string) {
	var sources []string
	if req.Source != "" {
		p, err := canonicalPrefix(req.Source)
		if err != nil {
			errorResponse(w, http.StatusBadRequest, "invalid source IP/CIDR")
			return
		}
		sources = []string{p}
	}
	var svcs []*models.FirewallService
	for _, proto := range protocols {
		svcs = append(svcs, &models.FirewallService{ID: uuid.New().String(), Protocol: proto,
			PortFrom: req.Port, PortTo: req.Port, Sources: append([]string{}, sources...)})
	}
	if _, err := s.firewall.Propose(r.Context(), addServices(s, svcs...), false, s.protectAddrs(r)); err != nil {
		engineError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, OpenPortResponse{
		Status:   "success",
		Message:  fmt.Sprintf("Port %d/%s opened successfully", req.Port, req.Protocol),
		Port:     req.Port,
		Protocol: req.Protocol,
		Source:   req.Source,
	})
}

func (s *Server) handleFirewallClosePortNft(w http.ResponseWriter, r *http.Request, req ClosePortRequest, protocols []string) {
	host, err := s.firewall.Detect()
	if err != nil {
		engineError(w, err)
		return
	}
	for _, p := range host.SSHPorts {
		if int(p) == req.Port && !req.Force {
			errorWithCode(w, http.StatusForbidden, "protected_rule", fmt.Sprintf("port %d (SSH) is protected. Set force=true to override", req.Port))
			return
		}
	}
	st, err := s.firewall.LoadState(r.Context())
	if err != nil {
		engineError(w, err)
		return
	}
	var ids []string
	for _, svc := range st.Services {
		for _, proto := range protocols {
			if svc.Protocol == proto && svc.PortFrom == req.Port && svc.PortTo == req.Port {
				ids = append(ids, svc.ID)
			}
		}
	}
	if len(ids) > 0 {
		if _, err := s.firewall.Propose(r.Context(), removeServices(s, ids...), false, s.protectAddrs(r)); err != nil {
			engineError(w, err)
			return
		}
	}
	jsonResponse(w, http.StatusOK, ClosePortResponse{
		Status:       "success",
		Message:      fmt.Sprintf("Port %d/%s closed successfully", req.Port, req.Protocol),
		Port:         req.Port,
		Protocol:     req.Protocol,
		RulesDeleted: len(ids),
	})
}

// handleFirewallIPRuleNft implements legacy Block IP and Allow IP.
func (s *Server) handleFirewallIPRuleNft(w http.ResponseWriter, r *http.Request, action, ip, ports string) {
	rule, err := validateIPRule(v2IPRuleRequest{Action: action, Prefix: ip, Ports: ports}, "panel", time.Now())
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.firewall.Propose(r.Context(), addIPRule(s, rule), false, s.protectAddrs(r)); err != nil {
		engineError(w, err)
		return
	}
	verb := "blocked"
	if action == "allow" {
		verb = "allowed"
	}
	jsonResponse(w, http.StatusOK, IPRuleResponse{
		Status:  "success",
		Message: fmt.Sprintf("IP %s %s successfully", ip, verb),
		IP:      ip,
		Ports:   ports,
	})
}

func (s *Server) handleFirewallDeleteRuleNft(w http.ResponseWriter, r *http.Request, req DeleteRuleRequest) {
	if req.Chain != "INPUT" {
		errorResponse(w, http.StatusNotFound, fmt.Sprintf("rule %d not found in chain %s", req.LineNumber, req.Chain))
		return
	}
	entries, err := s.v1Entries(r.Context())
	if err != nil {
		engineError(w, err)
		return
	}
	if req.LineNumber > len(entries) {
		errorResponse(w, http.StatusNotFound, fmt.Sprintf("rule %d not found in chain %s", req.LineNumber, req.Chain))
		return
	}
	e := entries[req.LineNumber-1]
	if e.rule.Protected {
		// Structural rules are part of every compiled ruleset; force cannot remove them.
		errorWithCode(w, http.StatusForbidden, "protected_rule", fmt.Sprintf("rule %d is protected (SSH/WireGuard/Admin) and managed by NovusGate", req.LineNumber))
		return
	}
	ch := removeServices(s, e.serviceID)
	if e.ipRuleID != "" {
		ch = removeIPRules(s, e.ipRuleID)
	}
	if _, err := s.firewall.Propose(r.Context(), ch, false, s.protectAddrs(r)); err != nil {
		engineError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, DeleteRuleResponse{
		Status:      "success",
		Message:     fmt.Sprintf("Rule %d deleted from chain %s", req.LineNumber, req.Chain),
		Chain:       req.Chain,
		LineNumber:  req.LineNumber,
		DeletedRule: e.rule,
	})
}

func (s *Server) handleFirewallExportNft(w http.ResponseWriter, r *http.Request) {
	out, err := s.firewall.Applier.Exec.Runner.Run("", "nft", "list", "table", "inet", nft.TableName)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to export rules: %v", err))
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=\"novusgate-nftables.txt\"")
	w.Write([]byte(out))
}

func (s *Server) handleFirewallResetNft(w http.ResponseWriter, r *http.Request) {
	ch := firewall.Change{
		Mutate: func(st *firewall.State) error {
			st.Services, st.IPRules = nil, nil
			return nil
		},
		Commit: s.store.ResetFirewallHostRules,
	}
	if _, err := s.firewall.Propose(r.Context(), ch, false, s.protectAddrs(r)); err != nil {
		engineError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, StatusMessageResponse{
		Status:  "success",
		Message: "Firewall reset to default NovusGate configuration",
	})
}

// Fail2Ban permanent bans are whole-address blocks in the engine.

func (s *Server) handleFail2BanPermanentBanNft(w http.ResponseWriter, r *http.Request, ip string) {
	rule, err := validateIPRule(v2IPRuleRequest{Action: "block", Prefix: ip}, "fail2ban", time.Now())
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.firewall.Propose(r.Context(), addIPRule(s, rule), false, s.protectAddrs(r)); err != nil {
		engineError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, Fail2BanBanResponse{Status: "success",
		Message: fmt.Sprintf("IP %s permanently banned via nftables", ip), Type: "permanent"})
}

// wholeBlocks returns whole-address blocks (the legacy "permanent bans").
func wholeBlocks(st firewall.State) []*models.FirewallIPRule {
	var out []*models.FirewallIPRule
	for _, r := range st.IPRules {
		if r.Action == "block" && r.Ports == "" && r.ExpiresAt == nil {
			out = append(out, r)
		}
	}
	return out
}

func (s *Server) handleFail2BanGetPermanentBansNft(w http.ResponseWriter, r *http.Request) {
	st, err := s.firewall.LoadState(r.Context())
	if err != nil {
		engineError(w, err)
		return
	}
	bans := []PermanentBan{}
	for i, rule := range wholeBlocks(st) {
		bans = append(bans, PermanentBan{LineNumber: strconv.Itoa(i + 1), IP: displayPrefix(rule.Prefix), Target: "DROP", Protocol: "all"})
	}
	jsonResponse(w, http.StatusOK, PermanentBansResponse{PermanentBans: bans, Count: len(bans)})
}

func (s *Server) handleFail2BanRemovePermanentBanNft(w http.ResponseWriter, r *http.Request, ip string) {
	prefix, err := canonicalPrefix(ip)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid IP address")
		return
	}
	st, err := s.firewall.LoadState(r.Context())
	if err != nil {
		engineError(w, err)
		return
	}
	var ids []string
	for _, rule := range wholeBlocks(st) {
		if rule.Prefix == prefix {
			ids = append(ids, rule.ID)
		}
	}
	if len(ids) == 0 {
		errorResponse(w, http.StatusNotFound, fmt.Sprintf("no permanent ban for %s", ip))
		return
	}
	if _, err := s.firewall.Propose(r.Context(), removeIPRules(s, ids...), false, s.protectAddrs(r)); err != nil {
		engineError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, StatusMessageResponse{Status: "success", Message: fmt.Sprintf("Permanent ban removed for IP %s", ip)})
}
