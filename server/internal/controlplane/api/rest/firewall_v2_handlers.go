package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// /api/v1/firewall/v2/* manages the nftables engine. Mutations wait for
// confirmation (POST .../confirm/{id}) unless called with ?confirm=false.

func (s *Server) setupFirewallV2Routes(api *mux.Router) {
	api.HandleFunc("/firewall/v2/state", s.handleFirewallV2State).Methods("GET")
	api.HandleFunc("/firewall/v2/preview", s.handleFirewallV2Preview).Methods("GET")
	api.HandleFunc("/firewall/v2/services", s.handleFirewallV2CreateService).Methods("POST")
	api.HandleFunc("/firewall/v2/services/{id}", s.handleFirewallV2DeleteService).Methods("DELETE")
	api.HandleFunc("/firewall/v2/ip-rules", s.handleFirewallV2CreateIPRule).Methods("POST")
	api.HandleFunc("/firewall/v2/ip-rules/{id}", s.handleFirewallV2DeleteIPRule).Methods("DELETE")
	api.HandleFunc("/firewall/v2/forwards", s.handleFirewallV2CreateForward).Methods("POST")
	api.HandleFunc("/firewall/v2/forwards/{id}", s.handleFirewallV2DeleteForward).Methods("DELETE")
	api.HandleFunc("/firewall/v2/egress/{nodeId}", s.handleFirewallV2SetEgress).Methods("PUT", "DELETE")
	api.HandleFunc("/firewall/v2/confirm/{id}", s.handleFirewallV2Confirm).Methods("POST")
}

func (s *Server) handleFirewallV2State(w http.ResponseWriter, r *http.Request) {
	if s.firewall == nil {
		engineError(w, firewall.ErrEngineDisabled)
		return
	}
	st, err := s.firewall.LoadState(r.Context())
	if err != nil {
		engineError(w, err)
		return
	}
	resp := map[string]interface{}{
		"mode":            s.firewall.Mode,
		"services":        st.Services,
		"ip_rules":        st.IPRules,
		"forwards":        st.Forwards,
		"egress_node_ids": st.EgressNodeIDs,
		"pending":         nil,
	}
	if p, ok := s.firewall.PendingChange(); ok {
		resp["pending"] = map[string]interface{}{"id": p.ID, "deadline": p.Deadline}
	}
	if host, err := s.firewall.Detect(); err != nil {
		resp["host_error"] = err.Error()
	} else {
		resp["ssh_ports"] = host.SSHPorts
		resp["egress_interface"] = host.Egress
	}
	jsonResponse(w, http.StatusOK, resp)
}

func (s *Server) handleFirewallV2Preview(w http.ResponseWriter, r *http.Request) {
	if s.firewall == nil {
		engineError(w, firewall.ErrEngineDisabled)
		return
	}
	script, warnings, err := s.firewall.Preview(r.Context())
	if err != nil {
		engineError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{"script": script, "warnings": warningStrings(warnings)})
}

// proposeV2 runs a change and writes the common response.
func (s *Server) proposeV2(w http.ResponseWriter, r *http.Request, item interface{}, ch firewall.Change) {
	if s.firewall == nil {
		engineError(w, firewall.ErrEngineDisabled)
		return
	}
	confirm := r.URL.Query().Get("confirm") != "false"
	res, err := s.firewall.Propose(r.Context(), ch, confirm, s.protectAddrs(r))
	if err != nil {
		engineError(w, err)
		return
	}
	var pending interface{}
	if res.Pending != nil {
		pending = map[string]interface{}{"id": res.Pending.ID, "deadline": res.Pending.Deadline}
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"item":     item,
		"pending":  pending,
		"warnings": warningStrings(res.Warnings),
	})
}

type v2ServiceRequest struct {
	Protocol  string   `json:"protocol"`
	PortFrom  int      `json:"port_from"`
	PortTo    int      `json:"port_to"`
	Sources   []string `json:"sources"`
	Interface string   `json:"interface"`
	Comment   string   `json:"comment"`
}

func (s *Server) handleFirewallV2CreateService(w http.ResponseWriter, r *http.Request) {
	var req v2ServiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}
	svc, err := validateService(req)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	s.proposeV2(w, r, svc, addServices(s, svc))
}

func validateService(req v2ServiceRequest) (*models.FirewallService, error) {
	if req.Protocol != "tcp" && req.Protocol != "udp" {
		return nil, fmt.Errorf("protocol must be tcp or udp")
	}
	if req.PortTo == 0 {
		req.PortTo = req.PortFrom
	}
	if req.PortFrom < 1 || req.PortTo > 65535 || req.PortTo < req.PortFrom {
		return nil, fmt.Errorf("invalid port range %d-%d", req.PortFrom, req.PortTo)
	}
	if req.Interface != "" && !nft.ValidInterfaceName(req.Interface) {
		return nil, fmt.Errorf("invalid interface %q", req.Interface)
	}
	sources := []string{}
	for _, src := range req.Sources {
		p, err := canonicalPrefix(src)
		if err != nil {
			return nil, err
		}
		sources = append(sources, p)
	}
	return &models.FirewallService{ID: uuid.New().String(), Protocol: req.Protocol, PortFrom: req.PortFrom,
		PortTo: req.PortTo, Sources: sources, Interface: req.Interface, Comment: req.Comment}, nil
}

// addServices is the change that opens one or more services.
func addServices(s *Server, svcs ...*models.FirewallService) firewall.Change {
	return firewall.Change{
		Mutate: func(st *firewall.State) error {
			st.Services = append(st.Services, svcs...)
			return nil
		},
		Commit: func(ctx context.Context) error { return s.store.CreateFirewallServices(ctx, svcs) },
	}
}

// removeServices is the change that deletes the services with the given IDs.
func removeServices(s *Server, ids ...string) firewall.Change {
	drop := map[string]bool{}
	for _, id := range ids {
		drop[id] = true
	}
	return firewall.Change{
		Mutate: func(st *firewall.State) error {
			kept := st.Services[:0:0]
			found := 0
			for _, svc := range st.Services {
				if drop[svc.ID] {
					found++
					continue
				}
				kept = append(kept, svc)
			}
			if found != len(drop) {
				return fmt.Errorf("service %w", errNotFound)
			}
			st.Services = kept
			return nil
		},
		Commit: func(ctx context.Context) error {
			for id := range drop {
				if err := s.store.DeleteFirewallService(ctx, id); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func (s *Server) handleFirewallV2DeleteService(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s.proposeV2(w, r, map[string]string{"id": id}, removeServices(s, id))
}

type v2IPRuleRequest struct {
	Action    string     `json:"action"`
	Prefix    string     `json:"prefix"`
	Protocol  string     `json:"protocol"`
	Ports     string     `json:"ports"`
	ExpiresAt *time.Time `json:"expires_at"`
	Comment   string     `json:"comment"`
}

func (s *Server) handleFirewallV2CreateIPRule(w http.ResponseWriter, r *http.Request) {
	var req v2IPRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}
	rule, err := validateIPRule(req, "panel", time.Now())
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	s.proposeV2(w, r, rule, addIPRule(s, rule))
}

func validateIPRule(req v2IPRuleRequest, origin string, now time.Time) (*models.FirewallIPRule, error) {
	if req.Action != "block" && req.Action != "allow" {
		return nil, fmt.Errorf("action must be block or allow")
	}
	prefix, err := canonicalPrefix(req.Prefix)
	if err != nil {
		return nil, err
	}
	if req.Protocol != "" && req.Protocol != "tcp" && req.Protocol != "udp" {
		return nil, fmt.Errorf("protocol must be tcp, udp or empty")
	}
	if req.Ports != "" {
		if req.Protocol == "" {
			req.Protocol = "tcp" // the legacy panel blocked and allowed TCP ports
		}
		if _, err := firewall.ParsePorts(req.Ports); err != nil {
			return nil, err
		}
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.After(now) {
		return nil, fmt.Errorf("expires_at must be in the future")
	}
	return &models.FirewallIPRule{ID: uuid.New().String(), Action: req.Action, Prefix: prefix, Protocol: req.Protocol,
		Ports: req.Ports, ExpiresAt: req.ExpiresAt, Origin: origin, Comment: req.Comment}, nil
}

func addIPRule(s *Server, rule *models.FirewallIPRule) firewall.Change {
	return firewall.Change{
		Mutate: func(st *firewall.State) error {
			st.IPRules = append(st.IPRules, rule)
			return nil
		},
		Commit: func(ctx context.Context) error { return s.store.CreateFirewallIPRule(ctx, rule) },
	}
}

// removeIPRules is the change that deletes the IP rules with the given IDs.
func removeIPRules(s *Server, ids ...string) firewall.Change {
	drop := map[string]bool{}
	for _, id := range ids {
		drop[id] = true
	}
	return firewall.Change{
		Mutate: func(st *firewall.State) error {
			kept := st.IPRules[:0:0]
			found := 0
			for _, rule := range st.IPRules {
				if drop[rule.ID] {
					found++
					continue
				}
				kept = append(kept, rule)
			}
			if found != len(drop) {
				return fmt.Errorf("IP rule %w", errNotFound)
			}
			st.IPRules = kept
			return nil
		},
		Commit: func(ctx context.Context) error {
			for id := range drop {
				if err := s.store.DeleteFirewallIPRule(ctx, id); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func (s *Server) handleFirewallV2DeleteIPRule(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s.proposeV2(w, r, map[string]string{"id": id}, removeIPRules(s, id))
}

type v2ForwardRequest struct {
	Protocol   string `json:"protocol"`
	PublicPort int    `json:"public_port"`
	TargetIP   string `json:"target_ip"`
	TargetPort int    `json:"target_port"`
	Comment    string `json:"comment"`
}

func (s *Server) handleFirewallV2CreateForward(w http.ResponseWriter, r *http.Request) {
	var req v2ForwardRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}
	if req.Protocol != "tcp" && req.Protocol != "udp" {
		errorResponse(w, http.StatusBadRequest, "protocol must be tcp or udp")
		return
	}
	if req.PublicPort < 1 || req.PublicPort > 65535 || req.TargetPort < 1 || req.TargetPort > 65535 {
		errorResponse(w, http.StatusBadRequest, "ports must be 1-65535")
		return
	}
	ip, err := netip.ParseAddr(req.TargetIP)
	if err != nil || !ip.Unmap().Is4() {
		errorResponse(w, http.StatusBadRequest, "target_ip must be an IPv4 address of a VPN node")
		return
	}
	f := &models.FirewallForward{ID: uuid.New().String(), Protocol: req.Protocol, PublicPort: req.PublicPort,
		TargetIP: ip.Unmap().String(), TargetPort: req.TargetPort, Comment: req.Comment}
	s.proposeV2(w, r, f, firewall.Change{
		Mutate: func(st *firewall.State) error {
			for _, x := range st.Forwards {
				if x.Protocol == f.Protocol && x.PublicPort == f.PublicPort {
					return fmt.Errorf("%w: %s port %d is already forwarded", errConflict, f.Protocol, f.PublicPort)
				}
			}
			st.Forwards = append(st.Forwards, f)
			return nil
		},
		Commit: func(ctx context.Context) error { return s.store.CreateFirewallForward(ctx, f) },
	})
}

func (s *Server) handleFirewallV2DeleteForward(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s.proposeV2(w, r, map[string]string{"id": id}, firewall.Change{
		Mutate: func(st *firewall.State) error {
			for i, f := range st.Forwards {
				if f.ID == id {
					st.Forwards = append(st.Forwards[:i:i], st.Forwards[i+1:]...)
					return nil
				}
			}
			return fmt.Errorf("forward %w", errNotFound)
		},
		Commit: func(ctx context.Context) error { return s.store.DeleteFirewallForward(ctx, id) },
	})
}

func (s *Server) handleFirewallV2SetEgress(w http.ResponseWriter, r *http.Request) {
	nodeID := mux.Vars(r)["nodeId"]
	node, err := s.store.GetNode(r.Context(), nodeID)
	if err != nil || node == nil {
		errorResponse(w, http.StatusNotFound, "node not found")
		return
	}
	enable := r.Method == http.MethodPut
	s.proposeV2(w, r, map[string]interface{}{"node_id": nodeID, "egress": enable}, firewall.Change{
		Mutate: func(st *firewall.State) error {
			kept := st.EgressNodeIDs[:0:0]
			for _, id := range st.EgressNodeIDs {
				if id != nodeID {
					kept = append(kept, id)
				}
			}
			if enable {
				kept = append(kept, nodeID)
			}
			st.EgressNodeIDs = kept
			return nil
		},
		Commit: func(ctx context.Context) error { return s.store.SetNodeEgress(ctx, nodeID, enable) },
	})
}

func (s *Server) handleFirewallV2Confirm(w http.ResponseWriter, r *http.Request) {
	if s.firewall == nil {
		engineError(w, firewall.ErrEngineDisabled)
		return
	}
	if err := s.firewall.Confirm(r.Context(), mux.Vars(r)["id"]); err != nil {
		engineError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"status": "confirmed"})
}
