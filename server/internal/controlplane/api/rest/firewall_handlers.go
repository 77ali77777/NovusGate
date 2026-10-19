package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/netctl/nft"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// FirewallRule represents a parsed iptables rule
type FirewallRule struct {
	Number       int    `json:"number"`
	Chain        string `json:"chain"`
	Target       string `json:"target"`      // ACCEPT, DROP, REJECT
	Protocol     string `json:"protocol"`    // tcp, udp, icmp, all
	Source       string `json:"source"`      // IP/CIDR or "anywhere"
	Destination  string `json:"destination"` // IP/CIDR or "anywhere"
	Port         string `json:"port"`        // port number or range
	Interface    string `json:"interface"`   // wg0, eth0, etc.
	InInterface  string `json:"in_interface,omitempty"`
	OutInterface string `json:"out_interface,omitempty"`
	Options      string `json:"options,omitempty"`
	Protected    bool   `json:"protected"` // Cannot be deleted
}

// ChainInfo represents information about an iptables chain
type ChainInfo struct {
	Name   string         `json:"name"`
	Policy string         `json:"policy"` // ACCEPT or DROP
	Rules  []FirewallRule `json:"rules"`
}

// FirewallStatus represents the overall firewall status
type FirewallStatus struct {
	Chains     []ChainInfo `json:"chains"`
	TotalRules int         `json:"total_rules"`
	BlockedIPs int         `json:"blocked_ips"`
	OpenPorts  int         `json:"open_ports"`
}

// OpenPortRequest represents a request to open a port
type OpenPortRequest struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // tcp, udp, both
	Source   string `json:"source"`   // Optional: restrict to IP/CIDR
}

// ClosePortRequest represents a request to close a port
type ClosePortRequest struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // tcp, udp, both
	Force    bool   `json:"force"`    // Force close even if SSH port
}

// BlockIPRequest represents a request to block an IP
type BlockIPRequest struct {
	IP    string `json:"ip"`    // IP or CIDR
	Ports string `json:"ports"` // Optional: specific ports, empty = all
}

// AllowIPRequest represents a request to allow an IP
type AllowIPRequest struct {
	IP    string `json:"ip"`    // IP or CIDR
	Ports string `json:"ports"` // Optional: specific ports, empty = all
}

// DeleteRuleRequest represents a request to delete a rule
type DeleteRuleRequest struct {
	Chain      string `json:"chain"`
	LineNumber int    `json:"line_number"`
	Force      bool   `json:"force"` // Force delete even if protected
}

// ImportRulesRequest represents a request to import firewall rules
type ImportRulesRequest struct {
	Rules string `json:"rules"` // iptables-save format
}

// Protected ports that cannot be easily closed
var protectedPorts = map[int]string{
	22: "SSH",
}

// legacySSHPorts returns the ports sshd uses, so the iptables code paths
// never close SSH on a custom port; 22 alone when detection fails, as before
// (replaced in tests).
var legacySSHPorts = func() []uint16 {
	ports, err := nft.DetectSSHPorts(nft.HostRunner{})
	if err != nil {
		return []uint16{22}
	}
	return ports
}

func isSSHPort(port string, sshPorts []uint16) bool {
	for _, p := range sshPorts {
		if port == strconv.Itoa(int(p)) {
			return true
		}
	}
	return false
}

// isProtectedRule checks if a rule is protected (SSH, WireGuard, Admin API)
func isProtectedRule(rule FirewallRule, sshPorts []uint16) bool {
	// Protect SSH rules
	if isSSHPort(rule.Port, sshPorts) && rule.Target == "ACCEPT" {
		return true
	}

	// Protect WireGuard ports (51820+)
	if rule.Port != "" {
		port, err := strconv.Atoi(rule.Port)
		if err == nil && port >= 51820 && port <= 51830 && rule.Target == "ACCEPT" {
			return true
		}
	}

	// Protect rules for wg+ interfaces (WireGuard)
	if strings.HasPrefix(rule.Interface, "wg") || strings.HasPrefix(rule.InInterface, "wg") {
		return true
	}

	return false
}

// parseIptablesOutput parses the output of iptables -L -n -v --line-numbers
func parseIptablesOutput(output string, chainName string) (*ChainInfo, error) {
	lines := strings.Split(output, "\n")
	chain := &ChainInfo{
		Name:   chainName,
		Policy: "ACCEPT",
		Rules:  []FirewallRule{},
	}

	// Parse chain header for policy
	// Format: "Chain INPUT (policy ACCEPT 0 packets, 0 bytes)"
	for _, line := range lines {
		if strings.HasPrefix(line, "Chain "+chainName) {
			if strings.Contains(line, "policy DROP") {
				chain.Policy = "DROP"
			} else if strings.Contains(line, "policy REJECT") {
				chain.Policy = "REJECT"
			}
			break
		}
	}

	sshPorts := legacySSHPorts()

	// Parse rules
	// Format: "num   pkts bytes target     prot opt in     out     source               destination"
	// Example: "1     100  5000 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22"
	inRules := false
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines
		if line == "" {
			continue
		}

		// Skip header line
		if strings.HasPrefix(line, "num") || strings.HasPrefix(line, "Chain") {
			if strings.HasPrefix(line, "Chain "+chainName) {
				inRules = true
			}
			continue
		}

		if !inRules {
			continue
		}

		// Stop if we hit another chain
		if strings.HasPrefix(line, "Chain ") {
			break
		}

		rule := parseRuleLine(line, chainName)
		if rule != nil {
			rule.Protected = isProtectedRule(*rule, sshPorts)
			chain.Rules = append(chain.Rules, *rule)
		}
	}

	return chain, nil
}

// parseRuleLine parses a single iptables rule line
func parseRuleLine(line string, chainName string) *FirewallRule {
	fields := strings.Fields(line)
	// num pkts bytes target prot [opt] in out source destination [options...]
	// Newer iptables (nf_tables) omits the "opt" column.
	if len(fields) < 6 {
		return nil
	}
	in := 5
	if isOptColumn(fields[5]) {
		in = 6
	}
	if len(fields) < in+4 {
		return nil
	}
	lineNum, err := strconv.Atoi(fields[0])
	if err != nil {
		return nil
	}
	rule := &FirewallRule{Number: lineNum, Chain: chainName, Target: fields[3], Protocol: fields[4]}
	if fields[in] != "*" {
		rule.InInterface = fields[in]
		rule.Interface = fields[in]
	}
	if fields[in+1] != "*" {
		rule.OutInterface = fields[in+1]
		if rule.Interface == "" {
			rule.Interface = fields[in+1]
		}
	}
	rule.Source = fields[in+2]
	if rule.Source == "0.0.0.0/0" {
		rule.Source = "anywhere"
	}
	rule.Destination = fields[in+3]
	if rule.Destination == "0.0.0.0/0" {
		rule.Destination = "anywhere"
	}

	// Look for patterns like "tcp dpt:22" or "tcp dpts:8000:9000" or "multiport dports 80,443"
	remaining := strings.Join(fields[in+4:], " ")
	rule.Options = remaining

	// Extract port from options; a "/* comment */" may itself contain "dpt:".
	rule.Port = extractPort(ruleCommentRe.ReplaceAllString(remaining, ""))

	return rule
}

// extractPort extracts port information from iptables options string
func extractPort(options string) string {
	// Match patterns like "dpt:22", "dpts:8000:9000", "dports 80,443"
	patterns := []string{
		`dpt:(\d+)`,      // Single port
		`dpts:(\d+:\d+)`, // Port range
		`dports\s+(\S+)`, // Multiple ports
		`spt:(\d+)`,      // Source port
		`spts:(\d+:\d+)`, // Source port range
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(options)
		if len(matches) > 1 {
			return matches[1]
		}
	}

	return ""
}

// handleFirewallGetRules returns all iptables rules grouped by chain
func (s *Server) handleFirewallGetRules(w http.ResponseWriter, r *http.Request) {
	// Get chain from query param, default to all
	chainFilter := r.URL.Query().Get("chain")

	chains := []string{"INPUT", "FORWARD", "OUTPUT"}
	if chainFilter != "" {
		chainFilter = strings.ToUpper(chainFilter)
		if chainFilter != "INPUT" && chainFilter != "FORWARD" && chainFilter != "OUTPUT" {
			errorResponse(w, http.StatusBadRequest, "invalid chain: must be INPUT, FORWARD, or OUTPUT")
			return
		}
		chains = []string{chainFilter}
	}

	if s.engineEnforces() {
		s.handleFirewallGetRulesNft(w, r, chains)
		return
	}

	result := FirewallStatus{
		Chains:     []ChainInfo{},
		TotalRules: 0,
		BlockedIPs: 0,
		OpenPorts:  0,
	}

	for _, chainName := range chains {
		// Execute iptables command via nsenter (for Docker compatibility)
		output, err := execHostCommand("iptables", "-L", chainName, "-n", "-v", "--line-numbers")
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to get %s chain: %v", chainName, err))
			return
		}

		chain, err := parseIptablesOutput(output, chainName)
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to parse %s chain: %v", chainName, err))
			return
		}

		result.Chains = append(result.Chains, *chain)
		result.TotalRules += len(chain.Rules)

		// Count blocked IPs and open ports
		for _, rule := range chain.Rules {
			if rule.Target == "DROP" || rule.Target == "REJECT" {
				if rule.Source != "anywhere" && rule.Source != "" {
					result.BlockedIPs++
				}
			}
			if rule.Target == "ACCEPT" && rule.Port != "" && chainName == "INPUT" {
				result.OpenPorts++
			}
		}
	}

	jsonResponse(w, http.StatusOK, result)
}

// handleFirewallOpenPort opens a port in the firewall
func (s *Server) handleFirewallOpenPort(w http.ResponseWriter, r *http.Request) {
	var req OpenPortRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}

	// Validate port
	if req.Port < 1 || req.Port > 65535 {
		errorResponse(w, http.StatusBadRequest, "invalid port number: must be between 1 and 65535")
		return
	}

	// Validate protocol
	if req.Protocol == "" {
		req.Protocol = "tcp"
	}
	req.Protocol = strings.ToLower(req.Protocol)
	if req.Protocol != "tcp" && req.Protocol != "udp" && req.Protocol != "both" {
		errorResponse(w, http.StatusBadRequest, "invalid protocol: must be tcp, udp, or both")
		return
	}

	// Validate source IP if provided
	if req.Source != "" {
		if net.ParseIP(req.Source) == nil {
			if _, _, err := net.ParseCIDR(req.Source); err != nil {
				errorResponse(w, http.StatusBadRequest, "invalid source IP/CIDR")
				return
			}
		}
	}

	protocols := []string{req.Protocol}
	if req.Protocol == "both" {
		protocols = []string{"tcp", "udp"}
	}

	if s.engineEnforces() {
		s.handleFirewallOpenPortNft(w, r, req, protocols)
		return
	}

	for _, proto := range protocols {
		args := []string{"-A", "INPUT", "-p", proto, "--dport", strconv.Itoa(req.Port), "-j", "ACCEPT"}
		if req.Source != "" {
			args = []string{"-A", "INPUT", "-s", req.Source, "-p", proto, "--dport", strconv.Itoa(req.Port), "-j", "ACCEPT"}
		}

		_, err := execHostCommand("iptables", args...)
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to open port: %v", err))
			return
		}
	}

	// Save rules with netfilter-persistent
	execHostCommand("netfilter-persistent", "save")

	jsonResponse(w, http.StatusOK, OpenPortResponse{
		Status:   "success",
		Message:  fmt.Sprintf("Port %d/%s opened successfully", req.Port, req.Protocol),
		Port:     req.Port,
		Protocol: req.Protocol,
		Source:   req.Source,
	})
}

// handleFirewallClosePort closes a port in the firewall
func (s *Server) handleFirewallClosePort(w http.ResponseWriter, r *http.Request) {
	var req ClosePortRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}

	// Validate port
	if req.Port < 1 || req.Port > 65535 {
		errorResponse(w, http.StatusBadRequest, "invalid port number: must be between 1 and 65535")
		return
	}

	// Check if this is a protected port
	if portName, isProtected := protectedPorts[req.Port]; isProtected && !req.Force {
		errorWithCode(w, http.StatusForbidden, "protected_rule", fmt.Sprintf("port %d (%s) is protected. Set force=true to override", req.Port, portName))
		return
	}
	if isSSHPort(strconv.Itoa(req.Port), legacySSHPorts()) && !req.Force {
		errorWithCode(w, http.StatusForbidden, "protected_rule", fmt.Sprintf("port %d (SSH) is protected. Set force=true to override", req.Port))
		return
	}

	// Validate protocol
	if req.Protocol == "" {
		req.Protocol = "tcp"
	}
	req.Protocol = strings.ToLower(req.Protocol)
	if req.Protocol != "tcp" && req.Protocol != "udp" && req.Protocol != "both" {
		errorResponse(w, http.StatusBadRequest, "invalid protocol: must be tcp, udp, or both")
		return
	}

	protocols := []string{req.Protocol}
	if req.Protocol == "both" {
		protocols = []string{"tcp", "udp"}
	}

	if s.engineEnforces() {
		s.handleFirewallClosePortNft(w, r, req, protocols)
		return
	}

	deletedCount := 0
	for _, proto := range protocols {
		// Find and delete all ACCEPT rules for this port
		// We need to loop because there might be multiple rules
		for {
			// Get current rules
			output, err := execHostCommand("iptables", "-L", "INPUT", "-n", "-v", "--line-numbers")
			if err != nil {
				break
			}

			// Find rule number for this port
			lineNum := findRuleLineNumber(output, proto, req.Port, "ACCEPT")
			if lineNum == 0 {
				break
			}

			// Delete the rule
			_, err = execHostCommand("iptables", "-D", "INPUT", strconv.Itoa(lineNum))
			if err != nil {
				break
			}
			deletedCount++
		}
	}

	// Save rules with netfilter-persistent
	execHostCommand("netfilter-persistent", "save")

	jsonResponse(w, http.StatusOK, ClosePortResponse{
		Status:       "success",
		Message:      fmt.Sprintf("Port %d/%s closed successfully", req.Port, req.Protocol),
		Port:         req.Port,
		Protocol:     req.Protocol,
		RulesDeleted: deletedCount,
	})
}

// protoNumbers maps protocol names to the numeric form newer iptables prints with -n.
var protoNumbers = map[string]string{"tcp": "6", "udp": "17"}

// isOptColumn reports whether a field is the iptables "opt" column, which
// newer iptables versions omit from `-L -n -v` output.
func isOptColumn(field string) bool {
	return field == "--" || field == "-f" || field == "!f"
}

// findRuleLineNumber returns the line number of an INPUT rule created by
// handleFirewallOpenPort (no input-interface restriction) for the given
// protocol and port, or 0 if none matches. Port matching is exact, so
// closing port 3 never touches a rule for 3007, and port ranges never match.
func findRuleLineNumber(output string, protocol string, port int, target string) int {
	wantPort := "dpt:" + strconv.Itoa(port)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		// num pkts bytes target prot [opt] in out source destination [options...]
		if len(fields) < 9 {
			continue
		}
		lineNum, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		if fields[3] != target {
			continue
		}
		if fields[4] != protocol && fields[4] != protoNumbers[protocol] {
			continue
		}
		inIdx := 5
		if isOptColumn(fields[5]) {
			inIdx = 6
		}
		optionsIdx := inIdx + 4
		if len(fields) <= optionsIdx {
			continue
		}
		// Open Port never sets an input interface; interface-scoped rules
		// (wg0 admin panel, wg+ API) belong to the installer and must stay.
		if fields[inIdx] != "*" {
			continue
		}
		for _, opt := range fields[optionsIdx:] {
			if opt == wantPort {
				return lineNum
			}
		}
	}
	return 0
}

// handleFirewallBlockIP blocks an IP address
func (s *Server) handleFirewallBlockIP(w http.ResponseWriter, r *http.Request) {
	var req BlockIPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}

	// Validate IP/CIDR
	if req.IP == "" {
		errorResponse(w, http.StatusBadRequest, "ip is required")
		return
	}

	if net.ParseIP(req.IP) == nil {
		if _, _, err := net.ParseCIDR(req.IP); err != nil {
			errorResponse(w, http.StatusBadRequest, "invalid IP address or CIDR")
			return
		}
	}

	if s.engineEnforces() {
		s.handleFirewallIPRuleNft(w, r, "block", req.IP, req.Ports)
		return
	}

	// Build iptables command
	args := []string{"-I", "INPUT", "-s", req.IP}

	// Add port restriction if specified
	if req.Ports != "" {
		// Parse ports - could be single port, range, or comma-separated
		if strings.Contains(req.Ports, ",") {
			// Multiple ports - use multiport
			args = append(args, "-p", "tcp", "-m", "multiport", "--dports", req.Ports)
		} else if strings.Contains(req.Ports, ":") {
			// Port range
			args = append(args, "-p", "tcp", "--dport", req.Ports)
		} else {
			// Single port
			args = append(args, "-p", "tcp", "--dport", req.Ports)
		}
	}

	args = append(args, "-j", "DROP")

	_, err := execHostCommand("iptables", args...)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to block IP: %v", err))
		return
	}

	// Save rules with netfilter-persistent
	execHostCommand("netfilter-persistent", "save")

	jsonResponse(w, http.StatusOK, IPRuleResponse{
		Status:  "success",
		Message: fmt.Sprintf("IP %s blocked successfully", req.IP),
		IP:      req.IP,
		Ports:   req.Ports,
	})
}

// handleFirewallAllowIP allows an IP address
func (s *Server) handleFirewallAllowIP(w http.ResponseWriter, r *http.Request) {
	var req AllowIPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}

	// Validate IP/CIDR
	if req.IP == "" {
		errorResponse(w, http.StatusBadRequest, "ip is required")
		return
	}

	if net.ParseIP(req.IP) == nil {
		if _, _, err := net.ParseCIDR(req.IP); err != nil {
			errorResponse(w, http.StatusBadRequest, "invalid IP address or CIDR")
			return
		}
	}

	if s.engineEnforces() {
		s.handleFirewallIPRuleNft(w, r, "allow", req.IP, req.Ports)
		return
	}
	// Whole-address allows are kept off these ports by setup-firewall.sh.
	if p, ok := reservedPortIn(req.Ports); ok {
		errorResponse(w, http.StatusBadRequest, fmt.Sprintf("port %d is reserved for VPN-only admin services", p))
		return
	}

	// Build iptables command
	args := []string{"-I", "INPUT", "-s", req.IP}

	// Add port restriction if specified
	if req.Ports != "" {
		if strings.Contains(req.Ports, ",") {
			args = append(args, "-p", "tcp", "-m", "multiport", "--dports", req.Ports)
		} else if strings.Contains(req.Ports, ":") {
			args = append(args, "-p", "tcp", "--dport", req.Ports)
		} else {
			args = append(args, "-p", "tcp", "--dport", req.Ports)
		}
	}

	args = append(args, "-j", "ACCEPT")

	_, err := execHostCommand("iptables", args...)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to allow IP: %v", err))
		return
	}

	// Save rules with netfilter-persistent
	execHostCommand("netfilter-persistent", "save")

	jsonResponse(w, http.StatusOK, IPRuleResponse{
		Status:  "success",
		Message: fmt.Sprintf("IP %s allowed successfully", req.IP),
		IP:      req.IP,
		Ports:   req.Ports,
	})
}

// handleFirewallDeleteRule deletes a firewall rule by chain and line number
func (s *Server) handleFirewallDeleteRule(w http.ResponseWriter, r *http.Request) {
	var req DeleteRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}

	// Validate chain
	req.Chain = strings.ToUpper(req.Chain)
	if req.Chain != "INPUT" && req.Chain != "FORWARD" && req.Chain != "OUTPUT" {
		errorResponse(w, http.StatusBadRequest, "invalid chain: must be INPUT, FORWARD, or OUTPUT")
		return
	}

	// Validate line number
	if req.LineNumber < 1 {
		errorResponse(w, http.StatusBadRequest, "invalid line number: must be >= 1")
		return
	}

	if s.engineEnforces() {
		s.handleFirewallDeleteRuleNft(w, r, req)
		return
	}

	// Get current rules to check if protected
	output, err := execHostCommand("iptables", "-L", req.Chain, "-n", "-v", "--line-numbers")
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to get rules: %v", err))
		return
	}

	// Parse and find the rule
	chain, err := parseIptablesOutput(output, req.Chain)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to parse rules: %v", err))
		return
	}

	// Find the rule by line number
	var targetRule *FirewallRule
	for _, rule := range chain.Rules {
		if rule.Number == req.LineNumber {
			targetRule = &rule
			break
		}
	}

	if targetRule == nil {
		errorResponse(w, http.StatusNotFound, fmt.Sprintf("rule %d not found in chain %s", req.LineNumber, req.Chain))
		return
	}

	// Check if protected
	if targetRule.Protected && !req.Force {
		errorWithCode(w, http.StatusForbidden, "protected_rule", fmt.Sprintf("rule %d is protected (SSH/WireGuard/Admin). Set force=true to override", req.LineNumber))
		return
	}

	// Delete the rule
	_, err = execHostCommand("iptables", "-D", req.Chain, strconv.Itoa(req.LineNumber))
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete rule: %v", err))
		return
	}

	// Save rules with netfilter-persistent
	execHostCommand("netfilter-persistent", "save")

	jsonResponse(w, http.StatusOK, DeleteRuleResponse{
		Status:      "success",
		Message:     fmt.Sprintf("Rule %d deleted from chain %s", req.LineNumber, req.Chain),
		Chain:       req.Chain,
		LineNumber:  req.LineNumber,
		DeletedRule: *targetRule,
	})
}

// handleFirewallExport exports all iptables rules in iptables-save format
func (s *Server) handleFirewallExport(w http.ResponseWriter, r *http.Request) {
	if s.engineEnforces() {
		s.handleFirewallExportNft(w, r)
		return
	}
	output, err := execHostCommand("iptables-save")
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to export rules: %v", err))
		return
	}

	// Set headers for file download
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=\"iptables-rules.txt\"")
	w.Write([]byte(output))
}

// handleFirewallImport imports iptables rules from iptables-restore format
func (s *Server) handleFirewallImport(w http.ResponseWriter, r *http.Request) {
	if s.engineEnforces() {
		errorWithCode(w, http.StatusConflict, "firewall_engine_enforcing", "importing iptables rules is not supported while the nftables engine enforces the firewall")
		return
	}
	var req ImportRulesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}

	if req.Rules == "" {
		errorResponse(w, http.StatusBadRequest, "rules content is required")
		return
	}

	// Validate the rules format
	if !strings.Contains(req.Rules, "*filter") && !strings.Contains(req.Rules, "*nat") && !strings.Contains(req.Rules, "*mangle") {
		errorResponse(w, http.StatusBadRequest, "invalid iptables-save format: missing table declaration")
		return
	}

	// Create a temporary file for the rules
	tmpFile := "/tmp/iptables-import.txt"
	err := writeHostFile(tmpFile, req.Rules)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to write temporary file: %v", err))
		return
	}

	// Apply the rules using iptables-restore
	_, err = execHostCommand("iptables-restore", tmpFile)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to import rules: %v", err))
		return
	}

	// Save rules with netfilter-persistent
	execHostCommand("netfilter-persistent", "save")

	// Clean up temp file
	execHostCommand("rm", "-f", tmpFile)

	jsonResponse(w, http.StatusOK, StatusMessageResponse{
		Status:  "success",
		Message: "Firewall rules imported successfully",
	})
}

// writeHostFile writes content to a file on the host system
func writeHostFile(path string, content string) error {
	// Use nsenter to write file on host
	cmd := fmt.Sprintf("echo '%s' > %s", strings.ReplaceAll(content, "'", "'\\''"), path)
	_, err := execHostCommand("sh", "-c", cmd)
	return err
}

// handleFirewallReset resets firewall to default NovusGate configuration
func (s *Server) handleFirewallReset(w http.ResponseWriter, r *http.Request) {
	if s.engineEnforces() {
		s.handleFirewallResetNft(w, r)
		return
	}
	// Default NovusGate firewall rules
	defaultRules := `*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# Allow loopback
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT

# Allow established connections
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH
-A INPUT -p tcp --dport 22 -j ACCEPT

# Allow WireGuard (51820-51830)
-A INPUT -p udp --dport 51820:51830 -j ACCEPT

# Allow HTTP/HTTPS for web panel
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT

# Allow API port
-A INPUT -p tcp --dport 8080 -j ACCEPT

# Allow ICMP (ping)
-A INPUT -p icmp -j ACCEPT

# Allow all traffic from WireGuard interfaces
-A INPUT -i wg+ -j ACCEPT
-A FORWARD -i wg+ -j ACCEPT
-A FORWARD -o wg+ -j ACCEPT

COMMIT
`

	// Create a temporary file for the rules
	tmpFile := "/tmp/iptables-default.txt"
	err := writeHostFile(tmpFile, defaultRules)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to write temporary file: %v", err))
		return
	}

	// Apply the rules using iptables-restore
	_, err = execHostCommand("iptables-restore", tmpFile)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to reset firewall: %v", err))
		return
	}

	// Save rules with netfilter-persistent
	execHostCommand("netfilter-persistent", "save")

	// Clean up temp file
	execHostCommand("rm", "-f", tmpFile)

	jsonResponse(w, http.StatusOK, StatusMessageResponse{
		Status:  "success",
		Message: "Firewall reset to default NovusGate configuration",
	})
}

// =============================================================================
// VPN Firewall Handlers
// =============================================================================

// VPNFirewallRuleRequest represents a request to create/update a VPN firewall rule
type VPNFirewallRuleRequest struct {
	Name            string  `json:"name"`
	Description     string  `json:"description,omitempty"`
	SourceType      string  `json:"source_type"` // any, network, node, custom
	SourceNetworkID *string `json:"source_network_id,omitempty"`
	SourceNodeID    *string `json:"source_node_id,omitempty"`
	SourceIP        string  `json:"source_ip,omitempty"`
	DestType        string  `json:"dest_type"` // any, network, node, custom
	DestNetworkID   *string `json:"dest_network_id,omitempty"`
	DestNodeID      *string `json:"dest_node_id,omitempty"`
	DestIP          string  `json:"dest_ip,omitempty"`
	SourceGroupID   *string `json:"source_group_id,omitempty"` // source_type group (P9a)
	DestGroupID     *string `json:"dest_group_id,omitempty"`   // dest_type group
	Protocol        string  `json:"protocol"`                  // tcp, udp, icmp, all
	Port            string  `json:"port,omitempty"`
	Action          string  `json:"action"` // accept, drop, reject
	// Bidirectional (mutual): both ends may start connections; false
	// (one-way): only the source may, replies always come back.
	Bidirectional bool `json:"bidirectional,omitempty"`
	Priority      int  `json:"priority"`
	Enabled       bool `json:"enabled"`
}

// validateVPNFirewallRule validates a VPN firewall rule request
func validateVPNFirewallRule(req *VPNFirewallRuleRequest) error {
	if req.Name == "" {
		return fmt.Errorf("name is required")
	}

	// Validate source type
	validTypes := map[string]bool{"any": true, "network": true, "node": true, "custom": true, "group": true}
	if !validTypes[req.SourceType] {
		return fmt.Errorf("invalid source_type: must be any, network, node, custom or group")
	}

	// Validate destination type
	if !validTypes[req.DestType] {
		return fmt.Errorf("invalid dest_type: must be any, network, node, custom or group")
	}
	if req.SourceType == "group" && (req.SourceGroupID == nil || *req.SourceGroupID == "") {
		return fmt.Errorf("source_group_id is required when source_type is group")
	}
	if req.DestType == "group" && (req.DestGroupID == nil || *req.DestGroupID == "") {
		return fmt.Errorf("dest_group_id is required when dest_type is group")
	}
	// A group ID only counts with the group type.
	if req.SourceType != "group" {
		req.SourceGroupID = nil
	}
	if req.DestType != "group" {
		req.DestGroupID = nil
	}

	// Validate source references based on type
	switch req.SourceType {
	case "network":
		if req.SourceNetworkID == nil || *req.SourceNetworkID == "" {
			return fmt.Errorf("source_network_id is required when source_type is network")
		}
	case "node":
		if req.SourceNodeID == nil || *req.SourceNodeID == "" {
			return fmt.Errorf("source_node_id is required when source_type is node")
		}
	case "custom":
		if req.SourceIP == "" {
			return fmt.Errorf("source_ip is required when source_type is custom")
		}
		// IPv4 only: VPN rules are compiled into IPv4 nftables rules, and a
		// rule that cannot be compiled would be skipped (fail-open).
		if !isIPv4OrCIDR(req.SourceIP) {
			return fmt.Errorf("invalid source_ip: must be an IPv4 address or CIDR")
		}
		if isEveryAddress(req.SourceIP) {
			return fmt.Errorf("source_ip 0.0.0.0/0 is every address: use source_type any")
		}
	}

	// Validate destination references based on type
	switch req.DestType {
	case "network":
		if req.DestNetworkID == nil || *req.DestNetworkID == "" {
			return fmt.Errorf("dest_network_id is required when dest_type is network")
		}
	case "node":
		if req.DestNodeID == nil || *req.DestNodeID == "" {
			return fmt.Errorf("dest_node_id is required when dest_type is node")
		}
	case "custom":
		if req.DestIP == "" {
			return fmt.Errorf("dest_ip is required when dest_type is custom")
		}
		if !isIPv4OrCIDR(req.DestIP) {
			return fmt.Errorf("invalid dest_ip: must be an IPv4 address or CIDR")
		}
		if isEveryAddress(req.DestIP) {
			return fmt.Errorf("dest_ip 0.0.0.0/0 is every address: use dest_type any")
		}
	}

	// Validate protocol
	validProtocols := map[string]bool{"tcp": true, "udp": true, "icmp": true, "all": true}
	if req.Protocol == "" {
		req.Protocol = "all"
	}
	req.Protocol = strings.ToLower(req.Protocol)
	if !validProtocols[req.Protocol] {
		return fmt.Errorf("invalid protocol: must be tcp, udp, icmp, or all")
	}

	// Validate action
	validActions := map[string]bool{"accept": true, "drop": true, "reject": true}
	req.Action = strings.ToLower(req.Action)
	if !validActions[req.Action] {
		return fmt.Errorf("invalid action: must be accept, drop, or reject")
	}

	// Validate port (only for tcp/udp)
	if req.Port != "" && req.Protocol != "tcp" && req.Protocol != "udp" {
		return fmt.Errorf("port can only be specified for tcp or udp protocols")
	}
	if req.Port != "" {
		if _, err := firewall.ParsePorts(req.Port); err != nil {
			return fmt.Errorf("invalid port: %v", err)
		}
	}

	return nil
}

// handleVPNFirewallGetRules returns all VPN firewall rules from database
func (s *Server) handleVPNFirewallGetRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListVPNFirewallRules(r.Context())
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to get VPN firewall rules: %v", err))
		return
	}

	if rules == nil {
		rules = []*models.VPNFirewallRule{}
	}

	jsonResponse(w, http.StatusOK, rules)
}

// handleVPNFirewallCreateRule creates a new VPN firewall rule
func (s *Server) handleVPNFirewallCreateRule(w http.ResponseWriter, r *http.Request) {
	var req VPNFirewallRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}

	// Validate the request
	if err := validateVPNFirewallRule(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	// Create the rule model
	rule := &models.VPNFirewallRule{
		Name:            req.Name,
		Description:     req.Description,
		SourceType:      req.SourceType,
		SourceNetworkID: req.SourceNetworkID,
		SourceNodeID:    req.SourceNodeID,
		SourceIP:        req.SourceIP,
		DestType:        req.DestType,
		DestNetworkID:   req.DestNetworkID,
		DestNodeID:      req.DestNodeID,
		DestIP:          req.DestIP,
		SourceGroupID:   req.SourceGroupID,
		DestGroupID:     req.DestGroupID,
		Protocol:        req.Protocol,
		Port:            req.Port,
		Action:          req.Action,
		Bidirectional:   req.Bidirectional,
		Priority:        req.Priority,
		Enabled:         req.Enabled,
	}

	if err := s.checkRuleGroups(r.Context(), rule); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	// Save to database
	if err := s.store.CreateVPNFirewallRule(r.Context(), rule); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to create VPN firewall rule: %v", err))
		return
	}

	// Re-apply all VPN rules (nft engine or iptables chain), like update and
	// delete: rules are evaluated in priority order, so one rule alone cannot
	// be appended. A failure is logged; the rule is saved.
	if err := s.syncVPNFirewallRules(r.Context()); err != nil {
		slog.Error(fmt.Sprintf("Warning: failed to sync VPN firewall rules: %v", err))
	}

	// Create audit log
	s.store.CreateFirewallAuditLog(r.Context(), "vpn_rule_created", map[string]interface{}{
		"rule_id":   rule.ID,
		"rule_name": rule.Name,
	}, clientIP(r), sessionUserID(r))

	// Fetch the rule with joined names
	createdRule, _ := s.store.GetVPNFirewallRule(r.Context(), rule.ID)
	if createdRule != nil {
		rule = createdRule
	}

	jsonResponse(w, http.StatusCreated, rule)
}

// handleVPNFirewallUpdateRule updates an existing VPN firewall rule
func (s *Server) handleVPNFirewallUpdateRule(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	// Check if rule exists
	existingRule, err := s.store.GetVPNFirewallRule(r.Context(), id)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to get rule: %v", err))
		return
	}
	if existingRule == nil {
		errorResponse(w, http.StatusNotFound, "rule not found")
		return
	}

	var req VPNFirewallRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}

	// Validate the request
	if err := validateVPNFirewallRule(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	// Update the rule model
	rule := &models.VPNFirewallRule{
		ID:              id,
		Name:            req.Name,
		Description:     req.Description,
		SourceType:      req.SourceType,
		SourceNetworkID: req.SourceNetworkID,
		SourceNodeID:    req.SourceNodeID,
		SourceIP:        req.SourceIP,
		DestType:        req.DestType,
		DestNetworkID:   req.DestNetworkID,
		DestNodeID:      req.DestNodeID,
		DestIP:          req.DestIP,
		SourceGroupID:   req.SourceGroupID,
		DestGroupID:     req.DestGroupID,
		Protocol:        req.Protocol,
		Port:            req.Port,
		Action:          req.Action,
		Bidirectional:   req.Bidirectional,
		Priority:        req.Priority,
		Enabled:         req.Enabled,
	}

	if err := s.checkRuleGroups(r.Context(), rule); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	// Update in database
	if err := s.store.UpdateVPNFirewallRule(r.Context(), rule); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to update VPN firewall rule: %v", err))
		return
	}

	// Re-apply all VPN firewall rules to iptables
	if err := s.syncVPNFirewallRules(r.Context()); err != nil {
		slog.Error(fmt.Sprintf("Warning: failed to sync VPN firewall rules to iptables: %v", err))
	}

	// Create audit log
	s.store.CreateFirewallAuditLog(r.Context(), "vpn_rule_updated", map[string]interface{}{
		"rule_id":   rule.ID,
		"rule_name": rule.Name,
	}, clientIP(r), sessionUserID(r))

	// Fetch the rule with joined names
	updatedRule, _ := s.store.GetVPNFirewallRule(r.Context(), rule.ID)
	if updatedRule != nil {
		rule = updatedRule
	}

	jsonResponse(w, http.StatusOK, rule)
}

// handleVPNFirewallDeleteRule deletes a VPN firewall rule
func (s *Server) handleVPNFirewallDeleteRule(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	// Check if rule exists
	existingRule, err := s.store.GetVPNFirewallRule(r.Context(), id)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to get rule: %v", err))
		return
	}
	if existingRule == nil {
		errorResponse(w, http.StatusNotFound, "rule not found")
		return
	}

	// Delete from database
	if err := s.store.DeleteVPNFirewallRule(r.Context(), id); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete VPN firewall rule: %v", err))
		return
	}

	// Re-sync all VPN firewall rules to iptables (removes deleted rule)
	if err := s.syncVPNFirewallRules(r.Context()); err != nil {
		slog.Error(fmt.Sprintf("Warning: failed to sync VPN firewall rules to iptables: %v", err))
	}

	// Create audit log
	s.store.CreateFirewallAuditLog(r.Context(), "vpn_rule_deleted", map[string]interface{}{
		"rule_id":   id,
		"rule_name": existingRule.Name,
	}, clientIP(r), sessionUserID(r))

	w.WriteHeader(http.StatusNoContent)
}

// handleVPNFirewallApply syncs all database rules to iptables FORWARD chain
func (s *Server) handleVPNFirewallApply(w http.ResponseWriter, r *http.Request) {
	if err := s.syncVPNFirewallRules(r.Context()); err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to apply VPN firewall rules: %v", err))
		return
	}

	// Create audit log
	s.store.CreateFirewallAuditLog(r.Context(), "vpn_rules_applied", map[string]interface{}{
		"action": "full_sync",
	}, clientIP(r), sessionUserID(r))

	jsonResponse(w, http.StatusOK, StatusMessageResponse{
		Status:  "success",
		Message: "VPN firewall rules applied successfully",
	})
}

// applyVPNFirewallRule appends one VPN rule to chain NOVUSGATE-VPN (iptables
// mode); syncVPNFirewallRules calls it for every enabled rule in order.
func (s *Server) applyVPNFirewallRule(ctx context.Context, rule *models.VPNFirewallRule) error {
	// A group endpoint (P9a) is its members' addresses: one iptables rule per
	// source/destination pair; an empty group adds none (matches nothing).
	sources, err := s.resolveVPNRuleEndpoints(ctx, rule.SourceType, rule.SourceGroupID, rule.SourceNetworkID, rule.SourceNodeID, rule.SourceIP)
	if err != nil {
		return fmt.Errorf("failed to resolve source: %w", err)
	}
	dests, err := s.resolveVPNRuleEndpoints(ctx, rule.DestType, rule.DestGroupID, rule.DestNetworkID, rule.DestNodeID, rule.DestIP)
	if err != nil {
		return fmt.Errorf("failed to resolve destination: %w", err)
	}
	// One failed pair must not leave the other members without the rule.
	var firstErr error
	for _, sourceIP := range sources {
		for _, destIP := range dests {
			if err := appendVPNIptablesRule(rule, sourceIP, destIP); err != nil && firstErr == nil {
				firstErr = err
			}
			// Mutual: the destination side may start connections too.
			if rule.Bidirectional {
				if err := appendVPNIptablesRule(rule, destIP, sourceIP); err != nil && firstErr == nil {
					firstErr = err
				}
			}
		}
	}
	return firstErr
}

// resolveVPNRuleEndpoints is resolveVPNRuleEndpoint for every endpoint type,
// groups included.
func (s *Server) resolveVPNRuleEndpoints(ctx context.Context, endpointType string, groupID, networkID, nodeID *string, customIP string) ([]string, error) {
	if endpointType != "group" {
		ip, err := s.resolveVPNRuleEndpoint(ctx, endpointType, networkID, nodeID, customIP)
		return []string{ip}, err
	}
	if groupID == nil {
		return nil, fmt.Errorf("group_id is required for group type")
	}
	g, err := s.store.GetNodeGroup(ctx, *groupID)
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, fmt.Errorf("group not found")
	}
	out := []string{}
	for _, m := range g.Members {
		out = append(out, m.VirtualIP+"/32")
	}
	return out, nil
}

// appendVPNIptablesRule appends one rule for a source/destination pair.
func appendVPNIptablesRule(rule *models.VPNFirewallRule, sourceIP, destIP string) error {
	// Build iptables command
	args := []string{"-A", vpnChain}

	// Add source
	if sourceIP != "" && sourceIP != "0.0.0.0/0" {
		args = append(args, "-s", sourceIP)
	}

	// Add destination
	if destIP != "" && destIP != "0.0.0.0/0" {
		args = append(args, "-d", destIP)
	}

	// Add protocol
	if rule.Protocol != "all" && rule.Protocol != "" {
		args = append(args, "-p", rule.Protocol)

		// Add port (only for tcp/udp)
		if rule.Port != "" && (rule.Protocol == "tcp" || rule.Protocol == "udp") {
			ports := iptablesPorts(rule.Port)
			if strings.Contains(ports, ",") {
				args = append(args, "-m", "multiport", "--dports", ports)
			} else {
				args = append(args, "--dport", ports)
			}
		}
	}

	// Add action
	target := strings.ToUpper(rule.Action)
	args = append(args, "-j", target)

	// Add comment with rule ID for identification
	args = append(args, "-m", "comment", "--comment", fmt.Sprintf("novusgate-vpn-%s", rule.ID))

	// Execute iptables command
	if _, err := execHostCommand("iptables", args...); err != nil {
		return fmt.Errorf("iptables command failed: %w", err)
	}

	return nil
}

// resolveVPNRuleEndpoint resolves the IP/CIDR for a VPN rule endpoint
func (s *Server) resolveVPNRuleEndpoint(ctx context.Context, endpointType string, networkID, nodeID *string, customIP string) (string, error) {
	switch endpointType {
	case "any":
		return "0.0.0.0/0", nil
	case "network":
		if networkID == nil {
			return "", fmt.Errorf("network_id is required for network type")
		}
		network, err := s.store.GetNetwork(ctx, *networkID)
		if err != nil {
			return "", err
		}
		if network == nil {
			return "", fmt.Errorf("network not found")
		}
		return network.CIDR, nil
	case "node":
		if nodeID == nil {
			return "", fmt.Errorf("node_id is required for node type")
		}
		node, err := s.store.GetNode(ctx, *nodeID)
		if err != nil {
			return "", err
		}
		if node == nil {
			return "", fmt.Errorf("node not found")
		}
		return node.VirtualIP.String() + "/32", nil
	case "custom":
		if customIP == "" {
			return "", fmt.Errorf("custom IP is required for custom type")
		}
		// Ensure CIDR notation
		if !strings.Contains(customIP, "/") {
			customIP = customIP + "/32"
		}
		return customIP, nil
	default:
		return "", fmt.Errorf("unknown endpoint type: %s", endpointType)
	}
}

// syncVPNFirewallRules syncs all database rules to iptables FORWARD chain
func (s *Server) syncVPNFirewallRules(ctx context.Context) error {
	if s.engineEnforces() {
		// The engine enforces VPN rules in table inet novusgate.
		if _, err := execHostCommand("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
			slog.Warn(fmt.Sprintf("[Firewall] warning: enable ip_forward: %v", err))
		}
		_, err := s.firewall.ReconcileOrRetry(ctx)
		return err
	}
	s.vpnSync.Lock()
	defer s.vpnSync.Unlock()
	// Rules appended to FORWARD by earlier versions sat below the wg ACCEPTs
	// and never matched; they are removed, then the chain is rebuilt.
	if err := s.removeLegacyForwardVPNRules(); err != nil {
		return fmt.Errorf("failed to clear existing VPN rules: %w", err)
	}
	if err := ensureVPNChain(); err != nil {
		return err
	}

	// Get all enabled rules from database
	rules, err := s.store.ListVPNFirewallRules(ctx)
	if err != nil {
		return fmt.Errorf("failed to list VPN firewall rules: %w", err)
	}

	// Apply each enabled rule
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		if err := s.applyVPNFirewallRule(ctx, rule); err != nil {
			slog.Error(fmt.Sprintf("Warning: failed to apply VPN rule %s: %v", rule.Name, err))
			// Continue with other rules
		}
	}

	// Networks are apart by default, like the nftables engine (VLAN-style
	// access): after the rules, traffic inside one network goes on to the
	// ACCEPTs WireGuard's PostUp adds; between networks it is dropped.
	// Traffic to the internet (full tunnel) and to the hub is not matched.
	if err := s.isolateNetworks(ctx); err != nil {
		return err
	}

	// Forwarding between the wg interfaces. Peers keep their /32 on the hub
	// (configs route the rest, M1); rewriting them here with "wg set" could
	// re-create a peer just removed (key rotation, expiry), so it is not done.
	if _, err := execHostCommand("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		slog.Warn(fmt.Sprintf("[Firewall] warning: enable ip_forward: %v", err))
	}

	// Save rules with netfilter-persistent
	execHostCommand("netfilter-persistent", "save")

	return nil
}

// isolationComment marks the default DROP between networks in NOVUSGATE-VPN.
const isolationComment = "novusgate-vpn-isolation"

// isolateNetworks appends, after the VPN rules, a RETURN for traffic that
// stays inside each network and a DROP for wg-to-wg traffic between them.
func (s *Server) isolateNetworks(ctx context.Context) error {
	networks, err := s.store.ListNetworks(ctx)
	if err != nil {
		return fmt.Errorf("list networks for isolation: %w", err)
	}
	for _, n := range networks {
		if n.InterfaceName == "" {
			continue
		}
		if _, err := execHostCommand("iptables", "-A", vpnChain, "-i", n.InterfaceName, "-o", n.InterfaceName, "-j", "RETURN"); err != nil {
			return fmt.Errorf("%s same-network rule for %s: %w", vpnChain, n.InterfaceName, err)
		}
	}
	if _, err := execHostCommand("iptables", "-A", vpnChain, "-i", "wg+", "-o", "wg+", "-j", "DROP", "-m", "comment", "--comment", isolationComment); err != nil {
		return fmt.Errorf("%s isolation rule: %w", vpnChain, err)
	}
	return nil
}

// SyncVPNRules applies the stored VPN rules at start in iptables and shadow
// mode (NOVUSGATE-VPN with networks apart by default); nftables mode does
// this in its own engine. It is a no-op there.
func (s *Server) SyncVPNRules(ctx context.Context) {
	if s.engineEnforces() {
		return
	}
	if err := s.syncVPNFirewallRules(ctx); err != nil {
		slog.Warn(fmt.Sprintf("[Firewall] applying the VPN rules at start failed: %v", err))
	}
}

// removeLegacyForwardVPNRules deletes VPN rules earlier versions appended to
// FORWARD (comment "novusgate-vpn-*").
func (s *Server) removeLegacyForwardVPNRules() error {
	// Get current FORWARD chain rules
	output, err := execHostCommand("iptables", "-L", "FORWARD", "-n", "-v", "--line-numbers")
	if err != nil {
		return err
	}

	// Find all rules with novusgate-vpn comment and delete them (in reverse order)
	lines := strings.Split(output, "\n")
	var lineNumbers []int

	for _, line := range lines {
		if strings.Contains(line, "novusgate-vpn-") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				if num, err := strconv.Atoi(fields[0]); err == nil {
					lineNumbers = append(lineNumbers, num)
				}
			}
		}
	}

	// Delete in reverse order to maintain line numbers
	for i := len(lineNumbers) - 1; i >= 0; i-- {
		execHostCommand("iptables", "-D", "FORWARD", strconv.Itoa(lineNumbers[i]))
	}

	return nil
}

// isIPv4OrCIDR reports whether s is an IPv4 address or IPv4 CIDR.
func isIPv4OrCIDR(s string) bool {
	if strings.Contains(s, ":") { // IPv6, including IPv4-mapped (::ffff:a.b.c.d)
		return false
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.To4() != nil
	}
	ip, _, err := net.ParseCIDR(s)
	return err == nil && ip.To4() != nil
}

// isEveryAddress: a /0 range. As a rule end it would route the whole internet
// through the hub in device configs; the endpoint type any says the same.
func isEveryAddress(s string) bool {
	_, n, err := net.ParseCIDR(strings.TrimSpace(s))
	if err != nil {
		return false
	}
	ones, _ := n.Mask.Size()
	return ones == 0
}

// ruleCommentRe matches an iptables "/* comment */" in `iptables -L` output.
var ruleCommentRe = regexp.MustCompile(`/\*.*?\*/`)

// vpnChain holds the VPN rules in iptables mode. FORWARD jumps to it first
// for traffic from VPN interfaces, before the ACCEPTs WireGuard's PostUp
// appends, so drop and reject rules take effect.
const vpnChain = "NOVUSGATE-VPN"

// ensureVPNChain creates and empties NOVUSGATE-VPN, puts the jump at the top
// of FORWARD and lets replies of allowed connections return first (like the
// nftables engine, which checks VPN rules after established traffic).
func ensureVPNChain() error {
	execHostCommand("iptables", "-N", vpnChain) // fails when it exists
	if _, err := execHostCommand("iptables", "-F", vpnChain); err != nil {
		return fmt.Errorf("flush %s: %w", vpnChain, err)
	}
	if _, err := execHostCommand("iptables", "-C", "FORWARD", "-i", "wg+", "-j", vpnChain); err != nil {
		if _, err := execHostCommand("iptables", "-I", "FORWARD", "1", "-i", "wg+", "-j", vpnChain); err != nil {
			return fmt.Errorf("jump to %s: %w", vpnChain, err)
		}
	}
	if _, err := execHostCommand("iptables", "-A", vpnChain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN"); err != nil {
		return fmt.Errorf("%s established rule: %w", vpnChain, err)
	}
	return nil
}

// clearNovusGateVPNRules removes every iptables VPN rule NovusGate made: the
// legacy FORWARD rules, the jump and NOVUSGATE-VPN (the nftables engine takes
// over VPN rules).
func (s *Server) clearNovusGateVPNRules() error {
	if err := s.removeLegacyForwardVPNRules(); err != nil {
		return err
	}
	for {
		if _, err := execHostCommand("iptables", "-D", "FORWARD", "-i", "wg+", "-j", vpnChain); err != nil {
			break // no (more) jumps
		}
	}
	execHostCommand("iptables", "-F", vpnChain)
	execHostCommand("iptables", "-X", vpnChain)
	return nil
}

// iptablesPorts writes a stored port list ("8000-9000, 22", accepted by
// ParsePorts and by nftables) the way iptables reads it ("8000:9000,22").
func iptablesPorts(ports string) string {
	return strings.ReplaceAll(strings.ReplaceAll(ports, " ", ""), "-", ":")
}
