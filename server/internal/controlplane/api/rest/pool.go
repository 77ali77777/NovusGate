package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strings"

	"github.com/novusgate/novusgate/internal/wireguard"
)

// Server-side routing, P1 (2026-10-19): a device config is handed out once.
// It routes one address pool (default 10.0.0.0/8) and networks are made
// inside it, so a new network changes no config; who reaches whom is the
// hub firewall's decision alone.

// privateRanges are the blocks a pool may lie in (RFC 1918 and the shared
// address space RFC 6598 that Tailscale uses for the same purpose).
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
}

// validPool accepts an IPv4 private block from /8 to /16, written as its
// network address.
func validPool(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("pool must be an IPv4 CIDR like 10.0.0.0/8")
	}
	if p != p.Masked() {
		return netip.Prefix{}, fmt.Errorf("pool must be written as its network address (%s)", p.Masked())
	}
	if p.Bits() < 8 || p.Bits() > 16 {
		return netip.Prefix{}, fmt.Errorf("pool must be between /8 and /16")
	}
	for _, r := range privateRanges {
		if r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
			return p, nil
		}
	}
	return netip.Prefix{}, fmt.Errorf("pool must be private: inside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or 100.64.0.0/10")
}

// nextNetworkCIDR is the /24 a new network gets: in a pool wider than /16,
// the first /24 of a free /16 from the eleventh on (10.10.0.0/24,
// 10.11.0.0/24, … in 10.0.0.0/8: easy to read, room to grow), else the
// first free /24.
func nextNetworkCIDR(pool netip.Prefix, used []netip.Prefix) (netip.Prefix, bool) {
	free := func(c netip.Prefix) bool {
		for _, u := range used {
			if u.Overlaps(c) {
				return false
			}
		}
		return true
	}
	base := pool.Masked().Addr().As4()
	start := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	at := func(off uint32) netip.Prefix {
		v := start + off
		return netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), 24)
	}
	if pool.Bits() < 16 {
		blocks := uint32(1) << (16 - pool.Bits())
		for i := uint32(0); i < blocks; i++ {
			if c := at(((10 + i) % blocks) << 16); free(c) {
				return c, true
			}
		}
	}
	if pool.Bits() > 24 {
		return netip.Prefix{}, false
	}
	for i := uint32(0); i < uint32(1)<<(24-pool.Bits()); i++ {
		if c := at(i << 8); free(c) {
			return c, true
		}
	}
	return netip.Prefix{}, false
}

// VPNSettingsResponse is GET/PUT /api/v1/settings/vpn.
type VPNSettingsResponse struct {
	Pool     string `json:"pool"`
	NextCIDR string `json:"next_cidr"` // the /24 a new network would get; "" when the pool is full
	// EndpointHost (P2): the name or address configs reach the hub by; ""
	// keeps each network's endpoint, EndpointDefault (WG_SERVER_ENDPOINT).
	EndpointHost    string `json:"endpoint_host"`
	EndpointDefault string `json:"endpoint_default"`
}

// VPNSettingsRequest is the body of PUT /api/v1/settings/vpn; a field left
// out is not changed, at least one is required.
type VPNSettingsRequest struct {
	Pool         *string `json:"pool,omitempty"`
	EndpointHost *string `json:"endpoint_host,omitempty"`
}

// hostLabelRe is one DNS label (RFC 1123).
var hostLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// validEndpointHost accepts "" (clear), an IPv4 address or a DNS name,
// without a scheme or port (the network's port is added).
func validEndpointHost(s string) (string, error) {
	h := strings.ToLower(strings.TrimSpace(s))
	if h == "" {
		return "", nil
	}
	if a, err := netip.ParseAddr(h); err == nil {
		if !a.Is4() {
			return "", fmt.Errorf("endpoint_host: only IPv4 addresses or names")
		}
		return h, nil
	}
	bad := fmt.Errorf("endpoint_host must be a domain like vpn.example.com or an IPv4 address, without port")
	if len(h) > 253 || !strings.Contains(h, ".") {
		return "", bad
	}
	for _, l := range strings.Split(h, ".") {
		if !hostLabelRe.MatchString(l) {
			return "", bad
		}
	}
	return h, nil
}

// vpnPool reads the stored pool; a stored value that no longer parses
// falls back to the default.
func (s *Server) vpnPool(ctx context.Context) (netip.Prefix, error) {
	raw, err := s.store.VPNPool(ctx)
	if err != nil {
		return netip.Prefix{}, err
	}
	p, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.MustParsePrefix("10.0.0.0/8"), nil
	}
	return p.Masked(), nil
}

// nextCIDR is the /24 a new network gets in the pool.
func (s *Server) nextCIDR(ctx context.Context, pool netip.Prefix) (netip.Prefix, bool, error) {
	networks, err := s.store.ListNetworks(ctx)
	if err != nil {
		return netip.Prefix{}, false, err
	}
	var used []netip.Prefix
	for _, n := range networks {
		if p, err := netip.ParsePrefix(n.CIDR); err == nil {
			used = append(used, p.Masked())
		}
	}
	c, ok := nextNetworkCIDR(pool, used)
	return c, ok, nil
}

func (s *Server) vpnSettings(ctx context.Context) (VPNSettingsResponse, error) {
	pool, err := s.vpnPool(ctx)
	if err != nil {
		return VPNSettingsResponse{}, err
	}
	host, err := s.store.VPNEndpointHost(ctx)
	if err != nil {
		return VPNSettingsResponse{}, err
	}
	out := VPNSettingsResponse{Pool: pool.String(), EndpointHost: host, EndpointDefault: wireguard.GetServerEndpoint()}
	if c, ok, err := s.nextCIDR(ctx, pool); err != nil {
		return out, err
	} else if ok {
		out.NextCIDR = c.String()
	}
	return out, nil
}

// handleGetVPNSettings answers GET /api/v1/settings/vpn.
func (s *Server) handleGetVPNSettings(w http.ResponseWriter, r *http.Request) {
	out, err := s.vpnSettings(r.Context())
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to read VPN settings")
		return
	}
	jsonResponse(w, http.StatusOK, out)
}

// handleSetVPNSettings answers PUT /api/v1/settings/vpn (admin). Networks
// outside a new pool keep working: configs route them by name. Devices
// need their config once more when the pool changes.
func (s *Server) handleSetVPNSettings(w http.ResponseWriter, r *http.Request) {
	var req VPNSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}
	if req.Pool == nil && req.EndpointHost == nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "give pool or endpoint_host")
		return
	}
	// Both are checked before either is stored.
	var pool netip.Prefix
	host := ""
	var err error
	if req.Pool != nil {
		if pool, err = validPool(*req.Pool); err != nil {
			errorWithCode(w, http.StatusBadRequest, "invalid_pool", err.Error())
			return
		}
	}
	if req.EndpointHost != nil {
		if host, err = validEndpointHost(*req.EndpointHost); err != nil {
			errorWithCode(w, http.StatusBadRequest, "invalid_endpoint_host", err.Error())
			return
		}
	}
	if req.Pool != nil {
		if err := s.store.SetVPNPool(r.Context(), pool.String()); err != nil {
			errorResponse(w, http.StatusInternalServerError, "failed to store the pool")
			return
		}
	}
	if req.EndpointHost != nil {
		if err := s.store.SetVPNEndpointHost(r.Context(), host); err != nil {
			errorResponse(w, http.StatusInternalServerError, "failed to store the endpoint host")
			return
		}
	}
	s.handleGetVPNSettings(w, r)
}
