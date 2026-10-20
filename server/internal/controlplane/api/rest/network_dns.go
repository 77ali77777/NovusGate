package rest

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// maxClientDNS is how many DNS servers a client config may list.
const maxClientDNS = 3

// ClientDNSRequest sets the DNS servers of a network's client configs.
type ClientDNSRequest struct {
	ClientDNS string `json:"client_dns"` // comma-separated IPv4 addresses; empty: the default
}

// normalizeClientDNS checks a comma-separated list of IPv4 addresses and
// returns it as "a, b". Only addresses pass, so the value is safe to write
// into a WireGuard config and an install script. IPv6 is refused: the
// tunnels carry IPv4 only (full tunnel routes 0.0.0.0/0), so an IPv6 server
// would be asked outside the tunnel.
func normalizeClientDNS(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > maxClientDNS {
		return "", errors.New("at most 3 DNS servers")
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		ip := net.ParseIP(strings.TrimSpace(p)).To4()
		if ip == nil {
			return "", errors.New("not an IPv4 address: " + strings.TrimSpace(p))
		}
		out = append(out, ip.String())
	}
	return strings.Join(out, ", "), nil
}

func (s *Server) handleSetNetworkDNS(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if _, err := uuid.Parse(id); err != nil {
		errorResponse(w, http.StatusNotFound, "network not found")
		return
	}
	var req ClientDNSRequest
	if !decodeAdminRequest(w, r, &req) {
		return
	}
	dns, err := normalizeClientDNS(req.ClientDNS)
	if err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_dns", err.Error())
		return
	}
	if hub := s.hubAmong(r.Context(), dns); hub != "" {
		errorWithCode(w, http.StatusBadRequest, "dns_is_hub", hub+" is the hub's own address: devices already use it as DNS; give the servers the hub should ask")
		return
	}
	found, err := s.store.SetNetworkClientDNS(r.Context(), id, dns)
	if err != nil {
		slog.Error("client DNS not saved", "network", id, "error", err)
		errorResponse(w, http.StatusInternalServerError, "failed to save the DNS servers")
		return
	}
	if !found {
		errorResponse(w, http.StatusNotFound, "network not found")
		return
	}
	network, err := s.store.GetNetwork(r.Context(), id)
	if err != nil || network == nil {
		errorResponse(w, http.StatusInternalServerError, "failed to read the network")
		return
	}
	s.SyncDNS(r.Context()) // the hub's forwarder takes the new servers
	jsonResponse(w, http.StatusOK, network)
}

// hubAmong returns the first of the comma-separated addresses that is a
// network's hub address, or "". Devices name the hub as DNS (P3); a hub as
// one of its own upstreams would forward to itself.
func (s *Server) hubAmong(ctx context.Context, dns string) string {
	if dns == "" {
		return ""
	}
	networks, err := s.store.ListNetworks(ctx)
	if err != nil {
		return ""
	}
	hubs := map[string]bool{}
	for _, n := range networks {
		if hub, err := hubIP(n.CIDR); err == nil {
			hubs[hub] = true
		}
	}
	for _, ip := range strings.Split(dns, ",") {
		if ip = strings.TrimSpace(ip); hubs[ip] {
			return ip
		}
	}
	return ""
}
