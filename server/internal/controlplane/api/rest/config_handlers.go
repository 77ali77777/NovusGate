package rest

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
	"github.com/skip2/go-qrcode"
)

// fullTunnelDNS resolves names over the tunnel for full-tunnel nodes, so
// DNS queries do not leave outside it.
const fullTunnelDNS = "1.1.1.1"

// handleDownloadConfig returns the WireGuard config for a node
func (s *Server) handleDownloadConfig(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	node, err := s.store.GetNode(r.Context(), id)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to get node")
		return
	}
	if node == nil {
		errorResponse(w, http.StatusNotFound, "node not found")
		return
	}

	privateKey, err := s.store.NodePrivateKey(r.Context(), node.ID)
	if err != nil {
		slog.Error("read node private key", "node", node.ID, "error", err)
		errorResponse(w, http.StatusInternalServerError, "failed to read the node's private key")
		return
	}
	if privateKey == "" {
		errorResponse(w, http.StatusBadRequest, "private key not found for this node")
		return
	}

	// Get network to fetch server public key
	network, err := s.store.GetNetwork(r.Context(), node.NetworkID)
	if err != nil || network == nil {
		errorResponse(w, http.StatusInternalServerError, "failed to get network")
		return
	}

	serverPublicKey := network.ServerPublicKey
	if serverPublicKey == "" {
		// Fallback: Try to get from running manager
		mgr := s.getManager(network.ID)
		if mgr != nil {
			if key, err := mgr.GetPublicKey(); err == nil && key != "" {
				serverPublicKey = key
			}
		}
	}

	if serverPublicKey == "" {
		errorResponse(w, http.StatusInternalServerError, "server public key not configured for this network")
		return
	}

	serverEndpoint := s.nodeEndpoint(r.Context(), network)

	// Routes: every VPN network (the hub's firewall decides who reaches
	// whom), or everything for full tunnel; recorded for "config outdated".
	allowedIPsStr, dns := s.nodeRouting(r.Context(), node, network)
	s.recordConfigRoutes(r.Context(), node.ID, configRecord(allowedIPsStr, serverEndpoint, dns))

	cfgGen := wireguard.NewConfigGenerator()
	config := cfgGen.GeneratePeerConfigDNS(privateKey, serverPublicKey, serverEndpoint, node.VirtualIP.String(), allowedIPsStr, dns)

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.conf\"", node.Name))
	w.Write([]byte(config))
}

// handleGetQRCode returns PNG QR code of the config
func (s *Server) handleGetQRCode(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	node, err := s.store.GetNode(r.Context(), id)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to get node")
		return
	}
	if node == nil {
		errorResponse(w, http.StatusNotFound, "node not found")
		return
	}

	privateKey, err := s.store.NodePrivateKey(r.Context(), node.ID)
	if err != nil {
		slog.Error("read node private key", "node", node.ID, "error", err)
		errorResponse(w, http.StatusInternalServerError, "failed to read the node's private key")
		return
	}
	if privateKey == "" {
		errorResponse(w, http.StatusBadRequest, "private key not found")
		return
	}

	// Get network to fetch server public key
	network, err := s.store.GetNetwork(r.Context(), node.NetworkID)
	if err != nil || network == nil {
		errorResponse(w, http.StatusInternalServerError, "failed to get network")
		return
	}

	serverPublicKey := network.ServerPublicKey
	if serverPublicKey == "" {
		// Fallback: Try to get from running manager
		mgr := s.getManager(network.ID)
		if mgr != nil {
			if key, err := mgr.GetPublicKey(); err == nil && key != "" {
				serverPublicKey = key
			}
		}
	}

	if serverPublicKey == "" {
		errorResponse(w, http.StatusInternalServerError, "server public key not configured")
		return
	}

	serverEndpoint := s.nodeEndpoint(r.Context(), network)

	// Routes: every VPN network (the hub's firewall decides who reaches
	// whom), or everything for full tunnel; recorded for "config outdated".
	allowedIPsStr, dns := s.nodeRouting(r.Context(), node, network)
	s.recordConfigRoutes(r.Context(), node.ID, configRecord(allowedIPsStr, serverEndpoint, dns))

	cfgGen := wireguard.NewConfigGenerator()
	config := cfgGen.GeneratePeerConfigDNS(privateKey, serverPublicKey, serverEndpoint, node.VirtualIP.String(), allowedIPsStr, dns)

	png, err := qrcode.Encode(config, qrcode.Medium, 256)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to generate QR code")
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}

// handleCreateServerWithConfig creates a node and returns config+keys
func (s *Server) handleCreateServerWithConfig(w http.ResponseWriter, r *http.Request) {
	networkID := mux.Vars(r)["networkId"]

	var req CreateServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}

	// 1. Generate keys
	privateKey, publicKey, err := generateKeys()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to generate keys: "+err.Error())
		return
	}

	// 2. Create Node in DB
	node := &models.Node{
		NetworkID: networkID,
		Name:      req.Name,
		Labels:    withoutWireguardLabels(req.Labels),
		PublicKey: publicKey,
		ExpiresAt: req.ExpiresAt,
		Status:    "online",
	}

	// Allocate next available IP
	ip, err := s.store.AllocateIP(r.Context(), networkID)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to allocate IP: "+err.Error())
		return
	}
	node.VirtualIP = ip
	if node.Labels == nil {
		node.Labels = make(map[string]string)
	}

	// The node and its sealed private key (never in labels) are written together.
	if err := s.store.CreateNodeWithKey(r.Context(), node, privateKey); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to create node")
		return
	}

	// 3. Add to WireGuard interface
	mgr := s.getManager(networkID)
	if mgr != nil {
		allowedIPs := node.VirtualIP.String() + "/32"
		slog.Info(fmt.Sprintf("[WG] Adding peer to interface: PublicKey=%s, AllowedIPs=%s", publicKey, allowedIPs))
		if err := mgr.AddPeer(publicKey, allowedIPs); err != nil {
			// Log error but continue (soft failure)
			slog.Error(fmt.Sprintf("[WG] ERROR adding peer to interface: %v", err))
		} else {
			slog.Info("[WG] SUCCESS: Peer added to WireGuard interface")
		}
	} else {
		slog.Warn(fmt.Sprintf("[WG] WARNING: No manager found for network %s - peer NOT added to WireGuard!", networkID))
	}

	// 4. Generate Config - Use server's public key from network
	network, err := s.store.GetNetwork(r.Context(), networkID)
	if err != nil || network == nil {
		errorResponse(w, http.StatusInternalServerError, "failed to get network for config generation")
		return
	}

	serverPublicKey := network.ServerPublicKey
	if serverPublicKey == "" {
		serverPublicKey = "SERVER_KEY_NOT_CONFIGURED"
	}
	serverEndpoint := s.nodeEndpoint(r.Context(), network)

	// Routes: every VPN network (the hub's firewall decides who reaches
	// whom), or everything for full tunnel; recorded for "config outdated".
	allowedIPsStr, dns := s.nodeRouting(r.Context(), node, network)
	s.recordConfigRoutes(r.Context(), node.ID, configRecord(allowedIPsStr, serverEndpoint, dns))

	cfgGen := wireguard.NewConfigGenerator()
	config := cfgGen.GeneratePeerConfigDNS(privateKey, serverPublicKey, serverEndpoint, node.VirtualIP.String(), allowedIPsStr, dns)

	response := CreateServerResponse{Node: node, Config: config}

	s.triggerReconcile()
	// A full-tunnel network's new node joins the hub's internet exit set.
	if network.TunnelMode == models.TunnelFull && node.TunnelOverride == "" {
		s.reconcileFirewall(r.Context())
	}
	jsonResponse(w, http.StatusCreated, response)
}

func (s *Server) handleNodeInstallScript(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	node, err := s.store.GetNode(r.Context(), id)
	if err != nil || node == nil {
		errorResponse(w, http.StatusNotFound, "node not found")
		return
	}

	// 1. Get Config
	privateKey, err := s.store.NodePrivateKey(r.Context(), node.ID)
	if err != nil {
		slog.Error("read node private key", "node", node.ID, "error", err)
		errorResponse(w, http.StatusInternalServerError, "failed to read the node's private key")
		return
	}
	if privateKey == "" {
		errorResponse(w, http.StatusBadRequest, "private key not found for this node")
		return
	}
	network, err := s.store.GetNetwork(r.Context(), node.NetworkID)
	if err != nil || network == nil {
		errorResponse(w, http.StatusNotFound, "network not found")
		return
	}
	hub, err := hubAddress(network.CIDR)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "invalid network CIDR")
		return
	}
	hub, _, _ = strings.Cut(hub, "/")

	serverEndpoint := s.nodeEndpoint(r.Context(), network)

	serverPublicKey := network.ServerPublicKey
	if serverPublicKey == "" {
		// Fallback: Try to get from running manager
		mgr := s.getManager(network.ID)
		if mgr != nil {
			if key, err := mgr.GetPublicKey(); err == nil && key != "" {
				serverPublicKey = key
			}
		}
		// If still empty, use placeholder to avoid crash, script will fail to connect but at least run
		if serverPublicKey == "" {
			serverPublicKey = "SERVER_KEY_NOT_FOUND"
		}
	}

	// Routes: every VPN network (the hub's firewall decides who reaches
	// whom), or everything for full tunnel; recorded for "config outdated".
	allowedIPsStr, dns := s.nodeRouting(r.Context(), node, network)

	cfgGen := wireguard.NewConfigGenerator()
	config := cfgGen.GeneratePeerConfigDNS(privateKey, serverPublicKey, serverEndpoint, node.VirtualIP.String(), allowedIPsStr, dns)

	if isHead(r) { // no token for a HEAD: only the headers are wanted
		w.Header().Set("Content-Type", "text/x-shellscript")
		return
	}
	s.recordConfigRoutes(r.Context(), node.ID, configRecord(allowedIPsStr, serverEndpoint, dns))
	// 2. A fresh one-time token lets the script check in over the VPN.
	token, err := newSessionToken()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to create enrollment token")
		return
	}
	if err := s.store.CreateEnrollmentToken(r.Context(), node.ID, hashToken(token), authNow(), enrollmentTTL); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to create enrollment token")
		return
	}
	script := installScript(config, "http://"+hub+":8080/api/v1/nodes/"+node.ID+"/checkin", token)

	w.Header().Set("Content-Type", "text/x-shellscript")
	w.Write([]byte(script))
}
