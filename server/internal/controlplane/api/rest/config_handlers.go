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

// getRoutedNetworksForNode returns all network CIDRs that this node can reach
// based on VPN firewall rules
func (s *Server) getRoutedNetworksForNode(r *http.Request, networkID string) []string {
	// Start with own network
	network, err := s.store.GetNetwork(r.Context(), networkID)
	if err != nil || network == nil {
		return []string{}
	}
	
	cidrs := []string{network.CIDR}
	cidrSet := map[string]bool{network.CIDR: true}
	
	// Get all VPN firewall rules
	rules, err := s.store.ListVPNFirewallRules(r.Context())
	if err != nil {
		return cidrs
	}
	
	// Get all networks for lookup
	networks, err := s.store.ListNetworks(r.Context())
	if err != nil {
		return cidrs
	}
	networkMap := make(map[string]*models.Network)
	for _, n := range networks {
		networkMap[n.ID] = n
	}
	
	// Check each enabled ACCEPT rule
	for _, rule := range rules {
		if !rule.Enabled || rule.Action != "accept" {
			continue
		}
		
		// Check if this network is the source
		isSource := false
		switch rule.SourceType {
		case "any":
			isSource = true
		case "network":
			if rule.SourceNetworkID != nil && *rule.SourceNetworkID == networkID {
				isSource = true
			}
		case "node":
			if rule.SourceNodeID != nil {
				node, _ := s.store.GetNode(r.Context(), *rule.SourceNodeID)
				if node != nil && node.NetworkID == networkID {
					isSource = true
				}
			}
		}
		
		if !isSource {
			continue
		}
		
		// Add destination network CIDRs
		switch rule.DestType {
		case "any":
			for _, n := range networks {
				if !cidrSet[n.CIDR] {
					cidrs = append(cidrs, n.CIDR)
					cidrSet[n.CIDR] = true
				}
			}
		case "network":
			if rule.DestNetworkID != nil {
				if n, ok := networkMap[*rule.DestNetworkID]; ok {
					if !cidrSet[n.CIDR] {
						cidrs = append(cidrs, n.CIDR)
						cidrSet[n.CIDR] = true
					}
				}
			}
		case "node":
			if rule.DestNodeID != nil {
				node, _ := s.store.GetNode(r.Context(), *rule.DestNodeID)
				if node != nil {
					if n, ok := networkMap[node.NetworkID]; ok {
						if !cidrSet[n.CIDR] {
							cidrs = append(cidrs, n.CIDR)
							cidrSet[n.CIDR] = true
						}
					}
				}
			}
		case "custom":
			if rule.DestIP != "" && !cidrSet[rule.DestIP] {
				cidrs = append(cidrs, rule.DestIP)
				cidrSet[rule.DestIP] = true
			}
		}
	}
	
	return cidrs
}

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

	serverEndpoint := network.ServerEndpoint
	if serverEndpoint == "" {
		port := network.ListenPort
		if port == 0 {
			port = wireguard.DefaultServerPort
		}
		serverEndpoint = fmt.Sprintf("%s:%d", wireguard.GetServerEndpoint(), port)
	}
	
	// Get all routed networks based on VPN firewall rules
	allowedIPs := s.getRoutedNetworksForNode(r, node.NetworkID)
	allowedIPsStr := strings.Join(allowedIPs, ", ")
	
	cfgGen := wireguard.NewConfigGenerator()
	config := cfgGen.GeneratePeerConfig(
		privateKey,
		serverPublicKey,
		serverEndpoint,
		node.VirtualIP.String(),
		allowedIPsStr,
	)

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

	serverEndpoint := network.ServerEndpoint
	if serverEndpoint == "" {
		port := network.ListenPort
		if port == 0 {
			port = wireguard.DefaultServerPort
		}
		serverEndpoint = fmt.Sprintf("%s:%d", wireguard.GetServerEndpoint(), port)
	}

	// Get all routed networks based on VPN firewall rules
	allowedIPs := s.getRoutedNetworksForNode(r, node.NetworkID)
	allowedIPsStr := strings.Join(allowedIPs, ", ")

	cfgGen := wireguard.NewConfigGenerator()
	config := cfgGen.GeneratePeerConfig(
		privateKey,
		serverPublicKey,
		serverEndpoint,
		node.VirtualIP.String(),
		allowedIPsStr,
	)

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
	
	var serverPublicKey, serverEndpoint string
	if network.ServerPublicKey != "" {
		serverPublicKey = network.ServerPublicKey
		serverEndpoint = network.ServerEndpoint
	} else {
		serverPublicKey = "SERVER_KEY_NOT_CONFIGURED"
		port := network.ListenPort
		if port == 0 {
			port = wireguard.DefaultServerPort
		}
		serverEndpoint = fmt.Sprintf("%s:%d", wireguard.GetServerEndpoint(), port)
	}

	// Get all routed networks based on VPN firewall rules
	allowedIPsList := s.getRoutedNetworksForNode(r, networkID)
	allowedIPsStr := strings.Join(allowedIPsList, ", ")

	cfgGen := wireguard.NewConfigGenerator()
	config := cfgGen.GeneratePeerConfig(
		privateKey,
		serverPublicKey,
		serverEndpoint,
		node.VirtualIP.String(),
		allowedIPsStr,
	)

	response := CreateServerResponse{Node: node, Config: config}
	
	s.triggerReconcile()
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

	serverEndpoint := network.ServerEndpoint
	if serverEndpoint == "" {
		port := network.ListenPort
		if port == 0 {
			port = wireguard.DefaultServerPort
		}
		serverEndpoint = fmt.Sprintf("%s:%d", wireguard.GetServerEndpoint(), port)
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
		// If still empty, use placeholder to avoid crash, script will fail to connect but at least run
		if serverPublicKey == "" {
			serverPublicKey = "SERVER_KEY_NOT_FOUND" 
		}
	}

	// Get all routed networks based on VPN firewall rules
	allowedIPsList := s.getRoutedNetworksForNode(r, node.NetworkID)
	allowedIPsStr := strings.Join(allowedIPsList, ", ")

	cfgGen := wireguard.NewConfigGenerator()
	config := cfgGen.GeneratePeerConfig(
		privateKey,
		serverPublicKey,
		serverEndpoint,
		node.VirtualIP.String(),
		allowedIPsStr,
	)

	if isHead(r) { // no token for a HEAD: only the headers are wanted
		w.Header().Set("Content-Type", "text/x-shellscript")
		return
	}
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

