package rest

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/controlplane/reconciler"
	"github.com/novusgate/novusgate/internal/controlplane/store"
	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
	"golang.org/x/crypto/bcrypt"
)

// Admin credentials from env or defaults
var (
	adminUsername = getEnvOrDefault("ADMIN_USERNAME", "admin")
	adminPassword = getEnvOrDefault("ADMIN_PASSWORD", "") // REQUIRED - set via environment
	adminToken    = ""
	apiKey        = getEnvOrDefault("novusgate_API_KEY", "") // Request-level security key
)

func getEnvOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func init() {
	// Generate a random admin token on startup
	b := make([]byte, 32)
	rand.Read(b)
	adminToken = hex.EncodeToString(b)
}

// PeerActivity tracks the last known activity of a peer
type PeerActivity struct {
	LastRxBytes int64
	LastSeen    time.Time
}

// Server is the REST API server
type Server struct {
	store        *store.Store
	router       *mux.Router
	managers   map[string]*wireguard.Manager
	managersMu sync.RWMutex
	peerActivity map[string]*PeerActivity
	firewall     *firewall.Engine // nil, or engine for FIREWALL_ENGINE=shadow|nft
	reconciler   *reconciler.Reconciler // nil when WG_RECONCILER=off
	activityMu   sync.RWMutex
}

// NewServer creates a new REST API server
func NewServer(store *store.Store) *Server {
	s := &Server{
		store:        store,
		router:       mux.NewRouter(),
		managers:     make(map[string]*wireguard.Manager),
		peerActivity: make(map[string]*PeerActivity),
	}
	s.setupRoutes()
	// Initialize existing networks from DB
	go s.loadNetworks()
	return s
}

// loadNetworks initializes managers for existing networks and imports/syncs peers
func (s *Server) loadNetworks() {
	// Give DB a moment to come up
	time.Sleep(2 * time.Second)
	
	ctx := context.Background()
	networks, err := s.store.ListNetworks(ctx)
	if err != nil {
		slog.Error(fmt.Sprintf("Error loading networks: %v", err))
		return
	}
	
	for _, network := range networks {
		if network.InterfaceName == "" {
			continue
		}
		// Initialize manager
		mgr := wireguard.NewManager(network.InterfaceName)
		if err := wgInit(mgr); err != nil {
			slog.Warn(fmt.Sprintf("Warning: WireGuard tools missing for %s", network.Name))
			continue
		}
		
		// If port is 0 (legacy), default to 51820
		port := network.ListenPort
		if port == 0 {
			port = 51820
		}
		
		// Ensure config exists/is valid (idempotent)
		s.managersMu.Lock()
		s.managers[network.ID] = mgr
		s.managersMu.Unlock()
		
		// Ensure interface is UP
		if err := mgr.Up(); err != nil {
			slog.Info(fmt.Sprintf("Note: Interface %s might already be up: %v", network.InterfaceName, err))
		} else {
			slog.Info(fmt.Sprintf("Network %s (%s) is UP on port %d", network.Name, network.InterfaceName, port))
		}

		// SYNC: Import existing peers from WireGuard into DB
		peers, err := mgr.GetPeers()
		if err == nil && len(peers) > 0 {
			slog.Info(fmt.Sprintf("Syncing %d peers from %s to database...", len(peers), network.InterfaceName))
			
			// Get existing DB nodes to avoid duplicates
			dbNodes, err := s.store.ListNodes(ctx, network.ID)
			if err != nil {
				slog.Error(fmt.Sprintf("Failed to list DB nodes: %v", err))
				continue
			}
			
			existingKeys := make(map[string]bool)
			for _, n := range dbNodes {
				existingKeys[n.PublicKey] = true
			}
			
			for pubKey, peer := range peers {
				if !existingKeys[pubKey] {
					// Import this peer
					slog.Info(fmt.Sprintf("Importing peer %s...", pubKey))
					
					// Parse IP from AllowedIPs (first one if comma separated)
					ips := strings.Split(peer.AllowedIPs, ",")
					if len(ips) == 0 {
						slog.Warn(fmt.Sprintf("Warning: No AllowedIPs for peer %s, skipping import", pubKey))
						continue
					}
					
					// Take first IP and remove CIDR suffix if present
					ipStr := strings.TrimSpace(ips[0])
					if idx := strings.Index(ipStr, "/"); idx != -1 {
						ipStr = ipStr[:idx]
					}
					
					virtualIP := net.ParseIP(ipStr)
					if virtualIP == nil {
						slog.Warn(fmt.Sprintf("Warning: Invalid IP %s for peer %s, skipping import", ipStr, pubKey))
						continue
					}

					// Create Node
					hostname := "imported-client"
					// Try to give a better name for admin network
					if network.InterfaceName == "wg1" {
						hostname = "Admin Client"
					} else {
						hostname = fmt.Sprintf("Imported Node (%s)", ipStr)
					}

					node := &models.Node{
						NetworkID: network.ID,
						Name:      hostname,
						PublicKey: pubKey,
						VirtualIP: virtualIP,
						Status:    models.NodeStatusOnline, // Assume online if present in WG
						NodeInfo: &models.NodeInfo{
							Hostname:     hostname,
							OS:           "unknown",
							Architecture: "unknown",
						},
					}
					
					if err := s.store.CreateNode(ctx, node); err != nil {
						slog.Error(fmt.Sprintf("Failed to import node %s: %v", pubKey, err))
					} else {
						slog.Info(fmt.Sprintf("Successfully imported node %s (%s)", hostname, ipStr))
						existingKeys[pubKey] = true // Mark as done
					}
				}
			}
		}

		// Restore DB peers missing from the interface. Runtime peers are not
		// written to wgN.conf (SaveConfig = false), so a host reboot drops them.
		dbNodes, err := s.store.ListNodes(ctx, network.ID)
		if err != nil {
			slog.Warn(fmt.Sprintf("Warning: cannot restore peers for %s: %v", network.InterfaceName, err))
			continue
		}
		livePeers, err := mgr.GetPeers()
		if err != nil {
			slog.Warn(fmt.Sprintf("Warning: cannot read peers of %s: %v", network.InterfaceName, err))
			continue
		}
		restored, restoreErrs := restorePeers(mgr, dbNodes, livePeers, time.Now())
		if restored > 0 || len(restoreErrs) > 0 {
			slog.Info(fmt.Sprintf("Restored %d peers on %s (%d errors)", restored, network.InterfaceName, len(restoreErrs)))
		}
		for _, e := range restoreErrs {
			slog.Warn(fmt.Sprintf("Warning: %s", e))
		}
	}
}

// getManager returns the WireGuard manager for a network
// If manager doesn't exist but network does, it creates and registers one
func (s *Server) getManager(networkID string) *wireguard.Manager {
	s.managersMu.RLock()
	mgr := s.managers[networkID]
	s.managersMu.RUnlock()
	
	if mgr != nil {
		return mgr
	}
	
	// Manager not found - try to create it from network config
	ctx := context.Background()
	network, err := s.store.GetNetwork(ctx, networkID)
	if err != nil || network == nil || network.InterfaceName == "" {
		return nil
	}
	
	// Create and register manager
	newMgr := wireguard.NewManager(network.InterfaceName)
	if err := wgInit(newMgr); err != nil {
		slog.Error(fmt.Sprintf("Warning: Failed to init WireGuard manager for %s: %v", network.Name, err))
		return nil
	}
	
	s.managersMu.Lock()
	// Double-check another goroutine didn't create it
	if existing := s.managers[networkID]; existing != nil {
		s.managersMu.Unlock()
		return existing
	}
	s.managers[networkID] = newMgr
	s.managersMu.Unlock()
	
	slog.Info(fmt.Sprintf("Lazily initialized WireGuard manager for network %s (%s)", network.Name, network.InterfaceName))
	return newMgr
}

// Router returns the HTTP router
func (s *Server) Router() http.Handler {
	return s.router
}

func (s *Server) setupRoutes() {
	// Apply global middleware
	// Order: the request log wraps everything (it records the 500 that
	// RecoverMiddleware writes), then panic recovery, then auth.
	s.router.Use(LoggingMiddleware, RecoverMiddleware, APIKeyMiddleware, AuthMiddleware)

	api := s.router.PathPrefix("/api/v1").Subrouter()

	// Networks
	api.HandleFunc("/networks", s.handleListNetworks).Methods("GET")
	api.HandleFunc("/networks", s.handleCreateNetwork).Methods("POST")
	api.HandleFunc("/networks/{id}", s.handleGetNetwork).Methods("GET")
	api.HandleFunc("/networks/{id}", s.handleDeleteNetwork).Methods("DELETE")
	
	// Nodes
	api.HandleFunc("/networks/{networkId}/nodes", s.handleListNodes).Methods("GET")
	api.HandleFunc("/nodes/{id}", s.handleGetNode).Methods("GET")
	api.HandleFunc("/nodes/{id}", s.handleUpdateNode).Methods("PUT", "PATCH")
	api.HandleFunc("/nodes/{id}", s.handleDeleteNode).Methods("DELETE")
	api.HandleFunc("/nodes/{id}/checkin", s.handleNodeCheckIn).Methods("POST")
	
	// WireGuard Config & Utils
	api.HandleFunc("/nodes/{id}/config", s.handleDownloadConfig).Methods("GET")
	api.HandleFunc("/nodes/{id}/qrcode", s.handleGetQRCode).Methods("GET")
	api.HandleFunc("/nodes/{id}/install.sh", s.handleNodeInstallScript).Methods("GET")
	api.HandleFunc("/networks/{networkId}/servers", s.handleCreateServerWithConfig).Methods("POST")

	// Health check
	s.router.HandleFunc("/health", s.handleHealth).Methods("GET")
	
	// Debug endpoint - shows WireGuard interface status
	api.HandleFunc("/debug/wireguard/{networkId}", s.handleDebugWireGuard).Methods("GET")
	
	// Sync endpoint - syncs DB peers to WireGuard interface
	api.HandleFunc("/networks/{networkId}/sync", s.handleSyncPeers).Methods("POST")
	
	// Auth
	s.router.HandleFunc("/api/v1/auth/login", s.handleLogin).Methods("POST", "OPTIONS")
	api.HandleFunc("/auth/password", s.handleUpdatePassword).Methods("PUT")

	// User Management
	api.HandleFunc("/users", s.handleListUsers).Methods("GET")
	api.HandleFunc("/users", s.handleCreateUser).Methods("POST")
	api.HandleFunc("/users/{id}", s.handleDeleteUser).Methods("DELETE")

	// System Info & Monitoring
	api.HandleFunc("/system/info", s.handleSystemInfo).Methods("GET")
	api.HandleFunc("/system/fail2ban/status", s.handleFail2BanStatus).Methods("GET")
	api.HandleFunc("/system/fail2ban/logs", s.handleFail2BanLogs).Methods("GET")
	api.HandleFunc("/system/fail2ban/unban", s.handleFail2BanUnban).Methods("POST")
	api.HandleFunc("/system/fail2ban/ban", s.handleFail2BanManualBan).Methods("POST")
	api.HandleFunc("/system/fail2ban/jail/settings", s.handleFail2BanGetJailSettings).Methods("GET")
	api.HandleFunc("/system/fail2ban/jail/settings", s.handleFail2BanUpdateJailSettings).Methods("PUT")
	api.HandleFunc("/system/fail2ban/whitelist", s.handleFail2BanGetWhitelist).Methods("GET")
	api.HandleFunc("/system/fail2ban/whitelist", s.handleFail2BanUpdateWhitelist).Methods("PUT")
	api.HandleFunc("/system/fail2ban/permanent-bans", s.handleFail2BanGetPermanentBans).Methods("GET")
	api.HandleFunc("/system/fail2ban/permanent-bans", s.handleFail2BanRemovePermanentBan).Methods("DELETE")
	api.HandleFunc("/system/fail2ban/jail/control", s.handleFail2BanJailControl).Methods("POST")
	api.HandleFunc("/system/fail2ban/reload", s.handleFail2BanReload).Methods("POST")
	api.HandleFunc("/system/fail2ban/ping", s.handleFail2BanPing).Methods("GET")
	api.HandleFunc("/system/fail2ban/ban-history", s.handleFail2BanHistory).Methods("GET")
	
	// All Networks Stats (for dashboard)
	api.HandleFunc("/stats/overview", s.handleStatsOverview).Methods("GET")

	// Host Firewall Management
	api.HandleFunc("/firewall/host/rules", s.handleFirewallGetRules).Methods("GET")
	api.HandleFunc("/firewall/host/port/open", s.handleFirewallOpenPort).Methods("POST")
	api.HandleFunc("/firewall/host/port/close", s.handleFirewallClosePort).Methods("POST")
	api.HandleFunc("/firewall/host/ip/block", s.handleFirewallBlockIP).Methods("POST")
	api.HandleFunc("/firewall/host/ip/allow", s.handleFirewallAllowIP).Methods("POST")
	api.HandleFunc("/firewall/host/rules/delete", s.handleFirewallDeleteRule).Methods("POST")
	api.HandleFunc("/firewall/host/export", s.handleFirewallExport).Methods("GET")
	api.HandleFunc("/firewall/host/import", s.handleFirewallImport).Methods("POST")
	api.HandleFunc("/firewall/host/reset", s.handleFirewallReset).Methods("POST")

	// VPN Firewall Management
	api.HandleFunc("/firewall/vpn/rules", s.handleVPNFirewallGetRules).Methods("GET")
	api.HandleFunc("/firewall/vpn/rules", s.handleVPNFirewallCreateRule).Methods("POST")
	api.HandleFunc("/firewall/vpn/rules/{id}", s.handleVPNFirewallUpdateRule).Methods("PUT")
	api.HandleFunc("/firewall/vpn/rules/{id}", s.handleVPNFirewallDeleteRule).Methods("DELETE")
	api.HandleFunc("/firewall/vpn/apply", s.handleVPNFirewallApply).Methods("POST")
	s.setupFirewallV2Routes(api)

	// Helper for SPA (Single Page Application) serving
	s.router.PathPrefix("/").HandlerFunc(s.handleSPA)
}

func (s *Server) handleSPA(w http.ResponseWriter, r *http.Request) {
	// Security: Prevent directory traversal
	path := r.URL.Path
	if strings.Contains(path, "..") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// Default to dist directory relative to binary
	staticPath := "./dist"
	if envPath := os.Getenv("STATIC_FILES_PATH"); envPath != "" {
		staticPath = envPath
	}

	// Check if file exists
	fullPath := staticPath + path
	if path == "/" {
		fullPath = staticPath + "/index.html"
	}

	info, err := os.Stat(fullPath)
	if os.IsNotExist(err) || info.IsDir() {
		// File not found or is directory -> serve index.html (SPA fallback)
		http.ServeFile(w, r, staticPath+"/index.html")
		return
	}

	// Serve the file
	http.ServeFile(w, r, fullPath)
}


// Response helpers
func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func errorResponse(w http.ResponseWriter, status int, message string) {
	jsonResponse(w, status, map[string]string{"error": message})
}

// Login handler
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Add CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	
	// Validate credentials against DB
	user, err := s.store.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to check user")
		return
	}
	
	if user == nil {
		errorResponse(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		errorResponse(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	
	// Return token
	jsonResponse(w, http.StatusOK, map[string]string{
		"token":    adminToken,
		"username": adminUsername,
	})
}

// Update Password handler
func (s *Server) handleUpdatePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string `json:"username"`
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate current password first
	user, err := s.store.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to check user")
		return
	}
	if user == nil {
		errorResponse(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.OldPassword)); err != nil {
		errorResponse(w, http.StatusUnauthorized, "invalid old password")
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	// Update password
	if err := s.store.UpdateUserPassword(r.Context(), req.Username, string(hashedPassword)); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to update password")
		return
	}

	jsonResponse(w, http.StatusOK, map[string]string{"status": "success"})
}

// User Management Handlers

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to list users")
		return
	}
	// Don't return password hashes
	for _, u := range users {
		u.PasswordHash = ""
	}
	jsonResponse(w, http.StatusOK, users)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	
	if req.Username == "" || req.Password == "" {
		errorResponse(w, http.StatusBadRequest, "username and password required")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	user := &models.User{
		Username:     req.Username,
		PasswordHash: string(hashedPassword),
	}

	if err := s.store.CreateUser(r.Context(), user); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to create user")
		return
	}
	
	user.PasswordHash = "" // Don't return hash
	jsonResponse(w, http.StatusCreated, user)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	// Prevent deleting the last admin if possible, but for MVP just delete
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to delete user")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// networksOverlap checks if two IP networks overlap
func networksOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// Network handlers
func (s *Server) handleListNetworks(w http.ResponseWriter, r *http.Request) {
	networks, err := s.store.ListNetworks(r.Context())
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to list networks")
		return
	}
	jsonResponse(w, http.StatusOK, networks)
}

func (s *Server) handleCreateNetwork(w http.ResponseWriter, r *http.Request) {
	var network models.Network
	if err := json.NewDecoder(r.Body).Decode(&network); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate CIDR format
	_, newNet, err := net.ParseCIDR(network.CIDR)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid CIDR format: "+err.Error())
		return
	}

	// Dynamic Allocation Logic
	existing, err := s.store.ListNetworks(r.Context())
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to list networks")
		return
	}

	// Check for CIDR overlap with existing networks
	for _, existingNet := range existing {
		_, existingCIDR, err := net.ParseCIDR(existingNet.CIDR)
		if err != nil {
			continue // Skip invalid existing CIDRs
		}
		
		// Check if networks overlap
		if networksOverlap(newNet, existingCIDR) {
			errorResponse(w, http.StatusConflict, fmt.Sprintf(
				"CIDR %s overlaps with existing network '%s' (%s)",
				network.CIDR, existingNet.Name, existingNet.CIDR,
			))
			return
		}
	}
	
	// 1. Assign Interface Name (wg0, wg1, etc)
	// Find highest 'wgN'
	maxIdx := -1
	usedPorts := make(map[int]bool)
	
	for _, net := range existing {
		if strings.HasPrefix(net.InterfaceName, "wg") {
			var idx int
			if _, err := fmt.Sscanf(net.InterfaceName, "wg%d", &idx); err == nil {
				if idx > maxIdx {
					maxIdx = idx
				}
			}
		}
		if net.ListenPort > 0 {
			usedPorts[net.ListenPort] = true
		}
	}
	
	newIdx := maxIdx + 1
	network.InterfaceName = fmt.Sprintf("wg%d", newIdx)
	
	// 2. Assign Port (Start at 51820)
	port := 51820
	for {
		if !usedPorts[port] {
			break
		}
		port++
	}
	network.ListenPort = port
	
	// 3. Generate WireGuard keys BEFORE saving to DB
	privateKey, publicKey, err := generateKeys()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to generate WireGuard keys: "+err.Error())
		return
	}
	
	// Set keys and endpoint on network
	network.ServerPrivateKey = privateKey
	network.ServerPublicKey = publicKey
	network.ServerEndpoint = fmt.Sprintf("%s:%d", wireguard.GetServerEndpoint(), port)
	
	// 4. Save to DB (now with keys)
	if err := s.store.CreateNetwork(r.Context(), &network); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to create network: "+err.Error())
		return
	}
	
	// 5. Initialize WireGuard Interface
	mgr := wireguard.NewManager(network.InterfaceName)
	if err := wgInit(mgr); err != nil {
		slog.Warn(fmt.Sprintf("Warning: WireGuard tools not available: %v", err))
	} else {
		// Create WireGuard config with the generated key
		// Calculate server IP (first usable IP in CIDR)
		serverAddr, addrErr := hubAddress(network.CIDR)
		if addrErr != nil {
			slog.Warn(fmt.Sprintf("Warning: invalid CIDR %s: %v", network.CIDR, addrErr))
		} else if err := mgr.CreateServerConfigWithKey(privateKey, serverAddr, port); err != nil {
			slog.Error(fmt.Sprintf("Warning: Failed to create WireGuard config for %s: %v", network.Name, err))
		} else {
			slog.Info(fmt.Sprintf("WireGuard interface %s created for network %s", network.InterfaceName, network.Name))
			// Bring up the interface
			if err := mgr.Up(); err != nil {
				slog.Error(fmt.Sprintf("Warning: Failed to bring up %s: %v", network.InterfaceName, err))
			}
		}
		
		// Register manager
		s.managersMu.Lock()
		s.managers[network.ID] = mgr
		s.managersMu.Unlock()
	}
	
	s.reconcileFirewall(r.Context())
	s.triggerReconcile()
	jsonResponse(w, http.StatusCreated, network)
}

func (s *Server) handleGetNetwork(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	network, err := s.store.GetNetwork(r.Context(), id)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to get network")
		return
	}
	if network == nil {
		errorResponse(w, http.StatusNotFound, "network not found")
		return
	}
	jsonResponse(w, http.StatusOK, network)
}

func (s *Server) handleDeleteNetwork(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	
	// Get network first to get interface name
	network, err := s.store.GetNetwork(r.Context(), id)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to get network")
		return
	}
	if network == nil {
		errorResponse(w, http.StatusNotFound, "network not found")
		return
	}
	
	// Prevent deleting Admin Network (wg0)
	if network.InterfaceName == "wg0" {
		errorResponse(w, http.StatusForbidden, "cannot delete Admin Management Network")
		return
	}
	
	// Bring down WireGuard interface
	if network.InterfaceName != "" {
		wgTeardown(network.InterfaceName)

		// Unregister manager
		s.managersMu.Lock()
		delete(s.managers, id)
		s.managersMu.Unlock()
	}
	
	// Delete from DB
	if err := s.store.DeleteNetwork(r.Context(), id); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to delete network")
		return
	}
	
	slog.Info(fmt.Sprintf("Network %s (%s) deleted", network.Name, network.InterfaceName))
	s.reconcileFirewall(r.Context())
	s.triggerReconcile()
	w.WriteHeader(http.StatusNoContent)
}

// Node handlers
func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	networkID := mux.Vars(r)["networkId"]
	nodes, err := s.store.ListNodes(r.Context(), networkID)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to list nodes")
		return
	}

	// Fetch real-time status from WireGuard
	var peers map[string]wireguard.PeerStatus
	mgr := s.getManager(networkID)
	if mgr != nil {
		p, err := mgr.GetPeers()
		if err == nil {
			peers = p
		}
	}

	for i := range nodes {
		s.enrichNode(nodes[i], peers)
	}

	jsonResponse(w, http.StatusOK, nodes)
}

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
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

	// Enrich with real-time status
	var peers map[string]wireguard.PeerStatus
	mgr := s.getManager(node.NetworkID)
	if mgr != nil {
		p, err := mgr.GetPeers()
		if err == nil {
			peers = p
		}
	}
	s.enrichNode(node, peers)

	jsonResponse(w, http.StatusOK, node)
}

// enrichNode adds real-time info and metadata to a node
func (s *Server) enrichNode(node *models.Node, peers map[string]wireguard.PeerStatus) {
	// 1. Check expiration first
	isExpired := false
	if node.ExpiresAt != nil && !node.ExpiresAt.IsZero() {
		if time.Now().After(*node.ExpiresAt) {
			node.Status = models.NodeStatusExpired
			isExpired = true
			
			// If expired and session exists in WG, remove it
			mgr := s.getManager(node.NetworkID)
			if mgr != nil && peers != nil {
				if _, ok := peers[node.PublicKey]; ok {
					slog.Info(fmt.Sprintf("Enforcing expiration for node %s (%s)", node.Name, node.ID))
					mgr.RemovePeer(node.PublicKey)
				}
			}
		}
	}

	if peers != nil && !isExpired {
		if status, ok := peers[node.PublicKey]; ok {
			// Clean port from endpoint if present
			ep := status.Endpoint
			if idx := strings.LastIndex(ep, ":"); idx != -1 {
				ep = ep[:idx]
			}
			if ep != "(none)" && ep != "" {
				node.PublicIP = ep
			}
			
			node.TransferRx = status.TransferRx
			node.TransferTx = status.TransferTx
			
			
			// Update activity map
			s.activityMu.Lock()
			activity, exists := s.peerActivity[node.PublicKey]
			if !exists {
				activity = &PeerActivity{}
				s.peerActivity[node.PublicKey] = activity
			}
			
			// If we received data since last check, update LastSeen to NOW
			if status.TransferRx > activity.LastRxBytes {
				activity.LastSeen = time.Now()
				activity.LastRxBytes = status.TransferRx
			}
			s.activityMu.Unlock()

			// Determine status
			isOnline := false
			
			// 1. Check traffic activity (fast detection ~30-45s)
			// Clients with PersistentKeepalive=25 will send data every ~25s
			if !activity.LastSeen.IsZero() && time.Since(activity.LastSeen) < 45*time.Second {
				isOnline = true
				// Use the more recent activity time for LastSeen display
				if activity.LastSeen.After(time.Unix(status.LatestHandshakeTime, 0)) {
					node.LastSeen = activity.LastSeen
				}
			}

			// 2. Fallback to handshake (slow detection ~2.5m)
			if !isOnline && status.LatestHandshakeTime > 0 {
				hsTime := time.Unix(status.LatestHandshakeTime, 0)
				// Use handshake time if it's recent
				if time.Since(hsTime) < 150*time.Second {
					isOnline = true
					node.LastSeen = hsTime
				}
			}
			
			if status.LatestHandshakeTime > 0 && node.LastSeen.IsZero() {
				node.LastSeen = time.Unix(status.LatestHandshakeTime, 0)
			}

			if isOnline {
				node.Status = models.NodeStatusOnline
			} else {
				node.Status = models.NodeStatusOffline
			}
		}
	}

	// Dynamic metadata from labels for MVP
	if node.NodeInfo == nil || node.NodeInfo.OS == "" {
		if node.NodeInfo == nil {
			node.NodeInfo = &models.NodeInfo{}
		}
		if os, ok := node.Labels["os"]; ok {
			node.NodeInfo.OS = os
		}
		if arch, ok := node.Labels["arch"]; ok {
			node.NodeInfo.Architecture = arch
		}
		if hostname, ok := node.Labels["hostname"]; ok {
			node.NodeInfo.Hostname = hostname
		}
	}
}

func (s *Server) handleUpdateNode(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	
	var req struct {
		Name      *string          `json:"name"`
		ExpiresAt *string          `json:"expires_at"` // ISO string or null to remove
		Status    *string          `json:"status"`
		NodeInfo  *models.NodeInfo `json:"node_info"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	node, err := s.store.GetNode(r.Context(), id)
	if err != nil || node == nil {
		errorResponse(w, http.StatusNotFound, "node not found")
		return
	}
	before := *node

	// Update name if provided
	if req.Name != nil && *req.Name != "" {
		node.Name = *req.Name
	}

	// Update expires_at
	if req.ExpiresAt != nil {
		if *req.ExpiresAt == "" {
			// Empty string means remove expiration
			node.ExpiresAt = nil
		} else {
			t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
			if err == nil {
				node.ExpiresAt = &t
			}
		}
	}

	// Update status if provided
	if req.Status != nil {
		node.Status = models.NodeStatus(*req.Status)
	} else if node.Status == models.NodeStatusExpired && req.ExpiresAt != nil && *req.ExpiresAt != "" {
		// A new expiry for an expired node re-activates it.
		node.Status = models.NodeStatusPending
	}

	// Update NodeInfo if provided
	if req.NodeInfo != nil {
		if node.NodeInfo == nil {
			node.NodeInfo = &models.NodeInfo{}
		}
		if req.NodeInfo.OS != "" {
			node.NodeInfo.OS = req.NodeInfo.OS
		}
		if req.NodeInfo.Architecture != "" {
			node.NodeInfo.Architecture = req.NodeInfo.Architecture
		}
		if req.NodeInfo.Hostname != "" {
			node.NodeInfo.Hostname = req.NodeInfo.Hostname
		}
	}

	if err := s.store.UpdateNode(r.Context(), node); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to update node")
		return
	}

	// B11: the peer follows the node's activity.
	if add, remove := peerTransition(&before, node, time.Now()); add || remove {
		if mgr := s.getManager(node.NetworkID); mgr != nil {
			if add {
				slog.Info(fmt.Sprintf("Reactivating node %s, adding to WireGuard", node.Name))
				if err := mgr.AddPeer(node.PublicKey, node.VirtualIP.String()+"/32"); err != nil {
					slog.Error(fmt.Sprintf("Warning: failed to add reactivated peer to WireGuard: %v", err))
				}
			} else if err := mgr.RemovePeer(node.PublicKey); err != nil {
				slog.Error(fmt.Sprintf("Warning: failed to remove peer from WireGuard: %v", err))
			}
		}
	}

	// Enrich with real-time data before returning
	mgr := s.getManager(node.NetworkID)
	var peers map[string]wireguard.PeerStatus
	if mgr != nil {
		peers, _ = mgr.GetPeers()
	}
	s.enrichNode(node, peers)
	s.triggerReconcile()
	jsonResponse(w, http.StatusOK, node)
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	
	// Get node first to get public key
	node, err := s.store.GetNode(r.Context(), id)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to fetch node")
		return
	}
	if node == nil {
		errorResponse(w, http.StatusNotFound, "node not found")
		return
	}

	// Remove from WireGuard
	mgr := s.getManager(node.NetworkID)
	if mgr != nil && node.PublicKey != "" {
		if err := mgr.RemovePeer(node.PublicKey); err != nil {
			slog.Error(fmt.Sprintf("Warning: failed to remove peer from WireGuard: %v", err))
			// Continue with deletion anyway
		}
	}

	if err := s.store.DeleteNode(r.Context(), id); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to delete node")
		return
	}
	s.reconcileFirewall(r.Context())
	s.triggerReconcile()
	jsonResponse(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleNodeCheckIn(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var req struct {
		NodeInfo *models.NodeInfo  `json:"node_info"`
		Labels   map[string]string `json:"labels"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	node, err := s.store.GetNode(r.Context(), id)
	if err != nil || node == nil {
		errorResponse(w, http.StatusNotFound, "node not found")
		return
	}

	// Update NodeInfo if provided
	if req.NodeInfo != nil {
		if node.NodeInfo == nil {
			node.NodeInfo = req.NodeInfo
		} else {
			if req.NodeInfo.OS != "" {
				node.NodeInfo.OS = req.NodeInfo.OS
			}
			if req.NodeInfo.Architecture != "" {
				node.NodeInfo.Architecture = req.NodeInfo.Architecture
			}
			if req.NodeInfo.Hostname != "" {
				node.NodeInfo.Hostname = req.NodeInfo.Hostname
			}
		}
	}

	// Update/Merge Labels
	if req.Labels != nil {
		if node.Labels == nil {
			node.Labels = make(map[string]string)
		}
		for k, v := range req.Labels {
			node.Labels[k] = v
		}
	}

	if err := s.store.UpdateNode(r.Context(), node); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to update node info")
		return
	}

	jsonResponse(w, http.StatusOK, node)
}






// interfaceUp reports whether a network interface exists and is up. The
// control plane shares the host's network namespace (replaced in tests).
var interfaceUp = func(name string) bool {
	ifc, err := net.InterfaceByName(name)
	return err == nil && ifc.Flags&net.FlagUp != 0
}

// handleHealth always answers 200 (API contract); "status" is "healthy" or
// "degraded" and "checks" says why. It is public, so it reports states only,
// never error texts.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	healthy := true
	checks := map[string]interface{}{}

	if s.store.Ping(ctx) != nil {
		healthy = false
		checks["database"] = map[string]interface{}{"ok": false}
	} else {
		checks["database"] = map[string]interface{}{"ok": true}
		wgOK := true
		interfaces := map[string]string{}
		if networks, err := s.store.ListNetworks(ctx); err != nil {
			wgOK = false
		} else {
			for _, n := range networks {
				if n.InterfaceName == "" {
					continue
				}
				state := "up"
				if !interfaceUp(n.InterfaceName) {
					state, wgOK = "down", false
				}
				interfaces[n.InterfaceName] = state
			}
		}
		healthy = healthy && wgOK
		checks["wireguard"] = map[string]interface{}{"ok": wgOK, "interfaces": interfaces}
	}

	fw := map[string]interface{}{"ok": true, "mode": string(firewall.ModeIptables)}
	if s.firewall != nil {
		fw["mode"] = string(s.firewall.Mode)
		if s.firewall.Mode == firewall.ModeNft {
			ready := s.firewall.Ready()
			_, pending := s.firewall.PendingChange()
			fw["ok"], fw["ready"], fw["pending"] = ready, ready, pending
			healthy = healthy && ready
		}
	}
	if s.reconciler != nil {
		rep := s.reconciler.Status()
		rc := map[string]interface{}{"ok": rep.OK(), "mode": string(s.reconciler.Mode), "pending": 0, "last_run": nil}
		if !rep.Time.IsZero() {
			rc["last_run"] = rep.Time.UTC().Format(time.RFC3339)
			if rep.Mode != reconciler.ModeEnforce {
				rc["pending"] = len(rep.Actions) // shadow: changes enforce would make
			}
		}
		healthy = healthy && rep.OK()
		checks["reconciler"] = rc
	}
	checks["firewall"] = fw

	status := "healthy"
	if !healthy {
		status = "degraded"
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{"status": status, "version": "0.1.0", "checks": checks})
}

// System Info - CPU, RAM, Disk
func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	info := map[string]interface{}{}
	
	// CPU Info
	cpuInfo, _ := os.ReadFile("/proc/cpuinfo")
	cpuCount := strings.Count(string(cpuInfo), "processor")
	info["cpu_cores"] = cpuCount
	
	// CPU Model
	for _, line := range strings.Split(string(cpuInfo), "\n") {
		if strings.HasPrefix(line, "model name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				info["cpu_model"] = strings.TrimSpace(parts[1])
				break
			}
		}
	}
	
	// Load Average
	loadAvg, _ := os.ReadFile("/proc/loadavg")
	if len(loadAvg) > 0 {
		parts := strings.Fields(string(loadAvg))
		if len(parts) >= 3 {
			info["load_1m"] = parts[0]
			info["load_5m"] = parts[1]
			info["load_15m"] = parts[2]
		}
	}
	
	// Memory Info
	memInfo, _ := os.ReadFile("/proc/meminfo")
	memMap := make(map[string]int64)
	for _, line := range strings.Split(string(memInfo), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			key := strings.TrimSuffix(parts[0], ":")
			var val int64
			fmt.Sscanf(parts[1], "%d", &val)
			memMap[key] = val * 1024 // Convert KB to bytes
		}
	}
	info["memory_total"] = memMap["MemTotal"]
	info["memory_free"] = memMap["MemFree"]
	info["memory_available"] = memMap["MemAvailable"]
	info["memory_used"] = memMap["MemTotal"] - memMap["MemAvailable"]
	info["memory_buffers"] = memMap["Buffers"]
	info["memory_cached"] = memMap["Cached"]
	
	// Disk Info (root partition)
	// Using df command for simplicity
	dfOut, err := execCommand("df", "-B1", "/")
	if err == nil {
		lines := strings.Split(dfOut, "\n")
		if len(lines) >= 2 {
			fields := strings.Fields(lines[1])
			if len(fields) >= 4 {
				var total, used, avail int64
				fmt.Sscanf(fields[1], "%d", &total)
				fmt.Sscanf(fields[2], "%d", &used)
				fmt.Sscanf(fields[3], "%d", &avail)
				info["disk_total"] = total
				info["disk_used"] = used
				info["disk_free"] = avail
			}
		}
	}
	
	// Uptime
	uptimeData, _ := os.ReadFile("/proc/uptime")
	if len(uptimeData) > 0 {
		var uptime float64
		fmt.Sscanf(string(uptimeData), "%f", &uptime)
		info["uptime_seconds"] = int64(uptime)
	}
	
	// Hostname
	hostname, _ := os.Hostname()
	info["hostname"] = hostname
	
	jsonResponse(w, http.StatusOK, info)
}

// execCommand and execHostCommand run commands in the container or on the
// host; tests replace them so no host command ever runs.
var (
	execCommand     = runCommand
	execHostCommand = runHostCommand
)

// generateKeys creates a WireGuard key pair (replaced in tests).
var generateKeys = wireguard.GenerateKeys

// wgInit checks that WireGuard tools exist before a manager touches the
// host; wgTeardown brings an interface down and removes its config. Tests
// replace both so no interface is ever created on the machine running them.
var (
	wgInit     = func(m *wireguard.Manager) error { return m.Init() }
	wgTeardown = func(iface string) {
		if err := wireguard.NewManager(iface).Down(); err != nil {
			slog.Error(fmt.Sprintf("Warning: Failed to bring down %s: %v", iface, err))
		}
		os.Remove(fmt.Sprintf("/etc/wireguard/%s.conf", iface))
	}
)

// runCommand runs a command in the container.
func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	return string(out), err
}

// runHostCommand executes a command on the host system using nsenter
// This is needed because fail2ban runs on host, not in container
func runHostCommand(name string, args ...string) (string, error) {
	// First try direct execution (works if binary is mounted or we're on host)
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	if err == nil {
		return string(out), nil
	}
	
	// If direct execution fails, try nsenter to run in host namespace
	// nsenter -t 1 -m -u -i -n -- command args
	nsenterArgs := []string{"-t", "1", "-m", "-u", "-i", "-n", "--", name}
	nsenterArgs = append(nsenterArgs, args...)
	cmd = exec.Command("nsenter", nsenterArgs...)
	out, err = cmd.Output()
	return string(out), err
}

// Fail2Ban Status
func (s *Server) handleFail2BanStatus(w http.ResponseWriter, r *http.Request) {
	result := map[string]interface{}{
		"installed": false,
		"running":   false,
		"jails":     []map[string]interface{}{},
	}
	
	// Check if fail2ban is installed (try host command)
	_, err := execHostCommand("fail2ban-client", "--version")
	if err != nil {
		result["error"] = "fail2ban not installed on host"
		jsonResponse(w, http.StatusOK, result)
		return
	}
	result["installed"] = true
	
	// Check if running
	statusOut, err := execHostCommand("fail2ban-client", "status")
	if err != nil {
		result["error"] = "fail2ban service not responding"
		jsonResponse(w, http.StatusOK, result)
		return
	}
	result["running"] = true
	
	// Parse jails
	jails := []string{}
	for _, line := range strings.Split(statusOut, "\n") {
		if strings.Contains(line, "Jail list:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				jailList := strings.TrimSpace(parts[1])
				for _, j := range strings.Split(jailList, ",") {
					j = strings.TrimSpace(j)
					if j != "" {
						jails = append(jails, j)
					}
				}
			}
		}
	}
	
	// Get details for each jail
	jailDetails := []map[string]interface{}{}
	for _, jail := range jails {
		jailInfo := map[string]interface{}{
			"name": jail,
		}
		
		jailStatus, err := execHostCommand("fail2ban-client", "status", jail)
		if err == nil {
			// Parse banned IPs and stats - handle different fail2ban output formats
			for _, line := range strings.Split(jailStatus, "\n") {
				line = strings.TrimSpace(line)
				// Remove tree characters like |- and `-
				line = strings.TrimPrefix(line, "|- ")
				line = strings.TrimPrefix(line, "|  |- ")
				line = strings.TrimPrefix(line, "|  `- ")
				line = strings.TrimPrefix(line, "`- ")
				
				if strings.HasPrefix(line, "Currently banned:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						var count int
						fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &count)
						jailInfo["banned_count"] = count
					}
				}
				if strings.HasPrefix(line, "Total banned:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						var count int
						fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &count)
						jailInfo["total_banned"] = count
					}
				}
				if strings.HasPrefix(line, "Banned IP list:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						ips := strings.TrimSpace(parts[1])
						if ips != "" {
							jailInfo["banned_ips"] = strings.Fields(ips)
						} else {
							jailInfo["banned_ips"] = []string{}
						}
					}
				}
				if strings.HasPrefix(line, "Currently failed:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						var count int
						fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &count)
						jailInfo["failed_count"] = count
					}
				}
				if strings.HasPrefix(line, "Total failed:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						var count int
						fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &count)
						jailInfo["total_failed"] = count
					}
				}
			}
		}
		jailDetails = append(jailDetails, jailInfo)
	}
	result["jails"] = jailDetails
	
	jsonResponse(w, http.StatusOK, result)
}

// Fail2Ban Logs
func (s *Server) handleFail2BanLogs(w http.ResponseWriter, r *http.Request) {
	// Get last N lines from fail2ban log
	lines := r.URL.Query().Get("lines")
	if lines == "" {
		lines = "100"
	}
	
	logPath := "/var/log/fail2ban.log"
	
	// Check if log exists
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"logs":  []string{},
			"error": "fail2ban log not found",
		})
		return
	}
	
	// Use tail to get last N lines
	out, err := execCommand("tail", "-n", lines, logPath)
	if err != nil {
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"logs":  []string{},
			"error": err.Error(),
		})
		return
	}
	
	logLines := strings.Split(strings.TrimSpace(out), "\n")
	
	// Parse logs into structured format
	parsedLogs := []map[string]string{}
	for _, line := range logLines {
		if line == "" {
			continue
		}
		
		logEntry := map[string]string{
			"raw": line,
		}
		
		// Try to parse timestamp and action
		// Format: 2024-01-15 10:30:45,123 fail2ban.actions [12345]: NOTICE [sshd] Ban 192.168.1.100
		parts := strings.SplitN(line, " fail2ban.", 2)
		if len(parts) >= 1 {
			logEntry["timestamp"] = strings.TrimSpace(parts[0])
		}
		
		if action := fail2banLogAction(line); action != "" {
			logEntry["action"] = action
		}
		
		parsedLogs = append(parsedLogs, logEntry)
	}
	
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"logs":  parsedLogs,
		"count": len(parsedLogs),
	})
}

// Fail2Ban Unban IP
func (s *Server) handleFail2BanUnban(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Jail string `json:"jail"`
		IP   string `json:"ip"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	
	if req.Jail == "" || req.IP == "" {
		errorResponse(w, http.StatusBadRequest, "jail and ip are required")
		return
	}
	
	// Validate IP format
	if net.ParseIP(req.IP) == nil {
		errorResponse(w, http.StatusBadRequest, "invalid IP address")
		return
	}
	
	// Execute unban
	_, err := execHostCommand("fail2ban-client", "set", req.Jail, "unbanip", req.IP)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to unban IP: "+err.Error())
		return
	}
	
	jsonResponse(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("IP %s unbanned from jail %s", req.IP, req.Jail),
	})
}

// Stats Overview - All networks combined
func (s *Server) handleStatsOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	// Get all networks
	networks, err := s.store.ListNetworks(ctx)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to list networks")
		return
	}
	
	totalNodes := 0
	onlineNodes := 0
	offlineNodes := 0
	pendingNodes := 0
	expiredNodes := 0
	totalRx := int64(0)
	totalTx := int64(0)
	
	networkStats := []map[string]interface{}{}
	
	for _, network := range networks {
		nodes, err := s.store.ListNodes(ctx, network.ID)
		if err != nil {
			continue
		}
		
		// Get WireGuard peers for real-time status
		var peers map[string]wireguard.PeerStatus
		mgr := s.getManager(network.ID)
		if mgr != nil {
			peers, _ = mgr.GetPeers()
		}
		
		netOnline := 0
		netOffline := 0
		netPending := 0
		netExpired := 0
		netRx := int64(0)
		netTx := int64(0)
		
		for _, node := range nodes {
			s.enrichNode(node, peers)
			
			switch node.Status {
			case models.NodeStatusOnline:
				netOnline++
				onlineNodes++
			case models.NodeStatusOffline:
				netOffline++
				offlineNodes++
			case models.NodeStatusPending:
				netPending++
				pendingNodes++
			case models.NodeStatusExpired:
				netExpired++
				expiredNodes++
			}
			
			netRx += node.TransferRx
			netTx += node.TransferTx
		}
		
		totalNodes += len(nodes)
		totalRx += netRx
		totalTx += netTx
		
		networkStats = append(networkStats, map[string]interface{}{
			"id":            network.ID,
			"name":          network.Name,
			"cidr":          network.CIDR,
			"interface":     network.InterfaceName,
			"total_nodes":   len(nodes),
			"online_nodes":  netOnline,
			"offline_nodes": netOffline,
			"pending_nodes": netPending,
			"expired_nodes": netExpired,
			"transfer_rx":   netRx,
			"transfer_tx":   netTx,
		})
	}
	
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"total_networks": len(networks),
		"total_nodes":    totalNodes,
		"online_nodes":   onlineNodes,
		"offline_nodes":  offlineNodes,
		"pending_nodes":  pendingNodes,
		"expired_nodes":  expiredNodes,
		"total_rx":       totalRx,
		"total_tx":       totalTx,
		"networks":       networkStats,
	})
}

// Debug WireGuard - shows interface status and registered peers
func (s *Server) handleDebugWireGuard(w http.ResponseWriter, r *http.Request) {
	networkID := mux.Vars(r)["networkId"]
	
	result := map[string]interface{}{
		"network_id": networkID,
	}
	
	// Get network info
	network, err := s.store.GetNetwork(r.Context(), networkID)
	if err != nil || network == nil {
		result["error"] = "network not found"
		jsonResponse(w, http.StatusNotFound, result)
		return
	}
	
	result["network_name"] = network.Name
	result["interface_name"] = network.InterfaceName
	result["server_public_key"] = network.ServerPublicKey
	result["server_endpoint"] = network.ServerEndpoint
	
	// Check manager
	s.managersMu.RLock()
	mgr := s.managers[networkID]
	s.managersMu.RUnlock()
	
	result["manager_registered"] = mgr != nil
	
	// Get peers from WireGuard
	if mgr != nil {
		peers, err := mgr.GetPeers()
		if err != nil {
			result["wg_error"] = err.Error()
		} else {
			result["wg_peers_count"] = len(peers)
			peerList := []map[string]interface{}{}
			for pubKey, status := range peers {
				peerList = append(peerList, map[string]interface{}{
					"public_key":  pubKey,
					"endpoint":    status.Endpoint,
					"allowed_ips": status.AllowedIPs,
					"transfer_rx": status.TransferRx,
					"transfer_tx": status.TransferTx,
				})
			}
			result["wg_peers"] = peerList
		}
	}
	
	// Get DB nodes for comparison
	nodes, err := s.store.ListNodes(r.Context(), networkID)
	if err == nil {
		result["db_nodes_count"] = len(nodes)
		nodeList := []map[string]interface{}{}
		for _, n := range nodes {
			nodeList = append(nodeList, map[string]interface{}{
				"id":         n.ID,
				"name":       n.Name,
				"public_key": n.PublicKey,
				"virtual_ip": n.VirtualIP.String(),
			})
		}
		result["db_nodes"] = nodeList
	}
	
	jsonResponse(w, http.StatusOK, result)
}

// handleSyncPeers syncs all DB nodes to WireGuard interface
func (s *Server) handleSyncPeers(w http.ResponseWriter, r *http.Request) {
	networkID := mux.Vars(r)["networkId"]
	
	// Get manager
	mgr := s.getManager(networkID)
	if mgr == nil {
		errorResponse(w, http.StatusInternalServerError, "WireGuard manager not available for this network")
		return
	}
	
	// Get all nodes from DB
	nodes, err := s.store.ListNodes(r.Context(), networkID)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to list nodes: "+err.Error())
		return
	}
	
	// Get current WireGuard peers
	currentPeers, err := mgr.GetPeers()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to get WireGuard peers: "+err.Error())
		return
	}
	
	// Expired or disabled nodes are not re-added.
	added, errs := restorePeers(mgr, nodes, currentPeers, time.Now())

	s.triggerReconcile()
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"added":   added,
		"skipped": len(nodes) - added - len(errs),
		"errors":  errs,
		"total":   len(nodes),
	})
}

// Middleware

// AuthMiddleware validates authentication
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
		
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		// Skip auth for health check and login
		if r.URL.Path == "/health" ||
		   strings.HasSuffix(r.URL.Path, "/login") {
			next.ServeHTTP(w, r)
			return
		}
		
		auth := r.Header.Get("Authorization")
		if auth == "" {
			errorResponse(w, http.StatusUnauthorized, "missing authorization header")
			return
		}
		
		if !strings.HasPrefix(auth, "Bearer ") {
			errorResponse(w, http.StatusUnauthorized, "invalid authorization header")
			return
		}
		
		token := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(adminToken)) != 1 {
			errorResponse(w, http.StatusUnauthorized, "invalid token")
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

// APIKeyMiddleware validates the X-API-Key header
func APIKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip if no key is configured (dev mode)
		if apiKey == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Add CORS headers for OPTIONS
		if r.Method == "OPTIONS" {
			// Headers are handled in AuthMiddleware or should be here too if this runs first
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
			w.WriteHeader(http.StatusOK)
			return
		}

		// Public paths that don't need API Key
		if r.URL.Path == "/health" ||
		   strings.HasSuffix(r.URL.Path, "/login") {
			next.ServeHTTP(w, r)
			return
		}

		clientKey := r.Header.Get("X-API-Key")
		if subtle.ConstantTimeCompare([]byte(clientKey), []byte(apiKey)) != 1 {
			errorResponse(w, http.StatusUnauthorized, "invalid or missing api key")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Fail2Ban Manual Ban - Ban an IP address manually
func (s *Server) handleFail2BanManualBan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Jail      string `json:"jail"`
		IP        string `json:"ip"`
		Permanent bool   `json:"permanent"` // If true, add to iptables directly for permanent ban
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	
	if req.Jail == "" || req.IP == "" {
		errorResponse(w, http.StatusBadRequest, "jail and ip are required")
		return
	}
	
	// Validate IP format
	if net.ParseIP(req.IP) == nil {
		errorResponse(w, http.StatusBadRequest, "invalid IP address")
		return
	}
	
	if req.Permanent {
		if s.engineEnforces() {
			s.handleFail2BanPermanentBanNft(w, r, req.IP)
			return
		}
		// Add permanent ban via iptables
		_, err := execHostCommand("iptables", "-I", "INPUT", "-s", req.IP, "-j", "DROP")
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "failed to add permanent ban: "+err.Error())
			return
		}
		// Save iptables rules
		execHostCommand("netfilter-persistent", "save")
		
		jsonResponse(w, http.StatusOK, map[string]string{
			"status":  "success",
			"message": fmt.Sprintf("IP %s permanently banned via iptables", req.IP),
			"type":    "permanent",
		})
		return
	}
	
	// Regular fail2ban ban
	_, err := execHostCommand("fail2ban-client", "set", req.Jail, "banip", req.IP)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to ban IP: "+err.Error())
		return
	}
	
	jsonResponse(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("IP %s banned in jail %s", req.IP, req.Jail),
		"type":    "temporary",
	})
}

// Fail2Ban Get Jail Settings - Get current jail configuration
func (s *Server) handleFail2BanGetJailSettings(w http.ResponseWriter, r *http.Request) {
	jail := r.URL.Query().Get("jail")
	if jail == "" {
		jail = "sshd"
	}
	
	settings := map[string]interface{}{
		"jail": jail,
	}
	
	// Get bantime
	if out, err := execHostCommand("fail2ban-client", "get", jail, "bantime"); err == nil {
		settings["bantime"] = strings.TrimSpace(out)
	}
	
	// Get maxretry
	if out, err := execHostCommand("fail2ban-client", "get", jail, "maxretry"); err == nil {
		settings["maxretry"] = strings.TrimSpace(out)
	}
	
	// Get findtime
	if out, err := execHostCommand("fail2ban-client", "get", jail, "findtime"); err == nil {
		settings["findtime"] = strings.TrimSpace(out)
	}
	
	// Get ignoreip (whitelist)
	if out, err := execHostCommand("fail2ban-client", "get", jail, "ignoreip"); err == nil {
		settings["ignoreip"] = strings.TrimSpace(out)
	}
	
	jsonResponse(w, http.StatusOK, settings)
}

// Fail2Ban Update Jail Settings - Update jail configuration
func (s *Server) handleFail2BanUpdateJailSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Jail     string `json:"jail"`
		Bantime  string `json:"bantime"`   // e.g., "3600" (1 hour), "-1" (permanent)
		Maxretry string `json:"maxretry"`  // e.g., "3"
		Findtime string `json:"findtime"`  // e.g., "600" (10 minutes)
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	
	if req.Jail == "" {
		req.Jail = "sshd"
	}
	
	updated := []string{}
	errors := []string{}
	
	// Update bantime
	if req.Bantime != "" {
		if _, err := execHostCommand("fail2ban-client", "set", req.Jail, "bantime", req.Bantime); err != nil {
			errors = append(errors, "bantime: "+err.Error())
		} else {
			updated = append(updated, "bantime")
		}
	}
	
	// Update maxretry
	if req.Maxretry != "" {
		if _, err := execHostCommand("fail2ban-client", "set", req.Jail, "maxretry", req.Maxretry); err != nil {
			errors = append(errors, "maxretry: "+err.Error())
		} else {
			updated = append(updated, "maxretry")
		}
	}
	
	// Update findtime
	if req.Findtime != "" {
		if _, err := execHostCommand("fail2ban-client", "set", req.Jail, "findtime", req.Findtime); err != nil {
			errors = append(errors, "findtime: "+err.Error())
		} else {
			updated = append(updated, "findtime")
		}
	}
	
	if len(errors) > 0 {
		jsonResponse(w, http.StatusPartialContent, map[string]interface{}{
			"status":  "partial",
			"updated": updated,
			"errors":  errors,
		})
		return
	}
	
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"updated": updated,
	})
}

// Fail2Ban Get Whitelist - Get whitelisted IPs
func (s *Server) handleFail2BanGetWhitelist(w http.ResponseWriter, r *http.Request) {
	jail := r.URL.Query().Get("jail")
	if jail == "" {
		jail = "sshd"
	}
	
	out, err := execHostCommand("fail2ban-client", "get", jail, "ignoreip")
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to get whitelist: "+err.Error())
		return
	}
	
	ips := parseIgnoreIPList(out)
	
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"jail":      jail,
		"whitelist": ips,
	})
}

// Fail2Ban Update Whitelist - Add or remove IPs from whitelist
func (s *Server) handleFail2BanUpdateWhitelist(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Jail   string `json:"jail"`
		Action string `json:"action"` // "add" or "remove"
		IP     string `json:"ip"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	
	if req.Jail == "" {
		req.Jail = "sshd"
	}
	
	if req.Action == "" || req.IP == "" {
		errorResponse(w, http.StatusBadRequest, "action and ip are required")
		return
	}
	
	// Validate IP/CIDR format
	if net.ParseIP(req.IP) == nil {
		// Try parsing as CIDR
		if _, _, err := net.ParseCIDR(req.IP); err != nil {
			errorResponse(w, http.StatusBadRequest, "invalid IP address or CIDR")
			return
		}
	}
	
	var cmd string
	switch req.Action {
	case "add":
		cmd = "addignoreip"
	case "remove":
		cmd = "delignoreip"
	default:
		errorResponse(w, http.StatusBadRequest, "action must be 'add' or 'remove'")
		return
	}
	
	_, err := execHostCommand("fail2ban-client", "set", req.Jail, cmd, req.IP)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to update whitelist: "+err.Error())
		return
	}
	
	jsonResponse(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("IP %s %sed in jail %s whitelist", req.IP, req.Action, req.Jail),
	})
}

// Fail2Ban Get Permanent Bans - Get list of permanently banned IPs via iptables
func (s *Server) handleFail2BanGetPermanentBans(w http.ResponseWriter, r *http.Request) {
	if s.engineEnforces() {
		s.handleFail2BanGetPermanentBansNft(w, r)
		return
	}

	// Get iptables rules that DROP traffic
	out, err := execHostCommand("iptables", "-L", "INPUT", "-n", "--line-numbers")
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to get iptables rules: "+err.Error())
		return
	}
	
	bannedIPs := []map[string]interface{}{}
	lines := strings.Split(out, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Look for DROP rules with source IP
		// Format: "1    DROP       all  --  192.168.1.100    0.0.0.0/0"
		if strings.Contains(line, "DROP") && !strings.HasPrefix(line, "Chain") && !strings.HasPrefix(line, "num") {
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				lineNum := fields[0]
				sourceIP := fields[4]
				// Skip 0.0.0.0/0 (not a specific ban)
				if sourceIP != "0.0.0.0/0" && sourceIP != "anywhere" {
					bannedIPs = append(bannedIPs, map[string]interface{}{
						"line_number": lineNum,
						"ip":          sourceIP,
						"target":      "DROP",
						"protocol":    fields[2],
					})
				}
			}
		}
	}
	
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"permanent_bans": bannedIPs,
		"count":          len(bannedIPs),
	})
}

// Fail2Ban Remove Permanent Ban - Remove a permanently banned IP from iptables
func (s *Server) handleFail2BanRemovePermanentBan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP string `json:"ip"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	
	if req.IP == "" {
		errorResponse(w, http.StatusBadRequest, "ip is required")
		return
	}
	
	// Validate IP format
	if net.ParseIP(req.IP) == nil {
		// Try parsing as CIDR
		if _, _, err := net.ParseCIDR(req.IP); err != nil {
			errorResponse(w, http.StatusBadRequest, "invalid IP address")
			return
		}
	}
	
	if s.engineEnforces() {
		s.handleFail2BanRemovePermanentBanNft(w, r, req.IP)
		return
	}

	// Remove the DROP rule for this IP
	_, err := execHostCommand("iptables", "-D", "INPUT", "-s", req.IP, "-j", "DROP")
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to remove permanent ban: "+err.Error())
		return
	}
	
	// Save iptables rules
	execHostCommand("netfilter-persistent", "save")
	
	jsonResponse(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Permanent ban removed for IP %s", req.IP),
	})
}

// Fail2Ban Jail Control - Start/Stop a jail
func (s *Server) handleFail2BanJailControl(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Jail   string `json:"jail"`
		Action string `json:"action"` // "start" or "stop"
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	
	if req.Jail == "" || req.Action == "" {
		errorResponse(w, http.StatusBadRequest, "jail and action are required")
		return
	}
	
	var cmd string
	switch req.Action {
	case "start":
		cmd = "start"
	case "stop":
		cmd = "stop"
	default:
		errorResponse(w, http.StatusBadRequest, "action must be 'start' or 'stop'")
		return
	}
	
	_, err := execHostCommand("fail2ban-client", cmd, req.Jail)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to %s jail: %s", cmd, err.Error()))
		return
	}
	
	jsonResponse(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("Jail %s %sed successfully", req.Jail, cmd),
	})
}

// Fail2Ban Reload - Reload fail2ban without losing bans
func (s *Server) handleFail2BanReload(w http.ResponseWriter, r *http.Request) {
	jail := r.URL.Query().Get("jail")
	
	var out string
	var err error
	
	if jail != "" {
		// Reload specific jail
		out, err = execHostCommand("fail2ban-client", "reload", jail)
	} else {
		// Reload all
		out, err = execHostCommand("fail2ban-client", "reload")
	}
	
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to reload: "+err.Error())
		return
	}
	
	jsonResponse(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": "Fail2Ban reloaded successfully",
		"output":  strings.TrimSpace(out),
	})
}

// Fail2Ban Ping - Check if fail2ban is responding
func (s *Server) handleFail2BanPing(w http.ResponseWriter, r *http.Request) {
	out, err := execHostCommand("fail2ban-client", "ping")
	if err != nil {
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"alive":   false,
			"error":   err.Error(),
			"message": "Fail2Ban is not responding",
		})
		return
	}
	
	// Expected output: "Server replied: pong"
	alive := strings.Contains(out, "pong")
	
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"alive":   alive,
		"message": strings.TrimSpace(out),
	})
}

// Fail2Ban History - Get ban history from logs
func (s *Server) handleFail2BanHistory(w http.ResponseWriter, r *http.Request) {
	jail := r.URL.Query().Get("jail")
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	
	// The log is read directly; nothing from the request reaches a shell.
	history := []map[string]string{} // no log yet: empty history, as before
	if f, err := openFail2BanLog(); err == nil {
		history = parseFail2BanHistory(f, jail, limit)
		f.Close()
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"history": history,
		"count":   len(history),
		"jail":    jail,
	})
}

// hubAddress returns the hub's interface address for a network: the first
// host of cidr, with cidr's own prefix length (B21: not a fixed /24).
func hubAddress(cidr string) (string, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", err
	}
	p = p.Masked()
	return netip.PrefixFrom(p.Addr().Next(), p.Bits()).String(), nil
}
