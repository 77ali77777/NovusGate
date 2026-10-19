package rest

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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
	"github.com/novusgate/novusgate/internal/controlplane/backup"
	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/controlplane/hostadmin"
	"github.com/novusgate/novusgate/internal/controlplane/notify"
	"github.com/novusgate/novusgate/internal/controlplane/reconciler"
	"github.com/novusgate/novusgate/internal/controlplane/store"
	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/shared/version"
	"github.com/novusgate/novusgate/internal/wireguard"
	"golang.org/x/crypto/bcrypt"
)

// apiKey is the optional request-level key checked by APIKeyMiddleware.
var apiKey = getEnvOrDefault("novusgate_API_KEY", "")

func getEnvOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
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
	managers     map[string]*wireguard.Manager
	managersMu   sync.RWMutex
	peerActivity map[string]*PeerActivity
	firewall     *firewall.Engine       // nil, or engine for FIREWALL_ENGINE=shadow|nft
	reconciler   *reconciler.Reconciler // nil when WG_RECONCILER=off
	backups      *backup.Service        // nil: the backup endpoints answer 503
	notifier     *notify.Notifier       // nil: no notifications (P8)
	notifySender notify.Sender          // sends the test message
	host         hostadmin.Runner       // host commands (P10a); nil: nsenter
	activityMu   sync.RWMutex
	ifaceErrs    sync.Map // network ID -> last reason its interface did not come up
	ifaceRetry   sync.Map // network ID -> retryState of the interface check
	ifaceLocks   sync.Map // interface name -> *sync.Mutex (lockInterface)
	// vpnSync serializes NOVUSGATE-VPN rebuilds (iptables mode): two
	// interleaved flush-and-append runs would leave rules behind the DROP.
	vpnSync sync.Mutex
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
	go func() {
		s.loadNetworks()
		// Then bring back any interface that goes missing (reboot of a unit,
		// a failed start, an interface removed by hand).
		s.KeepInterfaces(context.Background())
	}()
	return s
}

// loadNetworks initializes managers for existing networks and imports/syncs peers
// loadNetworksDelay gives the database a moment at startup (replaced in tests).
var loadNetworksDelay = 2 * time.Second

func (s *Server) loadNetworks() {
	// Give DB a moment to come up
	time.Sleep(loadNetworksDelay)

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
			s.noteInterfaceError(network, err)
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

		// SYNC: Import existing peers from WireGuard into DB. This runs
		// before bringUp: handing an interface brought up outside systemd to
		// its unit restarts it, which drops its runtime peers.
		peers, err := mgr.GetPeers()
		dbNodes, listErr := s.store.ListNodes(ctx, network.ID)
		if listErr != nil {
			slog.Error(fmt.Sprintf("Failed to list DB nodes: %v", listErr))
		}
		if err == nil && listErr == nil && len(peers) > 0 {
			slog.Info(fmt.Sprintf("Syncing %d peers from %s to database...", len(peers), network.InterfaceName))

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

		// The interface runs as its systemd unit on the host; bringUp puts
		// the stored peers back (the unit starts without them) and keeps the
		// reason when it cannot (shown with the network, retried by
		// KeepInterfaces).
		unlock := s.lockInterface(network.InterfaceName)
		err = s.bringUp(ctx, network, false)
		unlock()
		if err == nil {
			slog.Info(fmt.Sprintf("Network %s (%s) is UP on port %d", network.Name, network.InterfaceName, port))
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

// Router returns the HTTP handler the server listens with. The request log
// wraps the mux itself, so its path-cleaning redirects are logged too, and
// HEAD requests are answered as GET without a body.
func (s *Server) Router() http.Handler {
	return LoggingMiddleware(headAsGet(s.router))
}

func (s *Server) setupRoutes() {
	// Route middleware: panic recovery, then auth. The request log wraps the
	// whole mux in Router (it records the 500 that RecoverMiddleware writes).
	s.router.Use(RecoverMiddleware, APIKeyMiddleware, s.authMiddleware, s.roleMiddleware, s.auditMiddleware, s.firewallActorMiddleware, s.firewallChangeMiddleware)

	api := s.router.PathPrefix("/api/v1").Subrouter()

	// Networks
	api.HandleFunc("/networks", s.handleListNetworks).Methods("GET")
	api.HandleFunc("/networks", s.handleCreateNetwork).Methods("POST")
	api.HandleFunc("/networks/{id}", s.handleGetNetwork).Methods("GET")
	api.HandleFunc("/networks/{id}", s.handleDeleteNetwork).Methods("DELETE")
	api.HandleFunc("/networks/{id}/dns", s.handleSetNetworkDNS).Methods("PUT")
	api.HandleFunc("/networks/{id}/restart", s.handleRestartInterface).Methods("POST")

	// Nodes
	api.HandleFunc("/networks/{networkId}/nodes", s.handleListNodes).Methods("GET")
	api.HandleFunc("/nodes/{id}", s.handleGetNode).Methods("GET")
	api.HandleFunc("/nodes/{id}", s.handleUpdateNode).Methods("PUT", "PATCH")
	api.HandleFunc("/nodes/{id}", s.handleDeleteNode).Methods("DELETE")
	api.HandleFunc("/nodes/{id}/rotate-key", s.handleRotateNodeKey).Methods("POST")
	api.HandleFunc("/nodes/{id}/checkin", s.handleNodeCheckIn).Methods("POST")

	// WireGuard Config & Utils
	api.HandleFunc("/nodes/{id}/config", s.handleDownloadConfig).Methods("GET")
	api.HandleFunc("/nodes/{id}/qrcode", s.handleGetQRCode).Methods("GET")
	api.HandleFunc("/nodes/{id}/install.sh", s.handleNodeInstallScript).Methods("GET")
	api.HandleFunc("/nodes/{id}/traffic", s.handleNodeTraffic).Methods("GET")
	s.registerBackupRoutes(api)
	s.registerNotificationRoutes(api)
	s.registerAuditRoutes(api)
	s.registerGroupRoutes(api)
	s.registerLimitRoutes(api)
	s.registerServerAdminRoutes(api)
	s.registerRoleRoutes(api)
	s.registerTunnelRoutes(api)
	api.HandleFunc("/networks/{networkId}/servers", s.handleCreateServerWithConfig).Methods("POST")

	// Health check
	s.router.HandleFunc("/health", s.handleHealth).Methods("GET")

	// Debug endpoint - shows WireGuard interface status
	api.HandleFunc("/debug/wireguard/{networkId}", s.handleDebugWireGuard).Methods("GET")

	// Sync endpoint - syncs DB peers to WireGuard interface
	api.HandleFunc("/networks/{networkId}/sync", s.handleSyncPeers).Methods("POST")

	// Auth
	s.router.HandleFunc("/api/v1/auth/login", s.handleLogin).Methods("POST")
	api.HandleFunc("/auth/password", s.handleUpdatePassword).Methods("PUT")
	api.HandleFunc("/auth/logout", s.handleLogout).Methods("POST")

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
	api.HandleFunc("/openapi.json", s.handleOpenAPI).Methods("GET")

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
	api.HandleFunc("/firewall/policy-matrix", s.handleFirewallPolicyMatrix).Methods("GET")
	api.HandleFunc("/firewall/access-check", s.handleAccessCheck).Methods("GET")
	s.setupFirewallV2Routes(api)

	// Helper for SPA (Single Page Application) serving
	// Unmatched /api requests answer in JSON (404/405), never with the SPA.
	s.router.Path("/api").HandlerFunc(s.handleAPIFallback).Name("api-fallback")
	s.router.PathPrefix("/api/").HandlerFunc(s.handleAPIFallback).Name("api-fallback")
	s.router.PathPrefix("/").HandlerFunc(s.handleSPA).Name("spa")
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

// apiError is the unified error body: {"error":{"code","message"}}. The code
// is stable snake_case for clients to act on; the message is for people.
type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// errorWithCode writes an error with a specific code.
func errorWithCode(w http.ResponseWriter, status int, code, message string) {
	jsonResponse(w, status, map[string]apiError{"error": {Code: code, Message: message}})
}

// errorResponse writes an error whose code follows the HTTP status.
func errorResponse(w http.ResponseWriter, status int, message string) {
	errorWithCode(w, status, defaultErrorCode(status), message)
}

// defaultErrorCode names an HTTP status as a stable error code.
func defaultErrorCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "bad_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusMethodNotAllowed:
		return "method_not_allowed"
	case http.StatusConflict:
		return "conflict"
	case http.StatusGone:
		return "gone"
	case http.StatusInternalServerError:
		return "internal_error"
	case http.StatusBadGateway:
		return "bad_gateway"
	case http.StatusServiceUnavailable:
		return "unavailable"
	}
	return "error"
}

// Login handler
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	key, now := limiterKey(clientIP(r)), authNow()
	if wait, ok := loginLimit.begin(key, now); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		errorWithCode(w, http.StatusTooManyRequests, "too_many_attempts", "too many failed logins, try again later")
		return
	}

	var req LoginRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}

	noteLoginUsername(r, req.Username)
	// Validate credentials against DB
	user, err := s.store.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to check user")
		return
	}

	if user == nil {
		comparePassword(dummyPasswordHash, []byte(req.Password)) // same cost as a wrong password
		errorWithCode(w, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")
		return
	}

	if err := comparePassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		errorWithCode(w, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")
		return
	}

	loginLimit.succeed(key)
	s.store.DeleteExpiredSessions(r.Context(), authNow()) // housekeeping; a failure only leaves old rows
	token, err := newSessionToken()
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to create session")
		return
	}
	if err := s.store.CreateSession(r.Context(), user.ID, hashToken(token), authNow(), sessionTTL); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to create session")
		return
	}
	jsonResponse(w, http.StatusOK, LoginResponse{Token: token, Username: user.Username, Role: user.Role})
}

// Update Password handler
func (s *Server) handleUpdatePassword(w http.ResponseWriter, r *http.Request) {
	var req UpdatePasswordRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}

	// The password changed is always the session user's; a body username
	// is accepted only when it names that user.
	current, hash := sessionFrom(r)
	if current == nil {
		errorWithCode(w, http.StatusUnauthorized, "invalid_token", "invalid token")
		return
	}
	if req.Username != "" && req.Username != current.Username {
		errorWithCode(w, http.StatusForbidden, "forbidden", "you can only change your own password")
		return
	}
	user, err := s.store.GetUserByUsername(r.Context(), current.Username)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to check user")
		return
	}
	if user == nil { // deleted after this request was authenticated
		errorWithCode(w, http.StatusUnauthorized, "invalid_token", "invalid token")
		return
	}

	if err := comparePassword([]byte(user.PasswordHash), []byte(req.OldPassword)); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_old_password", "invalid old password") // 400: a 401 logs the panel out (B15)
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	// One transaction: the new password and the end of the user's other
	// logins (the session that changed it stays) happen together or not at all.
	if err := s.store.ChangePassword(r.Context(), user.ID, string(hashedPassword), hash); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to update password")
		return
	}

	jsonResponse(w, http.StatusOK, StatusResponse{Status: "success"})
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
	var req CreateUserRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}

	if req.Username == "" || req.Password == "" {
		errorResponse(w, http.StatusBadRequest, "username and password required")
		return
	}
	if req.Role == "" {
		req.Role = "admin" // API clients from before roles
	}
	if !store.ValidRole(req.Role) {
		errorResponse(w, http.StatusBadRequest, "role must be admin, operator or viewer")
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
		Role:         req.Role,
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
	// The last admin cannot be deleted (409 last_admin).
	if err := s.store.DeleteUserKeepingAdmin(r.Context(), id); err != nil {
		userRoleError(w, err)
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
	for _, n := range networks {
		s.withInterfaceStatus(r, n)
	}
	jsonResponse(w, http.StatusOK, networks)
}

func (s *Server) handleCreateNetwork(w http.ResponseWriter, r *http.Request) {
	var network models.Network
	if err := json.NewDecoder(r.Body).Decode(&network); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}

	// Validate CIDR format
	_, newNet, err := net.ParseCIDR(network.CIDR)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid CIDR format: "+err.Error())
		return
	}
	if network.ClientDNS, err = normalizeClientDNS(network.ClientDNS); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_dns", err.Error())
		return
	}
	if network.TunnelMode == "" {
		network.TunnelMode = models.TunnelSplit
	}
	if !models.ValidTunnelMode(network.TunnelMode) {
		errorWithCode(w, http.StatusBadRequest, "invalid_tunnel_mode", `tunnel_mode must be "split" or "full"`)
		return
	}
	// A full network makes the hub its nodes' internet exit, like every
	// tunnel change (PUT .../tunnel): that needs an admin.
	if user, _ := sessionFrom(r); network.TunnelMode == models.TunnelFull && user != nil && roleRank[user.Role] < roleRank["admin"] {
		errorWithCode(w, http.StatusForbidden, "forbidden", "your role ("+user.Role+") cannot create a full-tunnel network; it needs admin")
		return
	}
	// The hub takes the first address; a /31 or /32 leaves no room for a peer.
	if ones, bits := newNet.Mask.Size(); bits-ones < 2 {
		errorWithCode(w, http.StatusBadRequest, "invalid_cidr", "CIDR "+network.CIDR+" is too small: a network needs room for the hub and at least one peer")
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
			errorWithCode(w, http.StatusConflict, "cidr_overlap", fmt.Sprintf(
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

	// 4. Save to DB (now with keys). The interface lock is held from here
	// until its config is written and its unit started, so the check cannot
	// try the half-made interface.
	unlock := s.lockInterface(network.InterfaceName)
	defer unlock()
	if err := s.store.CreateNetwork(r.Context(), &network); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to create network: "+err.Error())
		return
	}

	// 5. Initialize WireGuard Interface
	// The network is stored either way; when its interface does not come up
	// the response (and every later read) carries why, the panel offers a
	// restart, and KeepInterfaces retries.
	mgr := wireguard.NewManager(network.InterfaceName)
	if err := wgInit(mgr); err != nil {
		s.noteInterfaceError(&network, err)
	} else {
		// Create WireGuard config with the generated key
		// Calculate server IP (first usable IP in CIDR)
		serverAddr, addrErr := hubAddress(network.CIDR)
		if addrErr != nil {
			s.noteInterfaceError(&network, fmt.Errorf("invalid CIDR %s: %w", network.CIDR, addrErr))
		} else if err := wgCreateInterface(mgr, privateKey, serverAddr, port); err != nil {
			s.noteInterfaceError(&network, err)
		} else {
			s.setInterfaceError(network.ID, "")
			slog.Info(fmt.Sprintf("WireGuard interface %s created for network %s", network.InterfaceName, network.Name))
		}

		// Register manager
		s.managersMu.Lock()
		s.managers[network.ID] = mgr
		s.managersMu.Unlock()
	}

	s.reconcileFirewall(r.Context())
	s.triggerReconcile()
	s.withInterfaceStatus(r, &network)
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
	s.withInterfaceStatus(r, network)
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
		errorWithCode(w, http.StatusForbidden, "admin_network_protected", "cannot delete Admin Management Network")
		return
	}

	// Under the interface lock, the row goes first and the interface second
	// (like a node: its row first), so the check, which re-reads the network
	// under the same lock, cannot start the unit again.
	if network.InterfaceName != "" {
		unlock := s.lockInterface(network.InterfaceName)
		defer unlock()
	}
	if err := s.store.DeleteNetwork(r.Context(), id); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to delete network")
		return
	}
	if network.InterfaceName != "" {
		wgTeardown(network.InterfaceName)
		s.setInterfaceError(network.ID, "")
		s.ifaceRetry.Delete(network.ID)

		// Unregister manager
		s.managersMu.Lock()
		delete(s.managers, id)
		s.managersMu.Unlock()
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
	s.markOutdated(r.Context(), nodes...)

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
	s.markOutdated(r.Context(), node)

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

	var req UpdateNodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
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
			if err != nil {
				errorWithCode(w, http.StatusBadRequest, "invalid_expires_at", "expires_at must be an RFC 3339 time, e.g. 2026-10-14T12:00:00Z")
				return
			}
			node.ExpiresAt = &t
		}
	}

	// Update status if provided
	if req.Status != nil {
		switch st := models.NodeStatus(*req.Status); st {
		case models.NodeStatusPending, models.NodeStatusOnline, models.NodeStatusOffline, models.NodeStatusExpired:
			node.Status = st
		default:
			errorWithCode(w, http.StatusBadRequest, "invalid_status", "status must be pending, online, offline or expired")
			return
		}
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
		if pc := nodePeerControl(s, node.NetworkID); pc != nil {
			if add {
				slog.Info(fmt.Sprintf("Reactivating node %s, adding to WireGuard", node.Name))
				// Keep a live peer's gateway routes and never take another peer's /32.
				if err := ensurePeer(pc, node.PublicKey, node.VirtualIP.String()+"/32"); err != nil {
					slog.Error(fmt.Sprintf("Warning: failed to add reactivated peer to WireGuard: %v", err))
				}
			} else if err := pc.RemovePeer(node.PublicKey); err != nil {
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

	// Delete the row first, then the peer: a reconciler run in between would
	// otherwise re-add the peer of a node that is about to disappear.
	if err := s.store.DeleteNode(r.Context(), id); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to delete node")
		return
	}

	// Remove from WireGuard
	mgr := s.getManager(node.NetworkID)
	if mgr != nil && node.PublicKey != "" {
		if err := wgRemovePeer(mgr, node.PublicKey); err != nil {
			slog.Error(fmt.Sprintf("Warning: failed to remove peer from WireGuard: %v", err))
		}
	}
	s.reconcileFirewall(r.Context())
	s.triggerReconcile()
	jsonResponse(w, http.StatusOK, StatusResponse{Status: "deleted"})
}

func (s *Server) handleNodeCheckIn(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	// The body may come from a caller without a session; cap it before
	// decoding (a node's report is a few hundred bytes).
	r.Body = http.MaxBytesReader(w, r.Body, checkinBodyLimit)
	var req NodeCheckInRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}

	node, err := s.store.GetNode(r.Context(), id)
	if err != nil {
		node = nil // e.g. an id that is not a UUID: not found, as before
	}
	// A node enrolling with its install script's token: the token is used
	// only once the request is otherwise acceptable, so a rejected body does
	// not burn it. Without a session an unknown node is 401, not 404.
	enrollHash := ""
	if user, _ := sessionFrom(r); user == nil {
		// Checked here, used only after the node is stored, so a failed
		// update does not burn the token. The lookup runs for unknown
		// nodes too, so its timing does not reveal which IDs exist.
		enrollHash = hashToken(r.Header.Get(enrollmentHeader))
		ok, err := s.store.EnrollmentTokenValid(r.Context(), id, enrollHash, authNow())
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "failed to check enrollment token")
			return
		}
		if !ok || node == nil {
			errorWithCode(w, http.StatusUnauthorized, "invalid_enrollment_token", "invalid or expired enrollment token")
			return
		}
	}
	if node == nil {
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
			if strings.HasPrefix(k, "wireguard_") { // keys and WireGuard settings are not the node's to report
				continue
			}
			node.Labels[k] = v
		}
	}

	if err := s.store.UpdateNode(r.Context(), node); err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to update node info")
		return
	}
	if enrollHash != "" {
		// The node is stored: the token is used now. A concurrent checkin with
		// the same token may have used it first; this one was valid, too.
		if _, err := s.store.ConsumeEnrollmentToken(r.Context(), id, enrollHash, authNow()); err != nil {
			slog.Warn("enrollment token not marked used", "node", id, "error", err)
		}
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
// "degraded" and "checks" says why. It is public: everyone gets the status,
// only callers with a panel session or the API key get the checks. They
// report states only, never error texts.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	healthy := true
	resp := HealthResponse{Status: "healthy", Version: version.Version,
		Checks: &HealthChecks{Firewall: FirewallCheck{OK: true, Mode: string(firewall.ModeIptables)}}}

	if s.store.Ping(ctx) != nil {
		healthy = false
	} else {
		resp.Checks.Database.OK = true
		wg := &WireGuardCheck{OK: true, Interfaces: map[string]string{}}
		if names, err := s.store.ListInterfaceNames(ctx); err != nil {
			wg.OK = false
		} else {
			for _, name := range names {
				state := "up"
				if !interfaceUp(name) {
					state, wg.OK = "down", false
				}
				wg.Interfaces[name] = state
			}
		}
		healthy = healthy && wg.OK
		resp.Checks.WireGuard = wg
	}

	if s.firewall != nil {
		fw := &resp.Checks.Firewall
		fw.Mode = string(s.firewall.Mode)
		if s.firewall.Mode == firewall.ModeNft {
			ready := s.firewall.Ready()
			_, pending := s.firewall.PendingChange()
			fw.OK, fw.Ready, fw.Pending = ready, &ready, &pending
			healthy = healthy && ready
		}
	}
	if s.reconciler != nil {
		rep := s.reconciler.Status()
		rc := &ReconcilerCheck{OK: rep.OK(), Mode: string(s.reconciler.Mode)}
		if !rep.Time.IsZero() {
			last := rep.Time.UTC().Format(time.RFC3339)
			rc.LastRun = &last
			rc.Pending = len(rep.Pending) // shadow: adds and updates enforce would make
		}
		healthy = healthy && rep.OK()
		resp.Checks.Reconciler = rc
	}

	if !healthy {
		resp.Status = "degraded"
	}
	if !s.healthDetailsAllowed(r) {
		resp.Checks = nil
	}
	jsonResponse(w, http.StatusOK, resp)
}

// healthDetailsAllowed reports whether the caller may see the health checks:
// the configured API key or the bearer token of an unexpired panel session.
func (s *Server) healthDetailsAllowed(r *http.Request) bool {
	if apiKey != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-API-Key")), []byte(apiKey)) == 1 {
		return true
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return false
	}
	user, err := s.store.SessionUser(r.Context(), hashToken(token), authNow())
	return err == nil && user != nil
}

// System Info - CPU, RAM, Disk
func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	info := SystemInfoResponse{}

	// CPU Info
	cpuInfo, _ := os.ReadFile("/proc/cpuinfo")
	cpuCount := strings.Count(string(cpuInfo), "processor")
	info.CPUCores = cpuCount

	// CPU Model
	for _, line := range strings.Split(string(cpuInfo), "\n") {
		if strings.HasPrefix(line, "model name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				model := strings.TrimSpace(parts[1])
				info.CPUModel = &model
				break
			}
		}
	}

	// Load Average
	loadAvg, _ := os.ReadFile("/proc/loadavg")
	if len(loadAvg) > 0 {
		parts := strings.Fields(string(loadAvg))
		if len(parts) >= 3 {
			info.Load1m = &parts[0]
			info.Load5m = &parts[1]
			info.Load15m = &parts[2]
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
	info.MemoryTotal = memMap["MemTotal"]
	info.MemoryFree = memMap["MemFree"]
	info.MemoryAvailable = memMap["MemAvailable"]
	info.MemoryUsed = memMap["MemTotal"] - memMap["MemAvailable"]
	info.MemoryBuffers = memMap["Buffers"]
	info.MemoryCached = memMap["Cached"]

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
				info.DiskTotal = &total
				info.DiskUsed = &used
				info.DiskFree = &avail
			}
		}
	}

	// Uptime
	uptimeData, _ := os.ReadFile("/proc/uptime")
	if len(uptimeData) > 0 {
		var uptime float64
		fmt.Sscanf(string(uptimeData), "%f", &uptime)
		up := int64(uptime)
		info.UptimeSeconds = &up
	}

	// Hostname
	hostname, _ := os.Hostname()
	info.Hostname = hostname

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

// wgCreateInterface writes the network's wg-quick config and brings the
// interface up (SetupInterface ends with Up); replaced in tests.
var wgCreateInterface = func(m *wireguard.Manager, privateKey, address string, port int) error {
	return m.CreateServerConfigWithKey(privateKey, address, port)
}

// wgRemovePeer removes a peer from a live interface (replaced in tests).
var wgRemovePeer = func(m *wireguard.Manager, publicKey string) error { return m.RemovePeer(publicKey) }

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
	result := Fail2BanStatusResponse{Jails: []Fail2BanJail{}}

	// Check if fail2ban is installed (try host command)
	_, err := execHostCommand("fail2ban-client", "--version")
	if err != nil {
		result.Error = "fail2ban not installed on host"
		jsonResponse(w, http.StatusOK, result)
		return
	}
	result.Installed = true

	// Check if running
	statusOut, err := execHostCommand("fail2ban-client", "status")
	if err != nil {
		result.Error = "fail2ban service not responding"
		jsonResponse(w, http.StatusOK, result)
		return
	}
	result.Running = true

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
	jailDetails := []Fail2BanJail{}
	for _, jail := range jails {
		jailInfo := Fail2BanJail{Name: jail}

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
						jailInfo.BannedCount = &count
					}
				}
				if strings.HasPrefix(line, "Total banned:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						var count int
						fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &count)
						jailInfo.TotalBanned = &count
					}
				}
				if strings.HasPrefix(line, "Banned IP list:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						ips := strings.TrimSpace(parts[1])
						banned := []string{}
						if ips != "" {
							banned = strings.Fields(ips)
						}
						jailInfo.BannedIPs = &banned
					}
				}
				if strings.HasPrefix(line, "Currently failed:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						var count int
						fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &count)
						jailInfo.FailedCount = &count
					}
				}
				if strings.HasPrefix(line, "Total failed:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						var count int
						fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &count)
						jailInfo.TotalFailed = &count
					}
				}
			}
		}
		jailDetails = append(jailDetails, jailInfo)
	}
	result.Jails = jailDetails

	jsonResponse(w, http.StatusOK, result)
}

// Fail2Ban Logs
func (s *Server) handleFail2BanLogs(w http.ResponseWriter, r *http.Request) {
	// Get last N lines from fail2ban log
	lines := r.URL.Query().Get("lines")
	if lines == "" {
		lines = "100"
	}

	logPath := Fail2BanLogPath

	// Check if log exists
	if !fail2banLogExists(logPath) {
		jsonResponse(w, http.StatusOK, Fail2BanLogsResponse{Logs: []Fail2BanLogEntry{}, Error: "fail2ban log not found"})
		return
	}

	// Use tail to get last N lines
	out, err := execCommand("tail", "-n", lines, logPath)
	if err != nil {
		jsonResponse(w, http.StatusOK, Fail2BanLogsResponse{Logs: []Fail2BanLogEntry{}, Error: err.Error()})
		return
	}

	logLines := strings.Split(strings.TrimSpace(out), "\n")

	// Parse logs into structured format
	parsedLogs := []Fail2BanLogEntry{}
	for _, line := range logLines {
		if line == "" {
			continue
		}

		logEntry := Fail2BanLogEntry{Raw: line}

		// Try to parse timestamp and action
		// Format: 2024-01-15 10:30:45,123 fail2ban.actions [12345]: NOTICE [sshd] Ban 192.168.1.100
		parts := strings.SplitN(line, " fail2ban.", 2)
		if len(parts) >= 1 {
			logEntry.Timestamp = strings.TrimSpace(parts[0])
		}

		if action := fail2banLogAction(line); action != "" {
			logEntry.Action = action
		}

		parsedLogs = append(parsedLogs, logEntry)
	}

	count := len(parsedLogs)
	jsonResponse(w, http.StatusOK, Fail2BanLogsResponse{Logs: parsedLogs, Count: &count})
}

// Fail2Ban Unban IP
func (s *Server) handleFail2BanUnban(w http.ResponseWriter, r *http.Request) {
	var req Fail2BanJailIPRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
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

	jsonResponse(w, http.StatusOK, StatusMessageResponse{Status: "success",
		Message: fmt.Sprintf("IP %s unbanned from jail %s", req.IP, req.Jail)})
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

	networkStats := []NetworkStats{}

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

		networkStats = append(networkStats, NetworkStats{
			ID: network.ID, Name: network.Name, CIDR: network.CIDR, Interface: network.InterfaceName,
			TotalNodes: len(nodes), OnlineNodes: netOnline, OfflineNodes: netOffline,
			PendingNodes: netPending, ExpiredNodes: netExpired, TransferRx: netRx, TransferTx: netTx,
		})
	}

	jsonResponse(w, http.StatusOK, StatsOverviewResponse{
		TotalNetworks: len(networks), TotalNodes: totalNodes, OnlineNodes: onlineNodes,
		OfflineNodes: offlineNodes, PendingNodes: pendingNodes, ExpiredNodes: expiredNodes,
		TotalRx: totalRx, TotalTx: totalTx, Networks: networkStats,
	})
}

// Debug WireGuard - shows interface status and registered peers
func (s *Server) handleDebugWireGuard(w http.ResponseWriter, r *http.Request) {
	networkID := mux.Vars(r)["networkId"]

	// Get network info
	network, err := s.store.GetNetwork(r.Context(), networkID)
	if err != nil || network == nil {
		errorResponse(w, http.StatusNotFound, "network not found")
		return
	}

	result := DebugWireGuardResponse{
		NetworkID:       networkID,
		NetworkName:     network.Name,
		InterfaceName:   network.InterfaceName,
		ServerPublicKey: network.ServerPublicKey,
		ServerEndpoint:  network.ServerEndpoint,
	}

	// Check manager
	s.managersMu.RLock()
	mgr := s.managers[networkID]
	s.managersMu.RUnlock()

	result.ManagerRegistered = mgr != nil

	// Get peers from WireGuard
	if mgr != nil {
		peers, err := mgr.GetPeers()
		if err != nil {
			wgErr := err.Error()
			result.WGError = &wgErr
		} else {
			count := len(peers)
			result.WGPeersCount = &count
			peerList := []DebugPeer{}
			for pubKey, status := range peers {
				peerList = append(peerList, DebugPeer{
					PublicKey:  pubKey,
					Endpoint:   status.Endpoint,
					AllowedIPs: status.AllowedIPs,
					TransferRx: status.TransferRx,
					TransferTx: status.TransferTx,
				})
			}
			result.WGPeers = &peerList
		}
	}

	// Get DB nodes for comparison
	nodes, err := s.store.ListNodes(r.Context(), networkID)
	if err == nil {
		count := len(nodes)
		result.DBNodesCount = &count
		nodeList := []DebugDBNode{}
		for _, n := range nodes {
			nodeList = append(nodeList, DebugDBNode{
				ID:        n.ID,
				Name:      n.Name,
				PublicKey: n.PublicKey,
				VirtualIP: n.VirtualIP.String(),
			})
		}
		result.DBNodes = &nodeList
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
	added, skipped, errs := restorePeers(mgr, nodes, currentPeers, time.Now())

	s.triggerReconcile()
	jsonResponse(w, http.StatusOK, SyncPeersResponse{Added: added, Skipped: skipped, Errors: errs, Total: len(nodes)})
}

// Middleware

// APIKeyMiddleware validates the X-API-Key header
func APIKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip if no key is configured (dev mode)
		if apiKey == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Public paths that don't need API Key
		if publicPaths[r.URL.Path] || isEnrollmentCheckin(r) {
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
	var req Fail2BanBanRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
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

		jsonResponse(w, http.StatusOK, Fail2BanBanResponse{Status: "success",
			Message: fmt.Sprintf("IP %s permanently banned via iptables", req.IP), Type: "permanent"})
		return
	}

	// Regular fail2ban ban
	_, err := execHostCommand("fail2ban-client", "set", req.Jail, "banip", req.IP)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to ban IP: "+err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, Fail2BanBanResponse{Status: "success",
		Message: fmt.Sprintf("IP %s banned in jail %s", req.IP, req.Jail), Type: "temporary"})
}

// Fail2Ban Get Jail Settings - Get current jail configuration
func (s *Server) handleFail2BanGetJailSettings(w http.ResponseWriter, r *http.Request) {
	jail := r.URL.Query().Get("jail")
	if jail == "" {
		jail = "sshd"
	}

	settings := Fail2BanJailSettingsResponse{Jail: jail}
	trimmed := func(out string) *string {
		v := strings.TrimSpace(out)
		return &v
	}

	// Get bantime
	if out, err := execHostCommand("fail2ban-client", "get", jail, "bantime"); err == nil {
		settings.Bantime = trimmed(out)
	}

	// Get maxretry
	if out, err := execHostCommand("fail2ban-client", "get", jail, "maxretry"); err == nil {
		settings.Maxretry = trimmed(out)
	}

	// Get findtime
	if out, err := execHostCommand("fail2ban-client", "get", jail, "findtime"); err == nil {
		settings.Findtime = trimmed(out)
	}

	// Get ignoreip (whitelist)
	if out, err := execHostCommand("fail2ban-client", "get", jail, "ignoreip"); err == nil {
		settings.IgnoreIP = trimmed(out)
	}

	jsonResponse(w, http.StatusOK, settings)
}

// Fail2Ban Update Jail Settings - Update jail configuration
func (s *Server) handleFail2BanUpdateJailSettings(w http.ResponseWriter, r *http.Request) {
	var req Fail2BanJailSettingsRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
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
		jsonResponse(w, http.StatusPartialContent, Fail2BanUpdateSettingsResponse{Status: "partial", Updated: updated, Errors: errors})
		return
	}

	jsonResponse(w, http.StatusOK, Fail2BanUpdateSettingsResponse{Status: "success", Updated: updated})
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

	jsonResponse(w, http.StatusOK, Fail2BanWhitelistResponse{Jail: jail, Whitelist: ips})
}

// Fail2Ban Update Whitelist - Add or remove IPs from whitelist
func (s *Server) handleFail2BanUpdateWhitelist(w http.ResponseWriter, r *http.Request) {
	var req Fail2BanWhitelistRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
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

	jsonResponse(w, http.StatusOK, StatusMessageResponse{Status: "success",
		Message: fmt.Sprintf("IP %s %sed in jail %s whitelist", req.IP, req.Action, req.Jail)})
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

	bannedIPs := []PermanentBan{}
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
					bannedIPs = append(bannedIPs, PermanentBan{LineNumber: lineNum, IP: sourceIP, Target: "DROP", Protocol: fields[2]})
				}
			}
		}
	}

	jsonResponse(w, http.StatusOK, PermanentBansResponse{PermanentBans: bannedIPs, Count: len(bannedIPs)})
}

// Fail2Ban Remove Permanent Ban - Remove a permanently banned IP from iptables
func (s *Server) handleFail2BanRemovePermanentBan(w http.ResponseWriter, r *http.Request) {
	var req Fail2BanIPRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
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

	jsonResponse(w, http.StatusOK, StatusMessageResponse{Status: "success", Message: fmt.Sprintf("Permanent ban removed for IP %s", req.IP)})
}

// Fail2Ban Jail Control - Start/Stop a jail
func (s *Server) handleFail2BanJailControl(w http.ResponseWriter, r *http.Request) {
	var req Fail2BanJailControlRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
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

	jsonResponse(w, http.StatusOK, StatusMessageResponse{Status: "success", Message: fmt.Sprintf("Jail %s %sed successfully", req.Jail, cmd)})
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

	jsonResponse(w, http.StatusOK, Fail2BanReloadResponse{Status: "success", Message: "Fail2Ban reloaded successfully", Output: strings.TrimSpace(out)})
}

// Fail2Ban Ping - Check if fail2ban is responding
func (s *Server) handleFail2BanPing(w http.ResponseWriter, r *http.Request) {
	out, err := execHostCommand("fail2ban-client", "ping")
	if err != nil {
		jsonResponse(w, http.StatusOK, Fail2BanPingResponse{Alive: false, Error: err.Error(), Message: "Fail2Ban is not responding"})
		return
	}

	// Expected output: "Server replied: pong"
	alive := strings.Contains(out, "pong")

	jsonResponse(w, http.StatusOK, Fail2BanPingResponse{Alive: alive, Message: strings.TrimSpace(out)})
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
	readErr := ""
	if f, err := openFail2BanLog(); err == nil {
		history = parseFail2BanHistory(f, jail, limit)
		f.Close()
	} else if !errors.Is(err, fs.ErrNotExist) {
		slog.Warn("fail2ban log cannot be read", "error", err)
		readErr = "fail2ban log cannot be read: " + err.Error()
	}

	entries := make([]Fail2BanHistoryEntry, 0, len(history))
	for _, m := range history {
		entries = append(entries, Fail2BanHistoryEntry{Raw: m["raw"], Timestamp: m["timestamp"], Jail: m["jail"], Action: m["action"], IP: m["ip"]})
	}
	jsonResponse(w, http.StatusOK, Fail2BanHistoryResponse{History: entries, Count: len(entries), Jail: jail, Error: readErr})
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
