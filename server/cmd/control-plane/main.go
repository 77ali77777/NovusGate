package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/novusgate/novusgate/internal/controlplane/api/rest"
	"github.com/novusgate/novusgate/internal/controlplane/backup"
	"github.com/novusgate/novusgate/internal/controlplane/firewall"
	"github.com/novusgate/novusgate/internal/controlplane/notify"
	"github.com/novusgate/novusgate/internal/controlplane/quota"
	"github.com/novusgate/novusgate/internal/controlplane/reconciler"
	"github.com/novusgate/novusgate/internal/controlplane/store"
	"github.com/novusgate/novusgate/internal/controlplane/traffic"
	"github.com/novusgate/novusgate/internal/shared/logging"
	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

var (
	cfgFile string
	version = "0.1.0"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "novusgate-server",
	Short: "novusgate Control Plane Server",
	Long: `novusgate Control Plane manages mesh VPN networks,
nodes, services, and access policies.`,
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the control plane server",
	RunE:  runServer,
}

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Run database migrations",
	RunE:  runMigrations,
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new network",
	RunE:  initNetwork,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("novusgate Control Plane v%s\n", version)
	},
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: /etc/novusgate/server.yaml)")

	// Serve command flags
	serveCmd.Flags().String("listen", ":8080", "HTTP listen address")
	serveCmd.Flags().String("grpc-listen", ":8443", "gRPC listen address")
	serveCmd.Flags().String("database", "", "Database connection string")

	// Init command flags
	initCmd.Flags().String("name", "", "Network name (required)")
	initCmd.Flags().String("cidr", "10.99.0.0/24", "Network CIDR")
	initCmd.Flags().String("database", "", "Database connection string")
	initCmd.MarkFlagRequired("name")

	// Migrate command flags
	migrateCmd.Flags().String("database", "", "Database connection string")

	// Bind flags to viper
	viper.BindPFlag("listen", serveCmd.Flags().Lookup("listen"))
	viper.BindPFlag("grpc_listen", serveCmd.Flags().Lookup("grpc-listen"))
	viper.BindPFlag("database_url", serveCmd.Flags().Lookup("database"))

	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(migrateCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(keysToLabelsCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("server")
		viper.SetConfigType("yaml")
		viper.AddConfigPath("/etc/novusgate")
		viper.AddConfigPath("$HOME/.novusgate")
		viper.AddConfigPath(".")
	}

	// Environment variables
	viper.SetEnvPrefix("novusgate")
	viper.AutomaticEnv()

	// Defaults
	viper.SetDefault("listen", ":8080")
	viper.SetDefault("grpc_listen", ":8443")

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fmt.Fprintf(os.Stderr, "Warning: Error reading config file: %v\n", err)
		}
	}
}

func runServer(cmd *cobra.Command, args []string) error {
	// Structured logs for the server; slog.SetDefault also routes the
	// standard log package. A typo in a logging variable must not stop the
	// VPN control plane: fall back to JSON/info and say so.
	logger, logErr := logging.New(os.Stdout, os.Getenv("LOG_FORMAT"), os.Getenv("LOG_LEVEL"))
	if logErr != nil {
		logger, _ = logging.New(os.Stdout, "", "")
	}
	slog.SetDefault(logger)
	if logErr != nil {
		slog.Warn(logErr.Error() + "; using LOG_FORMAT=json LOG_LEVEL=info")
	}

	// Get configuration
	listenAddr := viper.GetString("listen")
	databaseURL := viper.GetString("database_url")

	if databaseURL == "" {
		databaseURL = os.Getenv("DATABASE_URL")
	}
	if databaseURL == "" {
		return fmt.Errorf("database connection string is required (--database or DATABASE_URL)")
	}

	slog.Info(fmt.Sprintf("Starting novusgate Control Plane v%s", version))
	slog.Info(fmt.Sprintf("  HTTP Listen: %s", listenAddr))
	slog.Info(fmt.Sprintf("  Database: %s", maskDatabaseURL(databaseURL)))

	// Connect to database
	db, err := store.New(databaseURL)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()
	slog.Info("  Database: Connected")

	// Run migrations
	slog.Info("  Database: Running migrations...")
	if err := db.Migrate(context.Background()); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}
	slog.Info("  Database: Migrations applied")

	if err := rest.ValidateAPIKey(os.Getenv("novusgate_API_KEY")); err != nil {
		return err
	}

	if err := setupNodeKeys(context.Background(), db); err != nil {
		return err
	}

	// Bootstrap System (Admin User & Network)
	if err := bootstrapSystem(db); err != nil {
		slog.Error(fmt.Sprintf("Warning: Failed to bootstrap system: %v", err))
	}

	// Create REST API server (WireGuard managers are initialized internally by loadNetworks)
	apiServer := rest.NewServer(db)

	// WireGuard reconciler: off | shadow (default: report only) | enforce.
	wgMode, err := reconciler.ParseMode(os.Getenv("WG_RECONCILER"))
	if err != nil {
		return err
	}
	recCtx, stopReconciler := context.WithCancel(context.Background())
	defer stopReconciler()

	// Telegram notifications (P8): settings live in the database, so the
	// watchers always run and send only when the panel has enabled them.
	telegram := &notify.Telegram{BaseURL: "https://api.telegram.org", Client: &http.Client{Timeout: 20 * time.Second}}
	notifier := &notify.Notifier{Settings: db.NotificationSettings, Sender: telegram, Now: time.Now, Repeat: 30 * time.Minute}
	apiServer.SetNotifier(notifier, telegram)
	go notifier.Run(recCtx)
	peerWatcher := &notify.PeerWatcher{
		Notifier: notifier,
		Nodes:    func(ctx context.Context) ([]notify.WatchedNode, error) { return watchedNodes(ctx, db) },
		Peers: func(iface string) (map[string]wireguard.PeerStatus, error) {
			return wireguard.NewManager(iface).GetPeers()
		},
		Now: time.Now,
	}
	go peerWatcher.Run(recCtx)
	go (&notify.Fail2BanWatcher{Notifier: notifier, Path: rest.Fail2BanLogPath}).Run(recCtx)

	var rec *reconciler.Reconciler
	if wgMode != reconciler.ModeOff {
		rec = reconciler.New(wgMode, db, func(iface string) reconciler.PeerControl { return wireguard.NewManager(iface) })
		rec.OnExpired = func(n *models.Node) {
			notifier.Notify(notify.Event{Kind: notify.NodeExpired, Key: n.ID,
				Text: fmt.Sprintf("⏰ NovusGate: node %s expired; its access was removed", n.Name)})
		}
		apiServer.SetReconciler(rec)
		go rec.Run(recCtx, 15*time.Second)
		slog.Info(fmt.Sprintf("  WireGuard reconciler: %s", wgMode))
	}

	// Manual backups from the panel (P8): database dump + WireGuard configs.
	// /var/backups/novusgate is a host bind mount; uninstall keeps it.
	apiServer.SetBackups(&backup.Service{
		Dir:          "/var/backups/novusgate/panel",
		WireGuardDir: "/etc/wireguard",
		Dump:         backup.PgDump(databaseURL),
		Now:          time.Now,
	})

	// Traffic history (P8): every node's counters every 5 minutes, 30 days kept.
	sampler := &traffic.Sampler{
		Store: db,
		Peers: func(iface string) (map[string]wireguard.PeerStatus, error) {
			return wireguard.NewManager(iface).GetPeers()
		},
		Now:       time.Now,
		Retention: 30 * 24 * time.Hour,
	}
	// Traffic quotas (P9c): every sample run counts the nodes with a quota.
	quotas := &quota.Tracker{
		Store:     db,
		Now:       time.Now,
		Apply:     func() { apiServer.ApplyLimits(context.Background()) },
		Enforcing: apiServer.EnforcesLimits,
		Notify: func(key, text string) {
			notifier.Notify(notify.Event{Kind: notify.QuotaExceeded, Key: key, Text: text})
		},
	}
	sampler.After = func(ctx context.Context, samples []traffic.Sample) {
		if err := quotas.Observe(ctx, samples); err != nil {
			slog.Warn("traffic quota update failed", "error", err)
		}
	}
	go sampler.Run(recCtx, 5*time.Minute)

	// Firewall engine: iptables (default, legacy paths), shadow (check only) or nft.
	fwMode, err := firewall.ParseMode(os.Getenv("FIREWALL_ENGINE"))
	if err != nil {
		return err
	}
	if fwMode != firewall.ModeIptables {
		fw := firewall.NewHostEngine(fwMode, db)
		fw.History = db // P3c History: every applied change is recorded
		apiServer.SetFirewall(fw)
		go func() {
			if err := apiServer.StartFirewall(context.Background()); err != nil {
				slog.Error(fmt.Sprintf("[Firewall] startup failed: %v", err))
			}
		}()
		slog.Info(fmt.Sprintf("  Firewall engine: %s", fwMode))
	}

	// Ensure Admin Network manager is registered after bootstrap
	// This handles the case where bootstrapSystem creates the network after loadNetworks runs
	go func() {
		time.Sleep(5 * time.Second) // Wait for loadNetworks to complete
		ctx := context.Background()
		networks, err := db.ListNetworks(ctx)
		if err != nil {
			return
		}
		for _, net := range networks {
			if net.InterfaceName == "wg0" {
				// Force re-registration by calling the API server's internal method
				// This is a workaround - ideally loadNetworks should be called after bootstrap
				slog.Info("Ensuring wg0 manager is registered for Admin Network...")
				break
			}
		}
	}()

	// Create HTTP server
	httpServer := newHTTPServer(listenAddr, apiServer.Router(), slog.Default())

	// Start server in goroutine
	go func() {
		slog.Info(fmt.Sprintf("HTTP server listening on %s", listenAddr))
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error(fmt.Sprintf("HTTP server error: %v", err))
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	stopReconciler()
	if rec != nil { // let a run in progress finish before the process exits
		waited := make(chan struct{})
		go func() { rec.Wait(); close(waited) }()
		select {
		case <-waited:
		case <-time.After(30 * time.Second):
			slog.Warn("reconciler did not stop within 30s")
		}
	}

	slog.Info("\nShutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown error: %w", err)
	}

	slog.Info("Server stopped")
	return nil
}

func runMigrations(cmd *cobra.Command, args []string) error {
	// The store logs migration progress through slog; keep this CLI's output
	// readable for the person running it.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))
	databaseURL, _ := cmd.Flags().GetString("database")
	if databaseURL == "" {
		databaseURL = viper.GetString("database_url")
	}
	if databaseURL == "" {
		databaseURL = os.Getenv("DATABASE_URL")
	}
	if databaseURL == "" {
		return fmt.Errorf("database connection string is required")
	}

	fmt.Println("Running database migrations...")

	// Connect to database
	db, err := store.New(databaseURL)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	// Run migrations
	if err := db.Migrate(context.Background()); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	fmt.Println("Migrations completed successfully")
	return nil
}

func initNetwork(cmd *cobra.Command, args []string) error {
	name, _ := cmd.Flags().GetString("name")
	cidr, _ := cmd.Flags().GetString("cidr")
	databaseURL, _ := cmd.Flags().GetString("database")

	if databaseURL == "" {
		databaseURL = viper.GetString("database_url")
	}
	if databaseURL == "" {
		databaseURL = os.Getenv("DATABASE_URL")
	}
	if databaseURL == "" {
		return fmt.Errorf("database connection string is required")
	}

	// Connect to database
	db, err := store.New(databaseURL)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	// Create network with WireGuard keys
	ctx := context.Background()

	// Generate WireGuard key pair for the hub (server)
	privateKey, publicKey, err := wireguard.GenerateKeys()
	if err != nil {
		return fmt.Errorf("failed to generate WireGuard keys: %w", err)
	}

	// Get server endpoint from environment or use default
	serverEndpoint := wireguard.GetServerEndpoint()

	network := &models.Network{
		Name:             name,
		CIDR:             cidr,
		ServerPrivateKey: privateKey,
		ServerPublicKey:  publicKey,
		ServerEndpoint:   fmt.Sprintf("%s:51820", serverEndpoint),
	}

	if err := db.CreateNetwork(ctx, network); err != nil {
		// Check if network already exists
		existing, errList := db.ListNetworks(ctx)
		if errList == nil {
			found := false
			for _, n := range existing {
				if n.Name == name {
					network = n
					found = true
					fmt.Printf("Network '%s' already exists (ID: %s), proceeding to config...\n", name, network.ID)
					break
				}
			}
			if !found {
				return fmt.Errorf("failed to create network: %w", err)
			}
		} else {
			return fmt.Errorf("failed to create network: %w", err)
		}
	} else {
		fmt.Printf("Network created successfully!\n")
		fmt.Printf("  ID: %s\n", network.ID)
		fmt.Printf("  Name: %s\n", network.Name)
		fmt.Printf("  CIDR: %s\n", network.CIDR)
		fmt.Printf("  Server Public Key: %s\n", network.ServerPublicKey)
		fmt.Printf("  Server Endpoint: %s\n", network.ServerEndpoint)
	}

	// Initialize WireGuard for this network
	// Initialize WireGuard for this network
	wgManager := wireguard.NewManager("wg0")
	// Calculate server IP (first IP in CIDR)
	_, ipNet, _ := net.ParseCIDR(network.CIDR)
	ip := ipNet.IP
	// Increment IP to get .1 (hacky increment for IPv4)
	ip[len(ip)-1]++
	serverIP := fmt.Sprintf("%s/%s", ip.String(), strings.Split(network.CIDR, "/")[1])
	serverPort := 51820

	// Create WireGuard config using the network's private key
	if err := wgManager.CreateServerConfigWithKey(network.ServerPrivateKey, serverIP, serverPort); err != nil {
		fmt.Printf("Warning: Failed to create WireGuard config: %v\n", err)
	} else {
		fmt.Printf("WireGuard configuration written to /etc/wireguard/wg0.conf\n")
		// Attempt to start interface
		if err := wgManager.Up(); err != nil {
			fmt.Printf("Warning: Failed to bring up WireGuard interface: %v\n", err)
		} else {
			fmt.Printf("WireGuard interface wg0 started successfully.\n")
		}
	}

	return nil
}

func runMigrationSQL(db *store.Store) error {
	// Migrations are handled by the store package
	// This is a placeholder for when we add proper migration support
	fmt.Println("Note: Please run migrations/001_initial.sql manually or use a migration tool")
	return nil
}

var (
	// urlPasswordRe matches the userinfo password up to the last '@', so an
	// unencoded '#', '/' or '@' in it (compose builds the URL from .env
	// unencoded) is still covered; url.Parse would fail on those.
	urlPasswordRe = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9+.-]*://[^:/?#@\s]*:).*@`)
	// kvPasswordRe matches password=... in a DSN or a URL query, quoted or not.
	kvPasswordRe = regexp.MustCompile(`(password\s*=\s*)('(?:[^'\\]|\\.)*'|[^\s&]+)`)
)

// maskDatabaseURL hides the password in a postgres URL or key=value DSN so
// it never reaches the logs.
func maskDatabaseURL(raw string) string {
	masked := urlPasswordRe.ReplaceAllString(raw, "${1}xxxxx@")
	return kvPasswordRe.ReplaceAllString(masked, "${1}xxxxx")
}

func bootstrapSystem(db *store.Store) error {
	ctx := context.Background()

	// 1. Bootstrap Admin User
	users, err := db.ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	if len(users) == 0 {
		username := os.Getenv("ADMIN_USERNAME")
		if username == "" {
			username = "admin"
		}
		password := os.Getenv("ADMIN_PASSWORD")
		if password == "" {
			return fmt.Errorf("ADMIN_PASSWORD environment variable is required for first-time setup")
		}

		slog.Info(fmt.Sprintf("Bootstrapping admin user: %s", username))
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}

		user := &models.User{
			Username:     username,
			PasswordHash: string(hashedPassword),
		}

		if err := db.CreateUser(ctx, user); err != nil {
			return fmt.Errorf("failed to create admin user: %w", err)
		}
		slog.Info("Admin user created successfully")
	}

	// 2. Bootstrap Admin Network (wg0)
	cidr := os.Getenv("ADMIN_CIDR")
	if cidr == "" {
		return fmt.Errorf("ADMIN_CIDR environment variable is required (check .env)")
	}
	port := 51820
	serverEndpoint := wireguard.GetServerEndpoint()

	networks, err := db.ListNetworks(ctx)
	if err != nil {
		return fmt.Errorf("failed to list networks: %w", err)
	}

	var adminNet *models.Network
	for _, n := range networks {
		if n.InterfaceName == "wg0" {
			adminNet = n
			break
		}
	}

	if adminNet == nil {
		// Create new
		slog.Info(fmt.Sprintf("Bootstrapping Admin Network (wg0) on %s...", cidr))

		// CRITICAL: We MUST read keys from existing wg0.conf created by installer
		// The installer creates wg0 on the HOST before starting Docker containers
		var privateKey, publicKey string

		// Step 1: Try to read private key from config file (this is the source of truth)
		configPath := "/etc/wireguard/wg0.conf"
		if privKeyBytes, err := os.ReadFile(configPath); err == nil {
			config := string(privKeyBytes)
			slog.Info("Found existing wg0.conf, reading keys...")

			// Parse PrivateKey
			if idx := strings.Index(config, "PrivateKey = "); idx != -1 {
				start := idx + len("PrivateKey = ")
				end := strings.Index(config[start:], "\n")
				if end != -1 {
					privateKey = strings.TrimSpace(config[start : start+end])
					slog.Info("Read private key from wg0.conf")
				}
			}
		} else {
			slog.Warn(fmt.Sprintf("Warning: Could not read %s: %v", configPath, err))
		}

		// Step 2: Derive public key from private key (or get from running interface)
		if privateKey != "" {
			// Derive public key from private key using wg pubkey
			cmd := exec.Command("wg", "pubkey")
			cmd.Stdin = strings.NewReader(privateKey)
			output, err := cmd.Output()
			if err == nil {
				publicKey = strings.TrimSpace(string(output))
				slog.Info(fmt.Sprintf("Derived public key: %s", publicKey))
			} else {
				slog.Error(fmt.Sprintf("Warning: Failed to derive public key: %v", err))
			}
		}

		// Step 3: Fallback - try to get public key from running interface
		if publicKey == "" {
			mgr := wireguard.NewManager("wg0")
			if err := mgr.Init(); err == nil {
				if existingPubKey, err := mgr.GetPublicKey(); err == nil && existingPubKey != "" {
					publicKey = existingPubKey
					slog.Info(fmt.Sprintf("Got public key from running wg0 interface: %s", publicKey))
				}
			}
		}

		// Step 4: Last resort - generate new keys (this should NOT happen in normal flow)
		if privateKey == "" || publicKey == "" {
			slog.Warn("WARNING: Could not read existing keys, generating new ones...")
			slog.Warn("This may cause connection issues if wg0 was already configured by installer!")
			privateKey, publicKey, err = wireguard.GenerateKeys()
			if err != nil {
				return fmt.Errorf("failed to generate WireGuard keys: %w", err)
			}
		}

		network := &models.Network{
			ID:               "00000000-0000-0000-0000-000000000001",
			Name:             "Admin Management Network",
			CIDR:             cidr,
			ListenPort:       port,
			InterfaceName:    "wg0",
			ServerPrivateKey: privateKey,
			ServerPublicKey:  publicKey,
			ServerEndpoint:   fmt.Sprintf("%s:%d", serverEndpoint, port),
		}

		if err := db.CreateNetwork(ctx, network); err != nil {
			return fmt.Errorf("failed to create admin network: %w", err)
		}
		slog.Info(fmt.Sprintf("Admin Network (wg0) created successfully with public key: %s", publicKey))

	} else {
		// Admin Network already exists - verify and sync keys if needed
		slog.Info(fmt.Sprintf("Admin Network (wg0) already exists in DB with public key: %s", adminNet.ServerPublicKey))

		// Read actual keys from wg0.conf to verify they match
		configPath := "/etc/wireguard/wg0.conf"
		if privKeyBytes, err := os.ReadFile(configPath); err == nil {
			config := string(privKeyBytes)
			var actualPrivateKey, actualPublicKey string

			// Parse PrivateKey from config
			if idx := strings.Index(config, "PrivateKey = "); idx != -1 {
				start := idx + len("PrivateKey = ")
				end := strings.Index(config[start:], "\n")
				if end != -1 {
					actualPrivateKey = strings.TrimSpace(config[start : start+end])
				}
			}

			// Derive public key
			if actualPrivateKey != "" {
				cmd := exec.Command("wg", "pubkey")
				cmd.Stdin = strings.NewReader(actualPrivateKey)
				output, err := cmd.Output()
				if err == nil {
					actualPublicKey = strings.TrimSpace(string(output))
				}
			}

			// Check if DB keys match actual wg0 keys
			if actualPublicKey != "" && actualPublicKey != adminNet.ServerPublicKey {
				slog.Warn(fmt.Sprintf("WARNING: DB public key (%s) does not match wg0.conf key (%s)",
					adminNet.ServerPublicKey, actualPublicKey))
				slog.Info("Updating DB with correct keys from wg0.conf...")

				// Update network with correct keys
				if err := db.UpdateNetworkKeys(ctx, adminNet.ID, actualPrivateKey, actualPublicKey); err != nil {
					slog.Error(fmt.Sprintf("Failed to update network keys: %v", err))
				} else {
					slog.Info(fmt.Sprintf("SUCCESS: Network keys synced with wg0.conf. New public key: %s", actualPublicKey))
				}
			} else if actualPublicKey != "" {
				slog.Info("Keys are in sync ✓")
			}
		}

		// Also check CIDR mismatch
		if adminNet.CIDR != cidr {
			slog.Info(fmt.Sprintf("CORRECTION: Existing Admin Network (wg0) CIDR (%s) mismatches ENV config (%s).", adminNet.CIDR, cidr))
			slog.Info("Applying correction to Database...")

			if err := db.UpdateNetworkCIDR(ctx, adminNet.ID, cidr); err != nil {
				slog.Error(fmt.Sprintf("failed to update network CIDR: %v", err))
			} else {
				slog.Info("SUCCESS: Network configuration updated. Please restart the service or reboot if issues persist.")
			}
		}
	}

	return nil
}

// newHTTPServer builds the API server. net/http's own errors (accept
// failures, recovered panics) go to the logger at Error, so LOG_LEVEL=warn
// does not hide them.
func newHTTPServer(addr string, h http.Handler, logger *slog.Logger) *http.Server {
	return &http.Server{
		Addr:         addr,
		Handler:      h,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
		ErrorLog:     slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
}

// watchedNodes lists the nodes the peer watcher follows: every node with a
// key on a network with an interface, except expired ones.
func watchedNodes(ctx context.Context, db *store.Store) ([]notify.WatchedNode, error) {
	networks, err := db.ListNetworks(ctx)
	if err != nil {
		return nil, err
	}
	var out []notify.WatchedNode
	for _, nw := range networks {
		if nw.InterfaceName == "" {
			continue
		}
		nodes, err := db.ListNodes(ctx, nw.ID)
		if err != nil {
			return nil, err
		}
		for _, n := range nodes {
			if n.PublicKey == "" || n.Status == models.NodeStatusExpired {
				continue
			}
			out = append(out, notify.WatchedNode{ID: n.ID, Name: n.Name, Network: nw.Name, Interface: nw.InterfaceName, PublicKey: n.PublicKey})
		}
	}
	return out, nil
}
