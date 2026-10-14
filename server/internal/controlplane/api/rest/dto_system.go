package rest

import "github.com/novusgate/novusgate/internal/shared/models"

// StatusResponse is {"status": "..."} ("success", "deleted", "confirmed").
type StatusResponse struct {
	Status string `json:"status"`
}

// StatusMessageResponse is {"status","message"}.
type StatusMessageResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type LoginResponse struct {
	Token    string `json:"token"`
	Username string `json:"username"`
}

type CreateServerResponse struct {
	Node   *models.Node `json:"node"`
	Config string       `json:"config"`
}

type SyncPeersResponse struct {
	Added   int      `json:"added"`
	Skipped int      `json:"skipped"`
	Errors  []string `json:"errors"`
	Total   int      `json:"total"`
}

type HealthResponse struct {
	Status  string       `json:"status"` // healthy | degraded
	Version string       `json:"version"`
	Checks  HealthChecks `json:"checks"`
}

type HealthChecks struct {
	Database   OKCheck          `json:"database"`
	WireGuard  *WireGuardCheck  `json:"wireguard,omitempty"`  // only when the database answers
	Reconciler *ReconcilerCheck `json:"reconciler,omitempty"` // only when WG_RECONCILER != off
	Firewall   FirewallCheck    `json:"firewall"`
}

type OKCheck struct {
	OK bool `json:"ok"`
}

type WireGuardCheck struct {
	OK         bool              `json:"ok"`
	Interfaces map[string]string `json:"interfaces"` // interface -> up | down
}

type ReconcilerCheck struct {
	OK      bool    `json:"ok"`
	Mode    string  `json:"mode"`
	Pending int     `json:"pending"`
	LastRun *string `json:"last_run"` // null until the first run
}

type FirewallCheck struct {
	OK      bool   `json:"ok"`
	Mode    string `json:"mode"`
	Ready   *bool  `json:"ready,omitempty"`   // nft mode only
	Pending *bool  `json:"pending,omitempty"` // nft mode only
}

// SystemInfoResponse: optional fields are present only when the host
// file or command they come from could be read.
type SystemInfoResponse struct {
	CPUCores        int     `json:"cpu_cores"`
	CPUModel        *string `json:"cpu_model,omitempty"`
	Load1m          *string `json:"load_1m,omitempty"`
	Load5m          *string `json:"load_5m,omitempty"`
	Load15m         *string `json:"load_15m,omitempty"`
	MemoryTotal     int64   `json:"memory_total"`
	MemoryFree      int64   `json:"memory_free"`
	MemoryAvailable int64   `json:"memory_available"`
	MemoryUsed      int64   `json:"memory_used"`
	MemoryBuffers   int64   `json:"memory_buffers"`
	MemoryCached    int64   `json:"memory_cached"`
	DiskTotal       *int64  `json:"disk_total,omitempty"`
	DiskUsed        *int64  `json:"disk_used,omitempty"`
	DiskFree        *int64  `json:"disk_free,omitempty"`
	UptimeSeconds   *int64  `json:"uptime_seconds,omitempty"`
	Hostname        string  `json:"hostname"`
}

type StatsOverviewResponse struct {
	TotalNetworks int            `json:"total_networks"`
	TotalNodes    int            `json:"total_nodes"`
	OnlineNodes   int            `json:"online_nodes"`
	OfflineNodes  int            `json:"offline_nodes"`
	PendingNodes  int            `json:"pending_nodes"`
	ExpiredNodes  int            `json:"expired_nodes"`
	TotalRx       int64          `json:"total_rx"`
	TotalTx       int64          `json:"total_tx"`
	Networks      []NetworkStats `json:"networks"`
}

type NetworkStats struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	CIDR         string `json:"cidr"`
	Interface    string `json:"interface"`
	TotalNodes   int    `json:"total_nodes"`
	OnlineNodes  int    `json:"online_nodes"`
	OfflineNodes int    `json:"offline_nodes"`
	PendingNodes int    `json:"pending_nodes"`
	ExpiredNodes int    `json:"expired_nodes"`
	TransferRx   int64  `json:"transfer_rx"`
	TransferTx   int64  `json:"transfer_tx"`
}

// DebugWireGuardResponse compares DB nodes with live peers. The wg_* group
// is present only with a registered manager (wg_error when reading peers
// failed, wg_peers otherwise); db_* only when listing nodes worked.
type DebugWireGuardResponse struct {
	NetworkID         string         `json:"network_id"`
	NetworkName       string         `json:"network_name"`
	InterfaceName     string         `json:"interface_name"`
	ServerPublicKey   string         `json:"server_public_key"`
	ServerEndpoint    string         `json:"server_endpoint"`
	ManagerRegistered bool           `json:"manager_registered"`
	WGError           *string        `json:"wg_error,omitempty"`
	WGPeersCount      *int           `json:"wg_peers_count,omitempty"`
	WGPeers           *[]DebugPeer   `json:"wg_peers,omitempty"`
	DBNodesCount      *int           `json:"db_nodes_count,omitempty"`
	DBNodes           *[]DebugDBNode `json:"db_nodes,omitempty"`
}

type DebugPeer struct {
	PublicKey  string `json:"public_key"`
	Endpoint   string `json:"endpoint"`
	AllowedIPs string `json:"allowed_ips"`
	TransferRx int64  `json:"transfer_rx"`
	TransferTx int64  `json:"transfer_tx"`
}

type DebugDBNode struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	VirtualIP string `json:"virtual_ip"`
}

// DebugNotFoundResponse is debug/wireguard's legacy 404 body (not the
// unified error shape; kept as is, see P2d-2 deferred minor M-3).
type DebugNotFoundResponse struct {
	NetworkID string `json:"network_id"`
	Error     string `json:"error"`
}
