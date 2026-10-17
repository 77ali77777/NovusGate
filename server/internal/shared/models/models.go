package models

import (
	"encoding/json"
	"net"
	"time"
)

// NodeStatus represents the current status of a node
type NodeStatus string

const (
	NodeStatusPending NodeStatus = "pending"
	NodeStatusOnline  NodeStatus = "online"
	NodeStatusOffline NodeStatus = "offline"
	NodeStatusExpired NodeStatus = "expired"
)

// Network represents a VPN network (Hub configuration)
type Network struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	CIDR             string    `json:"cidr"`
	ServerPrivateKey string    `json:"-"`                           // Hub's private key (never sent to client)
	ServerPublicKey  string    `json:"server_public_key,omitempty"` // Hub's public key (sent to peers)
	ServerEndpoint   string    `json:"server_endpoint,omitempty"`   // Hub's endpoint (IP:Port)
	ListenPort       int       `json:"listen_port"`                 // UDP port (e.g., 51820)
	InterfaceName    string    `json:"interface_name"`              // Interface name (e.g., wg0)
	ClientDNS        string    `json:"client_dns"`                  // DNS servers for clients, comma separated; empty: default
	TunnelMode       string    `json:"tunnel_mode"`                 // TunnelSplit or TunnelFull: what its nodes route through the hub
	// Live state of the hub's interface (not stored): whether it runs, and
	// the last reason it could not be brought up ("" when it came up).
	InterfaceUp    bool   `json:"interface_up"`
	InterfaceError string `json:"interface_error"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// Tunnel modes. Split: a node's config routes the VPN networks through the
// hub; full: all IPv4 traffic, the hub being its internet exit.
const (
	TunnelSplit = "split"
	TunnelFull  = "full"
)

// ValidTunnelMode reports whether m is a tunnel mode.
func ValidTunnelMode(m string) bool { return m == TunnelSplit || m == TunnelFull }

// Node represents a peer (spoke) in the VPN network
type Node struct {
	ID         string            `json:"id"`
	NetworkID  string            `json:"network_id"`
	Name       string            `json:"name"`
	VirtualIP  net.IP            `json:"virtual_ip"`
	PublicKey  string            `json:"public_key"`
	Labels     map[string]string `json:"labels"`
	Status     NodeStatus        `json:"status"`
	LastSeen   time.Time         `json:"last_seen"`
	PublicIP   string            `json:"public_ip,omitempty"`
	TransferRx int64             `json:"transfer_rx,omitempty"`
	TransferTx int64             `json:"transfer_tx,omitempty"`
	ExpiresAt  *time.Time        `json:"expires_at,omitempty"`
	NodeInfo   *NodeInfo         `json:"node_info,omitempty"`
	Endpoints  []string          `json:"endpoints"`
	HasConfig  bool              `json:"has_config"` // the server holds its private key: config, QR and install script work
	// TunnelOverride is TunnelSplit or TunnelFull for this node only; empty:
	// the node follows its network's TunnelMode.
	TunnelOverride string    `json:"tunnel_override"`
	CreatedAt      time.Time `json:"created_at"`
}

// Active reports whether the node may hold a WireGuard peer at time now: it
// has a key and an address, is not marked expired, and now is not after
// its expires_at.
func (n *Node) Active(now time.Time) bool {
	if n.PublicKey == "" || n.VirtualIP == nil || n.Status == NodeStatusExpired {
		return false
	}
	return n.ExpiresAt == nil || n.ExpiresAt.IsZero() || !now.After(*n.ExpiresAt)
}

// NodeInfo contains metadata about the node's system
type NodeInfo struct {
	OS           string `json:"os"`
	Architecture string `json:"arch"`
	Hostname     string `json:"hostname"`
}

// User represents a system user (admin)
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"` // admin, operator or viewer (P9a)
	CreatedAt    time.Time `json:"created_at"`
}

// NetworkEvent represents a real-time network event
type NetworkEvent struct {
	Type      EventType `json:"type"`
	Payload   any       `json:"payload"`
	Timestamp time.Time `json:"timestamp"`
}

// EventType represents the type of network event
type EventType string

const (
	EventTypePeerAdded   EventType = "peer_added"
	EventTypePeerRemoved EventType = "peer_removed"
	EventTypePeerUpdated EventType = "peer_updated"
)

// VPNFirewallRule represents a firewall rule for VPN traffic control
type VPNFirewallRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`

	// Source configuration
	SourceType      string  `json:"source_type"` // any, network, node, custom
	SourceNetworkID *string `json:"source_network_id,omitempty"`
	SourceNodeID    *string `json:"source_node_id,omitempty"`
	SourceIP        string  `json:"source_ip,omitempty"`

	// Destination configuration
	DestType      string  `json:"dest_type"` // any, network, node, custom
	DestNetworkID *string `json:"dest_network_id,omitempty"`
	DestNodeID    *string `json:"dest_node_id,omitempty"`
	DestIP        string  `json:"dest_ip,omitempty"`

	// Group endpoints (source_type / dest_type "group", P9a)
	SourceGroupID *string `json:"source_group_id,omitempty"`
	DestGroupID   *string `json:"dest_group_id,omitempty"`

	// Rule details
	Protocol string `json:"protocol"`       // tcp, udp, icmp, all
	Port     string `json:"port,omitempty"` // port or range
	Action   string `json:"action"`         // accept, drop, reject

	// Metadata
	Priority  int       `json:"priority"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Joined fields for display (not stored in DB)
	SourceNetworkName string `json:"source_network_name,omitempty"`
	SourceNodeName    string `json:"source_node_name,omitempty"`
	DestNetworkName   string `json:"dest_network_name,omitempty"`
	DestNodeName      string `json:"dest_node_name,omitempty"`
	SourceGroupName   string `json:"source_group_name,omitempty"`
	DestGroupName     string `json:"dest_group_name,omitempty"`
}

// FirewallAuditLog represents an audit log entry for firewall changes
type FirewallAuditLog struct {
	ID        string                 `json:"id"`
	Action    string                 `json:"action"`
	Details   map[string]interface{} `json:"details,omitempty"`
	UserIP    string                 `json:"user_ip,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}

// NotificationSettings are the Telegram notification settings (P8). The bot
// token is stored sealed and never returned; TokenSet says whether one is.
type NotificationSettings struct {
	Enabled        bool   `json:"enabled"`
	ChatID         string `json:"chat_id"`
	TokenSet       bool   `json:"token_set"`
	NodeOffline    bool   `json:"node_offline"`    // a node goes offline or comes back
	NodeExpired    bool   `json:"node_expired"`    // a node's access expired
	Fail2BanBan    bool   `json:"fail2ban_ban"`    // Fail2Ban banned an address
	FirewallChange bool   `json:"firewall_change"` // a firewall rule was changed
	QuotaExceeded  bool   `json:"quota_exceeded"`  // a node reached 80% or 100% of its traffic quota (P9c)
}

// FirewallService opens a host port through the nftables engine.
type FirewallService struct {
	ID        string    `json:"id"`
	Protocol  string    `json:"protocol"` // tcp or udp
	PortFrom  int       `json:"port_from"`
	PortTo    int       `json:"port_to"`
	Sources   []string  `json:"sources"` // IPs or CIDRs; empty means any source
	Interface string    `json:"interface,omitempty"`
	Comment   string    `json:"comment,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// FirewallIPRule blocks or allows a source address, optionally on some ports.
type FirewallIPRule struct {
	ID        string     `json:"id"`
	Action    string     `json:"action"`             // block or allow
	Prefix    string     `json:"prefix"`             // CIDR, e.g. 203.0.113.7/32
	Protocol  string     `json:"protocol,omitempty"` // tcp, udp or empty
	Ports     string     `json:"ports,omitempty"`    // e.g. "80,443,8000-8100"
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Origin    string     `json:"origin"` // panel, fail2ban or import
	Comment   string     `json:"comment,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// FirewallForward publishes a VPN node's port on the server's public address.
type FirewallForward struct {
	ID         string    `json:"id"`
	Protocol   string    `json:"protocol"` // tcp or udp
	PublicPort int       `json:"public_port"`
	TargetIP   string    `json:"target_ip"`
	TargetPort int       `json:"target_port"`
	Comment    string    `json:"comment,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// FirewallHistoryEntry is the stored firewall state after one applied change
// (P3c History). State is the engine's state as JSON; Action says what made
// the change ("baseline" for the state before the first recorded one).
type FirewallHistoryEntry struct {
	ID        string          `json:"id"`
	CreatedAt time.Time       `json:"created_at"`
	UserID    string          `json:"user_id,omitempty"`
	Username  string          `json:"username,omitempty"`
	Action    string          `json:"action"`
	State     json.RawMessage `json:"-"`
}

// AuditEntry is one row of the audit log: a change made through the API or
// a login attempt (stored in firewall_audit_log, which predates it).
type AuditEntry struct {
	ID        string         `json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	Action    string         `json:"action"`
	Details   map[string]any `json:"details"`
	UserIP    string         `json:"user_ip,omitempty"`
	Username  string         `json:"username,omitempty"`
}

// SessionInfo is a login session as the panel lists it; the token hash
// stays on the server.
type SessionInfo struct {
	ID         string    `json:"id"`
	Username   string    `json:"username"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Current    bool      `json:"current"`
	TokenHash  string    `json:"-"`
}

// NodeGroup is a named set of nodes (P9a); VPN rules and limits can name a
// group instead of single nodes.
type NodeGroup struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Members     []NodeGroupMember `json:"members"`
	CreatedAt   time.Time         `json:"created_at"`
	// SetNo names the group's nft set (grp_<n>); it never changes.
	SetNo int `json:"-"`
}

// NodeGroupMember is a node in a group, with what rules need of it.
type NodeGroupMember struct {
	NodeID    string `json:"node_id"`
	Name      string `json:"name"`
	VirtualIP string `json:"virtual_ip"`
	NetworkID string `json:"network_id"`
}

// LimitProfile (P9b) limits each bound node separately: speed, concurrent
// connections and the times it may use the VPN. Nil limits are unlimited;
// an empty schedule allows every time.
type LimitProfile struct {
	ID             string           `json:"id"`
	Name           string           `json:"name"`
	DownKbps       *int             `json:"down_kbps"`
	UpKbps         *int             `json:"up_kbps"`
	MaxConnections *int             `json:"max_connections"`
	Schedule       []ScheduleWindow `json:"schedule"`
	Timezone       string           `json:"timezone"`
	NodeIDs        []string         `json:"node_ids"`  // nodes bound directly
	GroupIDs       []string         `json:"group_ids"` // groups bound; their members inherit it
	// Monthly traffic quota (P9c): nil = none. Over it a node is blocked or
	// throttled to ThrottleKbps until the period starts again on
	// QuotaResetDay (1-28, local midnight in Timezone).
	QuotaMB       *int      `json:"quota_mb"`
	QuotaAction   string    `json:"quota_action"` // block or throttle
	ThrottleKbps  *int      `json:"throttle_kbps"`
	QuotaResetDay int       `json:"quota_reset_day"`
	CreatedAt     time.Time `json:"created_at"`
	// SetNo names the profile's nft sets (lim_<n>); it never changes.
	SetNo int `json:"-"`
}

// NodeQuotaState is one node's traffic in the current quota period (P9c).
// LastRx/LastTx are the WireGuard counters of the last sample.
type NodeQuotaState struct {
	NodeID      string     `json:"node_id"`
	PeriodStart time.Time  `json:"period_start"`
	PeriodEnd   time.Time  `json:"period_end"` // fixed at the period start
	UsedBytes   int64      `json:"used_bytes"`
	LastRx      int64      `json:"-"`
	LastTx      int64      `json:"-"`
	WarnedAt    *time.Time `json:"warned_at"`
	ExceededAt  *time.Time `json:"exceeded_at"`
	UpdatedAt   time.Time  `json:"-"` // guards concurrent writers (tracker vs reset)
}

// ScheduleWindow allows traffic on Days from From to To, local time of the
// profile's time zone. To "24:00" is the end of the day; To before From
// runs past midnight into the next day.
type ScheduleWindow struct {
	Days []int  `json:"days"` // 0 = Sunday … 6 = Saturday
	From string `json:"from"` // "HH:MM"
	To   string `json:"to"`   // "HH:MM"
}

// NodeLimit is the limit profile in force for a node (P9b): its own, or
// else that of its first group (by name) with a profile.
type NodeLimit struct {
	NodeID    string `json:"node_id"`
	VirtualIP string `json:"virtual_ip"`
	ProfileID string `json:"profile_id"`
	GroupID   string `json:"group_id,omitempty"` // set when inherited from a group
}
