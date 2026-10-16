// API types are generated from the backend's OpenAPI document
// (npm run gen:api -> src/api/openapi.d.ts); only frontend-only types are
// written here.
import type { components } from '@/api/openapi'

type S = components['schemas']

// Network types (Hub-and-Spoke VPN)
export type Network = S['Network']

// Node types (Peers/Spokes)
export type NodeStatus = S['Node']['status']

export type NodeInfo = S['NodeInfo']

export type Node = S['Node']

// API response types
export interface ApiError {
  error: string
}

export interface PaginatedResponse<T> {
  data: T[]
  total: number
  page: number
  per_page: number
}

// Dashboard specific types
export type NetworkStats = S['NetworkStats']

export interface NetworkTopology {
  nodes: TopologyNode[]
  edges: TopologyEdge[]
}

export interface TopologyNode {
  id: string
  type: 'node'
  position: { x: number; y: number }
  data: {
    label: string
    status: NodeStatus
    ip: string
  }
}

export interface TopologyEdge {
  id: string
  source: string
  target: string
  data?: {
    latency?: number
    connected: boolean
  }
}

// WebSocket event types
export type EventType = 'node_status' | 'peer_added' | 'peer_removed'

export interface WebSocketEvent {
  type: EventType
  payload: Record<string, unknown>
  timestamp: string
}

export interface NodeStatusEvent {
  type: 'node_status'
  node_id: string
  status: NodeStatus
  timestamp: string
}

// Form types
export interface CreateNetworkForm {
  name: string
  cidr: string
  tunnel_mode?: 'split' | 'full'
}

// The item of a tunnel change (PUT /networks/{id}/tunnel, /nodes/{id}/tunnel).
// affected_nodes: nodes that switch between split and full; each needs its
// config downloaded again.
export interface TunnelChangeItem {
  network_id?: string
  node_id?: string
  tunnel_mode?: string
  tunnel_override: string
  affected_nodes: number
}
export type TunnelChange = Omit<FirewallV2Change, 'item'> & { item: TunnelChangeItem }

export interface CreateNodeForm {
  name: string
  labels?: Record<string, string>
}

// System Info types
export type SystemInfo = S['SystemInfoResponse']

// Fail2Ban types
export type Fail2BanJail = S['Fail2BanJail']

export type Fail2BanStatus = S['Fail2BanStatusResponse']

export type Fail2BanLogEntry = S['Fail2BanLogEntry']

export type Fail2BanLogs = S['Fail2BanLogsResponse']

export type Fail2BanBanResponse = S['Fail2BanBanResponse']

export type Fail2BanHistoryEntry = S['Fail2BanHistoryEntry']

export type Fail2BanHistory = S['Fail2BanHistoryResponse']

export type Fail2BanJailSettings = S['Fail2BanJailSettingsResponse']

export type Fail2BanUpdateSettings = S['Fail2BanUpdateSettingsResponse']

export type Fail2BanWhitelist = S['Fail2BanWhitelistResponse']

export type PermanentBans = S['PermanentBansResponse']

export type Fail2BanPing = S['Fail2BanPingResponse']

export type Fail2BanReload = S['Fail2BanReloadResponse']

// Generic { status, message } answer of several write endpoints.
export type StatusMessage = S['StatusMessageResponse']

export type StatsOverview = S['StatsOverviewResponse']

// Firewall types
export type FirewallRule = S['FirewallRule']

export type ChainInfo = S['ChainInfo']

export type FirewallStatus = S['FirewallStatus']

export type OpenPortRequest = S['OpenPortRequest']

export type ClosePortRequest = S['ClosePortRequest']

export type BlockIPRequest = S['BlockIPRequest']

export type AllowIPRequest = S['AllowIPRequest']

export type DeleteRuleRequest = S['DeleteRuleRequest']

export type ImportRulesRequest = S['ImportRulesRequest']

export type OpenPortResponse = S['OpenPortResponse']

export type ClosePortResponse = S['ClosePortResponse']

export type IPRuleResponse = S['IPRuleResponse']

export type DeleteRuleResponse = S['DeleteRuleResponse']

export type CreateServerRequest = S['CreateServerRequest']

export type CreateServerResponse = S['CreateServerResponse']

// VPN Firewall types
export type VPNEndpointType = 'any' | 'network' | 'node' | 'group' | 'custom'
export type VPNFirewallAction = 'accept' | 'drop' | 'reject'
export type VPNFirewallProtocol = 'tcp' | 'udp' | 'icmp' | 'all'

export type VPNFirewallRule = S['VPNFirewallRule']

export type VPNFirewallRuleRequest = S['VPNFirewallRuleRequest']

// Node groups and panel roles (P9a)
export type NodeGroup = S['NodeGroup']
export type NodeGroupMember = S['NodeGroupMember']
export type NodeGroupsResponse = S['NodeGroupsResponse']
export type MeResponse = S['MeResponse']
export type PanelUser = S['User']
export type UserRole = 'admin' | 'operator' | 'viewer'

// Limit profiles (P9b)
export type LimitProfile = S['LimitProfile']
export type LimitProfileRequest = S['LimitProfileRequest']
export type LimitProfilesResponse = S['LimitProfilesResponse']
export type NodeLimit = S['NodeLimit']
export type ScheduleWindow = S['ScheduleWindow']
export type NodeQuotaState = S['NodeQuotaState']

// Manual backup (P8): /api/v1/backups
export type BackupInfo = S['Info']

// Telegram notifications (P8). The bot token is never returned; token_set
// says whether one is stored.
export type NotificationSettings = S['NotificationSettings']

// Firewall v2 (nftables engine, /api/v1/firewall/v2/*)
export type FirewallEngineMode = S['V2StateResponse']['mode']

export type FirewallV2Service = S['FirewallService']

export type FirewallV2IPRule = S['FirewallIPRule']

export type FirewallV2Forward = S['FirewallForward']

export type FirewallV2Pending = S['PendingChange']

export type FirewallV2State = S['V2StateResponse']

export type FirewallV2Change = S['V2ChangeResponse']

export type FirewallV2Preview = S['V2PreviewResponse']

// GET /firewall/v2/live: counters and dropped come from the nftables table
// (empty when it is not loaded, e.g. in iptables mode); conntrack always.
export type FirewallV2RuleCounter = S['RuleCounter']

export type FirewallV2Live = S['V2LiveResponse']

// GET /audit: changes made through the API and login attempts.
export type AuditEntry = S['AuditEntry']

// GET /auth/sessions: unexpired login sessions; current is the caller's.
export type SessionInfo = S['SessionInfo']

// GET /firewall/policy-matrix: cells[from][to] for every pair of VPN networks,
// computed by the backend from the VPN rules and the firewall mode.
export type FirewallPolicyMatrix = S['Matrix']

// GET /firewall/v2/history: newest first; added/removed are readable lines.
export type FirewallV2HistoryEntry = S['V2HistoryEntry']

export type FirewallV2ServiceRequest = S['v2ServiceRequest']

export type FirewallV2IPRuleRequest = S['v2IPRuleRequest']

export type FirewallV2ForwardRequest = S['v2ForwardRequest']

// Server administration (P10a, admin only). Changes need a step-up.
export type ServiceStatus = S['ServiceStatus']

export type SysctlSettings = S['SysctlResponse']

export type SysctlChange = S['SysctlChangeResponse']

export type HostSystem = S['SystemInfo']

export type UpgradablePackage = S['Package']

export type UpgradeJob = S['UpgradeJob']

export type HostNetwork = S['NetworkView']
