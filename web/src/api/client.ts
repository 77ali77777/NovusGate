import axios, { type AxiosError, type AxiosInstance } from 'axios'
import type {
  AllowIPRequest,
  AuditEntry,
  BlockIPRequest,
  ClosePortRequest,
  ClosePortResponse,
  CreateNetworkForm,
  CreateServerRequest,
  CreateServerResponse,
  DeleteRuleRequest,
  DeleteRuleResponse,
  Fail2BanBanResponse,
  Fail2BanHistory,
  Fail2BanJailSettings,
  Fail2BanLogs,
  Fail2BanPing,
  Fail2BanReload,
  Fail2BanStatus,
  Fail2BanUpdateSettings,
  Fail2BanWhitelist,
  FirewallPolicyMatrix,
  FirewallStatus,
  FirewallV2Change,
  FirewallV2ForwardRequest,
  FirewallV2HistoryEntry,
  FirewallV2IPRuleRequest,
  FirewallV2Live,
  FirewallV2Preview,
  FirewallV2ServiceRequest,
  FirewallV2State,
  ImportRulesRequest,
  IPRuleResponse,
  LimitProfile,
  LimitProfileRequest,
  LimitProfilesResponse,
  MeResponse,
  Network,
  Node,
  NodeGroup,
  NodeGroupsResponse,
  OpenPortRequest,
  OpenPortResponse,
  PanelUser,
  PermanentBans,
  SessionInfo,
  StatsOverview,
  StatusMessage,
  SystemInfo,
  UserRole,
  VPNFirewallRule,
  VPNFirewallRuleRequest,
} from '@/types'

// Audit log page size (GET /audit allows up to 500).
const AUDIT_PAGE = 100

class ApiClient {
  private client: AxiosInstance

  constructor() {
    // Same origin: the panel's nginx proxies /api and adds the API key
    // (Vite's dev server proxies /api to localhost:8080).
    this.client = axios.create({
      baseURL: '/api/v1',
      headers: {
        'Content-Type': 'application/json',
      },
    })

    // Add auth interceptor
    this.client.interceptors.request.use((config) => {
      const token = localStorage.getItem('auth_token')
      if (token) {
        config.headers.Authorization = `Bearer ${token}`
      }
      return config
    })

    // Add error interceptor
    this.client.interceptors.response.use(
      (response) => response,
      (error: AxiosError) => {
        if (error.response?.status === 401) {
          localStorage.removeItem('auth_token')
          window.location.href = '/login'
        }
        return Promise.reject(error)
      }
    )
  }

  // Networks
  async getNetworks(): Promise<Network[]> {
    const { data } = await this.client.get<Network[]>('/networks')
    return data
  }

  async getNetwork(id: string): Promise<Network> {
    const { data } = await this.client.get<Network>(`/networks/${id}`)
    return data
  }

  async createNetwork(network: CreateNetworkForm): Promise<Network> {
    const { data } = await this.client.post<Network>('/networks', network)
    return data
  }

  async deleteNetwork(id: string): Promise<void> {
    await this.client.delete(`/networks/${id}`)
  }

  // Nodes
  async getNodes(networkId: string): Promise<Node[]> {
    const { data } = await this.client.get<Node[]>(`/networks/${networkId}/nodes`)
    return data
  }

  async getNode(id: string): Promise<Node> {
    const { data } = await this.client.get<Node>(`/nodes/${id}`)
    return data
  }

  async deleteNode(id: string): Promise<void> {
    await this.client.delete(`/nodes/${id}`)
  }

  async updateNode(
    id: string,
    data: {
      name?: string
      expires_at?: string | null
      status?: string
      node_info?: { os: string; arch: string; hostname: string }
    }
  ): Promise<Node> {
    const { data: res } = await this.client.put<Node>(`/nodes/${id}`, data)
    return res
  }

  async createServerWithConfig(
    networkId: string,
    data: CreateServerRequest
  ): Promise<CreateServerResponse> {
    const { data: res } = await this.client.post<CreateServerResponse>(
      `/networks/${networkId}/servers`,
      data
    )
    return res
  }

  async getNodeConfig(nodeId: string): Promise<string> {
    const { data } = await this.client.get(`/nodes/${nodeId}/config`, {
      responseType: 'text',
    })
    return data
  }

  // Each call issues a new one-time enrollment token inside the script.
  async getNodeInstallScript(nodeId: string): Promise<string> {
    const { data } = await this.client.get(`/nodes/${nodeId}/install.sh`, {
      responseType: 'text',
    })
    return data
  }

  async getNodeQrCode(nodeId: string): Promise<Blob> {
    const { data } = await this.client.get(`/nodes/${nodeId}/qrcode`, {
      responseType: 'blob',
    })
    return data
  }

  async logout(): Promise<void> {
    await this.client.post('/auth/logout')
  }

  // User Management
  // Changes the logged-in user's password; the server takes the user from the session.
  async updatePassword(oldPass: string, newPass: string): Promise<void> {
    await this.client.put('/auth/password', {
      oldPassword: oldPass,
      newPassword: newPass,
    })
  }

  async getUsers(): Promise<PanelUser[]> {
    const { data } = await this.client.get<PanelUser[]>('/users')
    return data
  }

  async createUser(username: string, password: string, role?: UserRole): Promise<PanelUser> {
    const { data } = await this.client.post<PanelUser>('/users', { username, password, role })
    return data
  }

  // Panel roles (P9a)
  async getMe(): Promise<MeResponse> {
    const { data } = await this.client.get<MeResponse>('/auth/me')
    return data
  }

  async setUserRole(id: string, role: UserRole): Promise<void> {
    await this.client.put(`/users/${id}/role`, { role })
  }

  // Node groups (P9a)
  async getGroups(): Promise<NodeGroupsResponse> {
    const { data } = await this.client.get<NodeGroupsResponse>('/groups')
    return data
  }

  async createGroup(req: { name: string; description: string }): Promise<NodeGroup> {
    const { data } = await this.client.post<NodeGroup>('/groups', req)
    return data
  }

  async updateGroup(id: string, req: { name: string; description: string }): Promise<NodeGroup> {
    const { data } = await this.client.put<NodeGroup>(`/groups/${id}`, req)
    return data
  }

  async deleteGroup(id: string): Promise<void> {
    await this.client.delete(`/groups/${id}`)
  }

  async setGroupMembers(id: string, nodeIds: string[]): Promise<NodeGroup> {
    const { data } = await this.client.put<NodeGroup>(`/groups/${id}/members`, {
      node_ids: nodeIds,
    })
    return data
  }

  // Limit profiles (P9b)
  async getLimits(): Promise<LimitProfilesResponse> {
    const { data } = await this.client.get<LimitProfilesResponse>('/limits')
    return data
  }

  async createLimit(req: LimitProfileRequest): Promise<LimitProfile> {
    const { data } = await this.client.post<LimitProfile>('/limits', req)
    return data
  }

  async updateLimit(id: string, req: LimitProfileRequest): Promise<LimitProfile> {
    const { data } = await this.client.put<LimitProfile>(`/limits/${id}`, req)
    return data
  }

  // Start a node's traffic quota count again and lift its block (P9c).
  async resetQuota(nodeId: string): Promise<void> {
    await this.client.post(`/nodes/${nodeId}/quota/reset`)
  }

  async deleteLimit(id: string): Promise<void> {
    await this.client.delete(`/limits/${id}`)
  }

  async setLimitBindings(id: string, nodeIds: string[], groupIds: string[]): Promise<LimitProfile> {
    const { data } = await this.client.put<LimitProfile>(`/limits/${id}/bindings`, {
      node_ids: nodeIds,
      group_ids: groupIds,
    })
    return data
  }

  async deleteUser(id: string): Promise<void> {
    await this.client.delete(`/users/${id}`)
  }

  // Health check
  async healthCheck(): Promise<{ status: string; version: string }> {
    const { data } = await this.client.get('/health')
    return data
  }

  // System Info
  async getSystemInfo(): Promise<SystemInfo> {
    const { data } = await this.client.get('/system/info')
    return data
  }

  // Fail2Ban
  async getFail2BanStatus(): Promise<Fail2BanStatus> {
    const { data } = await this.client.get('/system/fail2ban/status')
    return data
  }

  async getFail2BanLogs(lines: number = 100): Promise<Fail2BanLogs> {
    const { data } = await this.client.get(`/system/fail2ban/logs?lines=${lines}`)
    return data
  }

  async unbanIP(jail: string, ip: string): Promise<void> {
    await this.client.post('/system/fail2ban/unban', { jail, ip })
  }

  // Fail2Ban - Manual Ban
  async banIP(jail: string, ip: string, permanent: boolean = false): Promise<Fail2BanBanResponse> {
    const { data } = await this.client.post<Fail2BanBanResponse>('/system/fail2ban/ban', {
      jail,
      ip,
      permanent,
    })
    return data
  }

  // Fail2Ban - Jail Settings
  async getJailSettings(jail: string = 'sshd'): Promise<Fail2BanJailSettings> {
    const { data } = await this.client.get<Fail2BanJailSettings>(
      `/system/fail2ban/jail/settings?jail=${jail}`
    )
    return data
  }

  async updateJailSettings(
    jail: string,
    settings: { bantime?: string; maxretry?: string; findtime?: string }
  ): Promise<Fail2BanUpdateSettings> {
    const { data } = await this.client.put<Fail2BanUpdateSettings>(
      '/system/fail2ban/jail/settings',
      { jail, ...settings }
    )
    return data
  }

  // Fail2Ban - Whitelist
  async getWhitelist(jail: string = 'sshd'): Promise<Fail2BanWhitelist> {
    const { data } = await this.client.get<Fail2BanWhitelist>(
      `/system/fail2ban/whitelist?jail=${jail}`
    )
    return data
  }

  async updateWhitelist(
    jail: string,
    action: 'add' | 'remove',
    ip: string
  ): Promise<StatusMessage> {
    const { data } = await this.client.put<StatusMessage>('/system/fail2ban/whitelist', {
      jail,
      action,
      ip,
    })
    return data
  }

  // Fail2Ban - Permanent Bans (iptables)
  async getPermanentBans(): Promise<PermanentBans> {
    const { data } = await this.client.get<PermanentBans>('/system/fail2ban/permanent-bans')
    return data
  }

  async removePermanentBan(ip: string): Promise<StatusMessage> {
    const { data } = await this.client.delete<StatusMessage>('/system/fail2ban/permanent-bans', {
      data: { ip },
    })
    return data
  }

  // Fail2Ban - Jail Control
  async controlJail(jail: string, action: 'start' | 'stop'): Promise<StatusMessage> {
    const { data } = await this.client.post<StatusMessage>('/system/fail2ban/jail/control', {
      jail,
      action,
    })
    return data
  }

  // Fail2Ban - Reload
  async reloadFail2Ban(jail?: string): Promise<Fail2BanReload> {
    const url = jail ? `/system/fail2ban/reload?jail=${jail}` : '/system/fail2ban/reload'
    const { data } = await this.client.post<Fail2BanReload>(url)
    return data
  }

  // Fail2Ban - Ping (health check)
  async pingFail2Ban(): Promise<Fail2BanPing> {
    const { data } = await this.client.get<Fail2BanPing>('/system/fail2ban/ping')
    return data
  }

  // Fail2Ban - Ban History
  async getBanHistory(jail?: string, limit: number = 100): Promise<Fail2BanHistory> {
    let url = `/system/fail2ban/ban-history?limit=${limit}`
    if (jail) url += `&jail=${jail}`
    const { data } = await this.client.get<Fail2BanHistory>(url)
    return data
  }

  // Stats Overview (all networks)
  async getStatsOverview(): Promise<StatsOverview> {
    const { data } = await this.client.get('/stats/overview')
    return data
  }

  // =====================
  // Host Firewall Methods
  // =====================

  // Get all iptables rules (optionally filtered by chain)
  async getFirewallRules(chain?: string): Promise<FirewallStatus> {
    const params = chain ? { chain } : {}
    const { data } = await this.client.get<FirewallStatus>('/firewall/host/rules', { params })
    return data
  }

  // Open a port in the firewall
  async openPort(request: OpenPortRequest): Promise<OpenPortResponse> {
    const { data } = await this.client.post<OpenPortResponse>('/firewall/host/port/open', request)
    return data
  }

  // Close a port in the firewall
  async closePort(request: ClosePortRequest): Promise<ClosePortResponse> {
    const { data } = await this.client.post<ClosePortResponse>('/firewall/host/port/close', request)
    return data
  }

  // Block an IP address
  async blockIP(request: BlockIPRequest): Promise<IPRuleResponse> {
    const { data } = await this.client.post<IPRuleResponse>('/firewall/host/ip/block', request)
    return data
  }

  // Allow an IP address
  async allowIP(request: AllowIPRequest): Promise<IPRuleResponse> {
    const { data } = await this.client.post<IPRuleResponse>('/firewall/host/ip/allow', request)
    return data
  }

  // Delete a firewall rule
  async deleteFirewallRule(request: DeleteRuleRequest): Promise<DeleteRuleResponse> {
    const { data } = await this.client.post<DeleteRuleResponse>(
      '/firewall/host/rules/delete',
      request
    )
    return data
  }

  // Export firewall rules (iptables-save format)
  async exportFirewallRules(): Promise<string> {
    const { data } = await this.client.get('/firewall/host/export', {
      responseType: 'text',
    })
    return data
  }

  // Import firewall rules (iptables-restore format)
  async importFirewallRules(request: ImportRulesRequest): Promise<StatusMessage> {
    const { data } = await this.client.post<StatusMessage>('/firewall/host/import', request)
    return data
  }

  // Reset firewall to default NovusGate configuration
  async resetFirewall(): Promise<StatusMessage> {
    const { data } = await this.client.post<StatusMessage>('/firewall/host/reset')
    return data
  }

  // ====================
  // VPN Firewall Methods
  // ====================

  // Get all VPN firewall rules
  async getAuditLog(cursor?: AuditCursor): Promise<{ entries: AuditEntry[] }> {
    const { data } = await this.client.get<{ entries: AuditEntry[] }>('/audit', {
      params: { limit: AUDIT_PAGE, before: cursor?.before, before_id: cursor?.beforeId },
    })
    return data
  }

  async getSessions(): Promise<{ sessions: SessionInfo[] }> {
    const { data } = await this.client.get<{ sessions: SessionInfo[] }>('/auth/sessions')
    return data
  }

  async deleteSession(id: string): Promise<void> {
    await this.client.delete(`/auth/sessions/${id}`)
  }

  async getFirewallPolicyMatrix(): Promise<FirewallPolicyMatrix> {
    const { data } = await this.client.get<FirewallPolicyMatrix>('/firewall/policy-matrix')
    return data
  }

  async getVPNFirewallRules(): Promise<VPNFirewallRule[]> {
    const { data } = await this.client.get<VPNFirewallRule[]>('/firewall/vpn/rules')
    return data
  }

  // Create a VPN firewall rule
  async createVPNFirewallRule(request: VPNFirewallRuleRequest): Promise<VPNFirewallRule> {
    const { data } = await this.client.post<VPNFirewallRule>('/firewall/vpn/rules', request)
    return data
  }

  // Update a VPN firewall rule
  async updateVPNFirewallRule(
    id: string,
    request: VPNFirewallRuleRequest
  ): Promise<VPNFirewallRule> {
    const { data } = await this.client.put<VPNFirewallRule>(`/firewall/vpn/rules/${id}`, request)
    return data
  }

  // Delete a VPN firewall rule
  async deleteVPNFirewallRule(id: string): Promise<void> {
    await this.client.delete(`/firewall/vpn/rules/${id}`)
  }

  // Apply all VPN firewall rules to iptables
  async applyVPNFirewallRules(): Promise<StatusMessage> {
    const { data } = await this.client.post<StatusMessage>('/firewall/vpn/apply')
    return data
  }

  // Manual backups (P8): database dump + WireGuard configs, kept on the server.
  async listBackups(): Promise<{ backups: BackupInfo[] }> {
    const { data } = await this.client.get('/backups')
    return data
  }

  async createBackup(): Promise<BackupInfo> {
    const { data } = await this.client.post<BackupInfo>('/backups')
    return data
  }

  async deleteBackup(name: string): Promise<void> {
    await this.client.delete(`/backups/${encodeURIComponent(name)}`)
  }

  async downloadBackup(name: string): Promise<Blob> {
    const { data } = await this.client.get(`/backups/${encodeURIComponent(name)}`, {
      responseType: 'blob',
    })
    return data
  }

  // DNS servers of a network's client configs (P10a); '' is the default.
  async setNetworkDNS(id: string, clientDNS: string): Promise<Network> {
    const { data } = await this.client.put<Network>(`/networks/${id}/dns`, {
      client_dns: clientDNS,
    })
    return data
  }

  // Server administration (P10a). Changes answer 403 step_up_required until
  // stepUp has checked the password again (5 minutes).
  async stepUp(password: string): Promise<void> {
    await this.client.post('/auth/step-up', { password })
  }

  async getServerServices(): Promise<ServiceStatus[]> {
    const { data } = await this.client.get<{ services: ServiceStatus[] | null }>('/server/services')
    return data.services ?? []
  }

  async restartServerService(unit: string): Promise<void> {
    await this.client.post(`/server/services/${encodeURIComponent(unit)}/restart`)
  }

  async getSysctl(): Promise<SysctlSettings> {
    const { data } = await this.client.get<SysctlSettings>('/server/sysctl')
    return data
  }

  async setSysctl(values: Record<string, string>): Promise<SysctlChange> {
    const { data } = await this.client.put<SysctlChange>('/server/sysctl', { values })
    return data
  }

  async confirmSysctl(): Promise<void> {
    await this.client.post('/server/sysctl/confirm')
  }

  async getHostSystem(): Promise<HostSystem> {
    const { data } = await this.client.get<HostSystem>('/server/system')
    return data
  }

  async setHostname(hostname: string): Promise<HostSystem> {
    const { data } = await this.client.put<HostSystem>('/server/system/hostname', { hostname })
    return data
  }

  async setTimezone(timezone: string, ntp: boolean): Promise<HostSystem> {
    const { data } = await this.client.put<HostSystem>('/server/system/timezone', {
      timezone,
      ntp,
    })
    return data
  }

  async getUpgradablePackages(): Promise<UpgradablePackage[]> {
    const { data } = await this.client.get<{ packages: UpgradablePackage[] | null }>(
      '/server/packages'
    )
    return data.packages ?? []
  }

  async getUpgradeJob(): Promise<UpgradeJob> {
    const { data } = await this.client.get<UpgradeJob>('/server/packages/upgrade')
    return data
  }

  async startUpgrade(): Promise<void> {
    await this.client.post('/server/packages/upgrade', { confirm: 'upgrade' })
  }

  async rebootServer(): Promise<void> {
    await this.client.post('/server/reboot', { confirm: 'reboot' })
  }

  async getHostNetwork(): Promise<HostNetwork> {
    const { data } = await this.client.get<HostNetwork>('/server/network')
    return data
  }

  // Telegram notifications (P8).
  async getNotificationSettings(): Promise<NotificationSettings> {
    const { data } = await this.client.get<NotificationSettings>('/notifications/settings')
    return data
  }

  async updateNotificationSettings(
    req: NotificationSettingsRequest
  ): Promise<NotificationSettings> {
    const { data } = await this.client.put<NotificationSettings>('/notifications/settings', req)
    return data
  }

  async testNotification(): Promise<void> {
    await this.client.post('/notifications/test')
  }

  // Traffic history of a node: bytes per interval over the range.
  async getNodeTraffic(
    id: string,
    range: TrafficRange
  ): Promise<{
    node_id: string
    range: TrafficRange
    bucket_seconds: number
    points: TrafficPoint[]
  }> {
    const { data } = await this.client.get(`/nodes/${id}/traffic`, { params: { range } })
    return data
  }

  // Firewall v2 (nftables engine). Changes wait for /confirm unless confirmed
  // within the deadline the response carries; otherwise the host rolls back.
  async getFirewallV2State(): Promise<FirewallV2State> {
    const { data } = await this.client.get<FirewallV2State>('/firewall/v2/state')
    return data
  }

  async getFirewallV2Preview(): Promise<FirewallV2Preview> {
    const { data } = await this.client.get<FirewallV2Preview>('/firewall/v2/preview')
    return data
  }

  async getFirewallV2Live(): Promise<FirewallV2Live> {
    const { data } = await this.client.get<FirewallV2Live>('/firewall/v2/live')
    return data
  }

  async getFirewallV2History(): Promise<{ entries: FirewallV2HistoryEntry[] }> {
    const { data } = await this.client.get<{ entries: FirewallV2HistoryEntry[] }>(
      '/firewall/v2/history'
    )
    return data
  }

  async restoreFirewallV2History(id: string): Promise<FirewallV2Change> {
    const { data } = await this.client.post<FirewallV2Change>(`/firewall/v2/history/${id}/restore`)
    return data
  }

  async createFirewallV2Service(req: FirewallV2ServiceRequest): Promise<FirewallV2Change> {
    const { data } = await this.client.post<FirewallV2Change>('/firewall/v2/services', req)
    return data
  }

  async deleteFirewallV2Service(id: string): Promise<FirewallV2Change> {
    const { data } = await this.client.delete<FirewallV2Change>(`/firewall/v2/services/${id}`)
    return data
  }

  async createFirewallV2IPRule(req: FirewallV2IPRuleRequest): Promise<FirewallV2Change> {
    const { data } = await this.client.post<FirewallV2Change>('/firewall/v2/ip-rules', req)
    return data
  }

  async deleteFirewallV2IPRule(id: string): Promise<FirewallV2Change> {
    const { data } = await this.client.delete<FirewallV2Change>(`/firewall/v2/ip-rules/${id}`)
    return data
  }

  async createFirewallV2Forward(req: FirewallV2ForwardRequest): Promise<FirewallV2Change> {
    const { data } = await this.client.post<FirewallV2Change>('/firewall/v2/forwards', req)
    return data
  }

  async deleteFirewallV2Forward(id: string): Promise<FirewallV2Change> {
    const { data } = await this.client.delete<FirewallV2Change>(`/firewall/v2/forwards/${id}`)
    return data
  }

  async setFirewallV2Egress(nodeId: string, enabled: boolean): Promise<FirewallV2Change> {
    const url = `/firewall/v2/egress/${nodeId}`
    const { data } = enabled
      ? await this.client.put<FirewallV2Change>(url)
      : await this.client.delete<FirewallV2Change>(url)
    return data
  }

  async confirmFirewallV2(id: string): Promise<{ status: string }> {
    const { data } = await this.client.post<{ status: string }>(`/firewall/v2/confirm/${id}`)
    return data
  }
}

export const api = new ApiClient()

// React Query hooks
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { type AuditCursor, nextBefore } from '@/lib/audit'
import { engineState, retryFirewallV2 } from '@/lib/firewallV2'
import type { NotificationSettingsRequest } from '@/lib/notifications'
import { roleAtLeast } from '@/lib/roles'
import type { TrafficPoint, TrafficRange } from '@/lib/traffic'
import type {
  BackupInfo,
  HostNetwork,
  HostSystem,
  NotificationSettings,
  ServiceStatus,
  SysctlChange,
  SysctlSettings,
  UpgradablePackage,
  UpgradeJob,
} from '@/types'

// Export hooks

// Network hooks
export function useNetworks() {
  return useQuery({
    queryKey: ['networks'],
    queryFn: () => api.getNetworks(),
  })
}

export function useNetwork(id: string) {
  return useQuery({
    queryKey: ['networks', id],
    queryFn: () => api.getNetwork(id),
    enabled: !!id,
  })
}

export function useCreateNetwork() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { inlineError: true, successTitle: 'toasts:networkCreated' },
    mutationFn: (data: CreateNetworkForm) => api.createNetwork(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['networks'] })
    },
  })
}

export function useDeleteNetwork() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'toasts:failedToDeleteNetwork', successTitle: 'toasts:networkDeleted' },
    mutationFn: (id: string) => api.deleteNetwork(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['networks'] })
    },
  })
}

// Node hooks
export function useNodes(networkId: string) {
  return useQuery({
    queryKey: ['nodes', networkId],
    queryFn: () => api.getNodes(networkId),
    enabled: !!networkId,
    refetchInterval: 30000, // Refresh every 30 seconds
  })
}

export function useNode(id: string) {
  return useQuery({
    queryKey: ['nodes', 'detail', id],
    queryFn: () => api.getNode(id),
    enabled: !!id,
  })
}

export function useBackups() {
  return useQuery({ queryKey: ['backups'], queryFn: () => api.listBackups() })
}

export function useCreateBackup() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'toasts:failedToCreateBackup', successTitle: 'toasts:backupCreated' },
    mutationFn: () => api.createBackup(),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['backups'] }),
  })
}

export function useDeleteBackup() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'toasts:failedToDeleteBackup', successTitle: 'toasts:backupDeleted' },
    mutationFn: (name: string) => api.deleteBackup(name),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['backups'] }),
  })
}

export function useNotificationSettings() {
  return useQuery({ queryKey: ['notifications'], queryFn: () => api.getNotificationSettings() })
}

export function useUpdateNotificationSettings() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: {
      errorTitle: 'toasts:failedToSaveNotificationSettings',
      successTitle: 'toasts:notificationSettingsSaved',
    },
    mutationFn: (req: NotificationSettingsRequest) => api.updateNotificationSettings(req),
    onSuccess: (data) => queryClient.setQueryData(['notifications'], data),
  })
}

export function useTestNotification() {
  return useMutation({
    meta: { errorTitle: 'toasts:testMessageNotSent', successTitle: 'toasts:testMessageSent' },
    mutationFn: () => api.testNotification(),
  })
}

export function useNodeTraffic(id: string, range: TrafficRange) {
  return useQuery({
    queryKey: ['nodes', 'traffic', id, range],
    queryFn: () => api.getNodeTraffic(id, range),
    enabled: !!id,
    refetchInterval: 5 * 60 * 1000, // a new sample every 5 minutes
  })
}

export function useDeleteNode() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'toasts:failedToDeleteNode', successTitle: 'toasts:nodeDeleted' },
    mutationFn: (id: string) => api.deleteNode(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['nodes'] })
    },
  })
}

export function useCreateServerWithConfig() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'toasts:failedToCreatePeer' },
    mutationFn: (vars: { networkId: string; data: CreateServerRequest }) =>
      api.createServerWithConfig(vars.networkId, vars.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['nodes'] })
    },
  })
}

export function useUpdateNode() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'toasts:failedToUpdateNode', successTitle: 'toasts:nodeUpdated' },
    mutationFn: (vars: {
      id: string
      data: {
        name?: string
        expires_at?: string | null
        status?: string
        node_info?: { os: string; arch: string; hostname: string }
      }
    }) => api.updateNode(vars.id, vars.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['nodes'] })
    },
  })
}

// User Management hooks
export function useUpdatePassword() {
  return useMutation({
    meta: { inlineError: true },
    mutationFn: (data: { oldPass: string; newPass: string }) =>
      api.updatePassword(data.oldPass, data.newPass),
  })
}

export function useUsers() {
  return useQuery({
    queryKey: ['users'],
    queryFn: () => api.getUsers(),
  })
}

// The signed-in user and role; the UI hides what the role cannot do (the
// backend refuses it anyway).
export function useMe() {
  return useQuery({ queryKey: ['me'], queryFn: () => api.getMe(), staleTime: 60000 })
}

// useCan reports whether the signed-in role may do what need allows.
export function useCan(need: UserRole): boolean {
  const { data } = useMe()
  return roleAtLeast(data?.role, need)
}

export function useSetUserRole() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'toasts:failedToChangeRole', successTitle: 'toasts:roleChanged' },
    mutationFn: (v: { id: string; role: UserRole }) => api.setUserRole(v.id, v.role),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      // An admin may have changed their own role.
      queryClient.invalidateQueries({ queryKey: ['me'] })
    },
  })
}

export function useGroups() {
  return useQuery({ queryKey: ['groups'], queryFn: () => api.getGroups() })
}

// Group changes also change the VPN rules that name the group.
function useGroupMutation<T>(
  fn: (v: T) => Promise<unknown>,
  errorTitle: string,
  successTitle: string
) {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle, successTitle },
    mutationFn: fn,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['groups'] })
      queryClient.invalidateQueries({ queryKey: ['firewall', 'vpn'] })
      // nft mode compiles groups into the host ruleset.
      queryClient.invalidateQueries({ queryKey: ['firewall', 'v2'] })
    },
  })
}

export const useCreateGroup = () =>
  useGroupMutation(
    (req: { name: string; description: string }) => api.createGroup(req),
    'toasts:failedToCreateGroup',
    'toasts:groupCreated'
  )
export const useUpdateGroup = () =>
  useGroupMutation(
    (v: { id: string; name: string; description: string }) =>
      api.updateGroup(v.id, { name: v.name, description: v.description }),
    'toasts:failedToUpdateGroup',
    'toasts:groupUpdated'
  )
export const useDeleteGroup = () =>
  useGroupMutation(
    (id: string) => api.deleteGroup(id),
    'toasts:failedToDeleteGroup',
    'toasts:groupDeleted'
  )
export const useSetGroupMembers = () =>
  useGroupMutation(
    (v: { id: string; nodeIds: string[] }) => api.setGroupMembers(v.id, v.nodeIds),
    'toasts:failedToSaveMembers',
    'toasts:membersSaved'
  )

export function useLimits() {
  return useQuery({ queryKey: ['limits'], queryFn: () => api.getLimits() })
}

// Limit changes are compiled into the host ruleset (nft mode): the firewall
// views and the matrix change with them.
function useLimitMutation<T>(
  fn: (v: T) => Promise<unknown>,
  errorTitle: string,
  successTitle: string
) {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle, successTitle },
    mutationFn: fn,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['limits'] })
      queryClient.invalidateQueries({ queryKey: ['firewall'] })
    },
  })
}

export const useCreateLimit = () =>
  useLimitMutation(
    (req: LimitProfileRequest) => api.createLimit(req),
    'toasts:failedToCreateLimit',
    'toasts:limitCreated'
  )
export const useUpdateLimit = () =>
  useLimitMutation(
    (v: { id: string; req: LimitProfileRequest }) => api.updateLimit(v.id, v.req),
    'toasts:failedToUpdateLimit',
    'toasts:limitUpdated'
  )
export const useDeleteLimit = () =>
  useLimitMutation(
    (id: string) => api.deleteLimit(id),
    'toasts:failedToDeleteLimit',
    'toasts:limitDeleted'
  )
export const useResetQuota = () =>
  useLimitMutation(
    (nodeId: string) => api.resetQuota(nodeId),
    'toasts:failedToResetQuota',
    'toasts:quotaReset'
  )
export const useSetLimitBindings = () =>
  useLimitMutation(
    (v: { id: string; nodeIds: string[]; groupIds: string[] }) =>
      api.setLimitBindings(v.id, v.nodeIds, v.groupIds),
    'toasts:failedToSaveBindings',
    'toasts:bindingsSaved'
  )

export function useCreateUser() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { inlineError: true, successTitle: 'toasts:userCreated' },
    mutationFn: (data: { username: string; password: string; role?: UserRole }) =>
      api.createUser(data.username, data.password, data.role),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
    },
  })
}

export function useDeleteUser() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'toasts:failedToDeleteUser', successTitle: 'toasts:userDeleted' },
    mutationFn: (id: string) => api.deleteUser(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
    },
  })
}

// System Info hooks
export function useSystemInfo() {
  return useQuery({
    queryKey: ['systemInfo'],
    queryFn: () => api.getSystemInfo(),
    refetchInterval: 30000, // Refresh every 30 seconds
  })
}

// Fail2Ban hooks
export function useFail2BanStatus() {
  return useQuery({
    queryKey: ['fail2ban', 'status'],
    queryFn: () => api.getFail2BanStatus(),
    refetchInterval: 30000,
  })
}

export function useFail2BanLogs(lines: number = 100) {
  return useQuery({
    queryKey: ['fail2ban', 'logs', lines],
    queryFn: () => api.getFail2BanLogs(lines),
  })
}

export function useUnbanIP() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'toasts:failedToUnbanIp', successTitle: 'toasts:ipUnbanned' },
    mutationFn: (data: { jail: string; ip: string }) => api.unbanIP(data.jail, data.ip),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fail2ban'] })
    },
  })
}

// Stats Overview hook
export function useStatsOverview() {
  return useQuery({
    queryKey: ['stats', 'overview'],
    queryFn: () => api.getStatsOverview(),
    refetchInterval: 30000,
  })
}

// =====================
// Host Firewall Hooks
// =====================

export function useFirewallRules(chain?: string) {
  return useQuery({
    queryKey: ['firewall', 'host', 'rules', chain],
    queryFn: () => api.getFirewallRules(chain),
    refetchInterval: 30000,
  })
}

export function useOpenPort() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'toasts:failedToOpenPort', successTitle: 'toasts:portOpened' },
    mutationFn: (request: OpenPortRequest) => api.openPort(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'host'] })
    },
  })
}

export function useClosePort() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'toasts:failedToClosePort', successTitle: 'toasts:portClosed' },
    mutationFn: (request: ClosePortRequest) => api.closePort(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'host'] })
    },
  })
}

export function useBlockIP() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'toasts:failedToBlockIp', successTitle: 'toasts:ipBlocked' },
    mutationFn: (request: BlockIPRequest) => api.blockIP(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'host'] })
    },
  })
}

export function useAllowIP() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'toasts:failedToAllowIp', successTitle: 'toasts:ipAllowed' },
    mutationFn: (request: AllowIPRequest) => api.allowIP(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'host'] })
    },
  })
}

export function useDeleteFirewallRule() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'toasts:failedToDeleteRule', successTitle: 'toasts:ruleDeleted' },
    mutationFn: (request: DeleteRuleRequest) => api.deleteFirewallRule(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'host'] })
    },
  })
}

export function useImportFirewallRules() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'toasts:failedToImportRules', successTitle: 'toasts:rulesImported' },
    mutationFn: (request: ImportRulesRequest) => api.importFirewallRules(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'host'] })
    },
  })
}

export function useResetFirewall() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'toasts:failedToResetFirewall', successTitle: 'toasts:firewallReset' },
    mutationFn: () => api.resetFirewall(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'host'] })
    },
  })
}

// ====================
// VPN Firewall Hooks
// ====================

// Audit log, newest first, one page of AUDIT_PAGE entries at a time.
export function useAuditLog() {
  return useInfiniteQuery({
    queryKey: ['audit'],
    queryFn: ({ pageParam }) => api.getAuditLog(pageParam),
    initialPageParam: undefined as AuditCursor | undefined,
    getNextPageParam: (last) => nextBefore(last.entries, AUDIT_PAGE),
  })
}

export function useSessions() {
  return useQuery({
    queryKey: ['sessions'],
    queryFn: () => api.getSessions(),
    refetchInterval: 60000,
  })
}

export function useDeleteSession() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'toasts:failedToEndSession', successTitle: 'toasts:sessionEnded' },
    mutationFn: (id: string) => api.deleteSession(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['sessions'] }),
  })
}

// Network policy matrix; VPN rule changes invalidate ['firewall', 'vpn'].
export function useFirewallPolicyMatrix(enabled: boolean) {
  return useQuery({
    queryKey: ['firewall', 'vpn', 'matrix'],
    queryFn: () => api.getFirewallPolicyMatrix(),
    enabled,
    refetchInterval: 30000,
  })
}

export function useVPNFirewallRules() {
  return useQuery({
    queryKey: ['firewall', 'vpn', 'rules'],
    queryFn: () => api.getVPNFirewallRules(),
    refetchInterval: 30000,
  })
}

export function useCreateVPNFirewallRule() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'toasts:failedToSaveVpnRule', successTitle: 'toasts:vpnRuleCreated' },
    mutationFn: (request: VPNFirewallRuleRequest) => api.createVPNFirewallRule(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'vpn'] })
    },
  })
}

export function useUpdateVPNFirewallRule() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'toasts:failedToSaveVpnRule', successTitle: 'toasts:vpnRuleUpdated' },
    mutationFn: (vars: { id: string; request: VPNFirewallRuleRequest }) =>
      api.updateVPNFirewallRule(vars.id, vars.request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'vpn'] })
    },
  })
}

export function useDeleteVPNFirewallRule() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'toasts:failedToDeleteVpnRule', successTitle: 'toasts:vpnRuleDeleted' },
    mutationFn: (id: string) => api.deleteVPNFirewallRule(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'vpn'] })
    },
  })
}

export function useApplyVPNFirewallRules() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'toasts:failedToApplyVpnRules', successTitle: 'toasts:vpnRulesApplied' },
    mutationFn: () => api.applyVPNFirewallRules(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'vpn'] })
    },
  })
}

// Firewall v2 (nftables). The state refreshes every 5 s while a change waits
// for confirmation, so the countdown and the rollback show without a reload.
export function useFirewallV2State(enabled = true) {
  return useQuery({
    queryKey: ['firewall', 'v2', 'state'],
    queryFn: () => api.getFirewallV2State(),
    enabled,
    retry: retryFirewallV2,
    // With the engine off (iptables mode) there is nothing to poll for.
    refetchInterval: (query) =>
      query.state.error && engineState(query.state.error) === 'disabled'
        ? false
        : query.state.data?.pending
          ? 5000
          : 30000,
  })
}

export function useFirewallV2Preview(enabled: boolean) {
  return useQuery({
    queryKey: ['firewall', 'v2', 'preview'],
    queryFn: () => api.getFirewallV2Preview(),
    enabled,
    retry: retryFirewallV2,
  })
}

// Live view: refreshed every 10 s while the tab is open.
export function useFirewallV2Live() {
  return useQuery({
    queryKey: ['firewall', 'v2', 'live'],
    queryFn: () => api.getFirewallV2Live(),
    refetchInterval: 10000,
  })
}

export function useFirewallV2History() {
  return useQuery({
    queryKey: ['firewall', 'v2', 'history'],
    queryFn: () => api.getFirewallV2History(),
    retry: retryFirewallV2,
  })
}

function useFirewallV2Mutation<T>(fn: (vars: T) => Promise<unknown>, errorTitle: string) {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle },
    mutationFn: fn,
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall'] })
    },
  })
}

export const useCreateFirewallV2Service = () =>
  useFirewallV2Mutation(
    (req: FirewallV2ServiceRequest) => api.createFirewallV2Service(req),
    'toasts:failedToOpenService'
  )
export const useDeleteFirewallV2Service = () =>
  useFirewallV2Mutation(
    (id: string) => api.deleteFirewallV2Service(id),
    'toasts:failedToRemoveService'
  )
export const useCreateFirewallV2IPRule = () =>
  useFirewallV2Mutation(
    (req: FirewallV2IPRuleRequest) => api.createFirewallV2IPRule(req),
    'toasts:failedToAddIpRule'
  )
export const useDeleteFirewallV2IPRule = () =>
  useFirewallV2Mutation(
    (id: string) => api.deleteFirewallV2IPRule(id),
    'toasts:failedToRemoveIpRule'
  )
export const useCreateFirewallV2Forward = () =>
  useFirewallV2Mutation(
    (req: FirewallV2ForwardRequest) => api.createFirewallV2Forward(req),
    'toasts:failedToAddPortForward'
  )
export const useDeleteFirewallV2Forward = () =>
  useFirewallV2Mutation(
    (id: string) => api.deleteFirewallV2Forward(id),
    'toasts:failedToRemovePortForward'
  )
export const useSetFirewallV2Egress = () =>
  useFirewallV2Mutation(
    (v: { nodeId: string; enabled: boolean }) => api.setFirewallV2Egress(v.nodeId, v.enabled),
    'toasts:failedToChangeFullTunnel'
  )
export const useConfirmFirewallV2 = () =>
  useFirewallV2Mutation((id: string) => api.confirmFirewallV2(id), 'toasts:failedToConfirmChange')
export const useRestoreFirewallV2History = () =>
  useFirewallV2Mutation(
    (id: string) => api.restoreFirewallV2History(id),
    'toasts:failedToRestoreFirewallState'
  )

// Network client DNS (P10a).
export function useSetNetworkDNS() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'toasts:failedToSaveDns', successTitle: 'toasts:dnsSaved' },
    mutationFn: (v: { id: string; clientDNS: string }) => api.setNetworkDNS(v.id, v.clientDNS),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['networks'] }),
  })
}

// Server administration (P10a, admin only). The mutations take a function
// that runs the change through withStepUp (pages/Server), so the password
// prompt can sit between the 403 and the retry.
export function useServerServices() {
  return useQuery({
    queryKey: ['server', 'services'],
    queryFn: () => api.getServerServices(),
    refetchInterval: 15000,
  })
}

export function useSysctl() {
  return useQuery({ queryKey: ['server', 'sysctl'], queryFn: () => api.getSysctl() })
}

export function useHostSystem() {
  return useQuery({ queryKey: ['server', 'system'], queryFn: () => api.getHostSystem() })
}

export function useUpgradablePackages() {
  return useQuery({
    queryKey: ['server', 'packages'],
    queryFn: () => api.getUpgradablePackages(),
  })
}

// The last upgrade; polled while one runs.
export function useUpgradeJob() {
  return useQuery({
    queryKey: ['server', 'upgrade'],
    queryFn: () => api.getUpgradeJob(),
    refetchInterval: (query) => (query.state.data?.running ? 2000 : false),
  })
}

export function useHostNetwork() {
  return useQuery({ queryKey: ['server', 'network'], queryFn: () => api.getHostNetwork() })
}

export function useServerChange<T>(errorTitle: string, successTitle?: string) {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle, successTitle },
    mutationFn: (run: () => Promise<T>) => run(),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['server'] }),
  })
}
