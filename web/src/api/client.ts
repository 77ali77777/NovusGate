import axios, { type AxiosError, type AxiosInstance } from 'axios'
import type {
  AllowIPRequest,
  BlockIPRequest,
  ClosePortRequest,
  CreateNetworkForm,
  DeleteRuleRequest,
  Fail2BanLogs,
  Fail2BanStatus,
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
  Network,
  Node,
  OpenPortRequest,
  StatsOverview,
  SystemInfo,
  VPNFirewallRule,
  VPNFirewallRuleRequest,
} from '@/types'

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

  async createServerWithConfig(networkId: string, data: any): Promise<any> {
    const { data: res } = await this.client.post(`/networks/${networkId}/servers`, data)
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

  async getUsers(): Promise<any[]> {
    const { data } = await this.client.get('/users')
    return data
  }

  async createUser(username: string, password: string): Promise<any> {
    const { data } = await this.client.post('/users', { username, password })
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
  async banIP(jail: string, ip: string, permanent: boolean = false): Promise<any> {
    const { data } = await this.client.post('/system/fail2ban/ban', { jail, ip, permanent })
    return data
  }

  // Fail2Ban - Jail Settings
  async getJailSettings(jail: string = 'sshd'): Promise<any> {
    const { data } = await this.client.get(`/system/fail2ban/jail/settings?jail=${jail}`)
    return data
  }

  async updateJailSettings(
    jail: string,
    settings: { bantime?: string; maxretry?: string; findtime?: string }
  ): Promise<any> {
    const { data } = await this.client.put('/system/fail2ban/jail/settings', { jail, ...settings })
    return data
  }

  // Fail2Ban - Whitelist
  async getWhitelist(jail: string = 'sshd'): Promise<any> {
    const { data } = await this.client.get(`/system/fail2ban/whitelist?jail=${jail}`)
    return data
  }

  async updateWhitelist(jail: string, action: 'add' | 'remove', ip: string): Promise<any> {
    const { data } = await this.client.put('/system/fail2ban/whitelist', { jail, action, ip })
    return data
  }

  // Fail2Ban - Permanent Bans (iptables)
  async getPermanentBans(): Promise<any> {
    const { data } = await this.client.get('/system/fail2ban/permanent-bans')
    return data
  }

  async removePermanentBan(ip: string): Promise<any> {
    const { data } = await this.client.delete('/system/fail2ban/permanent-bans', { data: { ip } })
    return data
  }

  // Fail2Ban - Jail Control
  async controlJail(jail: string, action: 'start' | 'stop'): Promise<any> {
    const { data } = await this.client.post('/system/fail2ban/jail/control', { jail, action })
    return data
  }

  // Fail2Ban - Reload
  async reloadFail2Ban(jail?: string): Promise<any> {
    const url = jail ? `/system/fail2ban/reload?jail=${jail}` : '/system/fail2ban/reload'
    const { data } = await this.client.post(url)
    return data
  }

  // Fail2Ban - Ping (health check)
  async pingFail2Ban(): Promise<any> {
    const { data } = await this.client.get('/system/fail2ban/ping')
    return data
  }

  // Fail2Ban - Ban History
  async getBanHistory(jail?: string, limit: number = 100): Promise<any> {
    let url = `/system/fail2ban/ban-history?limit=${limit}`
    if (jail) url += `&jail=${jail}`
    const { data } = await this.client.get(url)
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
  async openPort(request: OpenPortRequest): Promise<any> {
    const { data } = await this.client.post('/firewall/host/port/open', request)
    return data
  }

  // Close a port in the firewall
  async closePort(request: ClosePortRequest): Promise<any> {
    const { data } = await this.client.post('/firewall/host/port/close', request)
    return data
  }

  // Block an IP address
  async blockIP(request: BlockIPRequest): Promise<any> {
    const { data } = await this.client.post('/firewall/host/ip/block', request)
    return data
  }

  // Allow an IP address
  async allowIP(request: AllowIPRequest): Promise<any> {
    const { data } = await this.client.post('/firewall/host/ip/allow', request)
    return data
  }

  // Delete a firewall rule
  async deleteFirewallRule(request: DeleteRuleRequest): Promise<any> {
    const { data } = await this.client.post('/firewall/host/rules/delete', request)
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
  async importFirewallRules(request: ImportRulesRequest): Promise<any> {
    const { data } = await this.client.post('/firewall/host/import', request)
    return data
  }

  // Reset firewall to default NovusGate configuration
  async resetFirewall(): Promise<any> {
    const { data } = await this.client.post('/firewall/host/reset')
    return data
  }

  // ====================
  // VPN Firewall Methods
  // ====================

  // Get all VPN firewall rules
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
  async applyVPNFirewallRules(): Promise<any> {
    const { data } = await this.client.post('/firewall/vpn/apply')
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
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type { NotificationSettingsRequest } from '@/lib/notifications'
import type { TrafficPoint, TrafficRange } from '@/lib/traffic'
import type { BackupInfo, NotificationSettings } from '@/types'

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
    meta: { inlineError: true, successTitle: 'Network created' },
    mutationFn: (data: CreateNetworkForm) => api.createNetwork(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['networks'] })
    },
  })
}

export function useDeleteNetwork() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'Failed to delete network', successTitle: 'Network deleted' },
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
    meta: { errorTitle: 'Failed to create the backup', successTitle: 'Backup created' },
    mutationFn: () => api.createBackup(),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['backups'] }),
  })
}

export function useDeleteBackup() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'Failed to delete the backup', successTitle: 'Backup deleted' },
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
      errorTitle: 'Failed to save the notification settings',
      successTitle: 'Notification settings saved',
    },
    mutationFn: (req: NotificationSettingsRequest) => api.updateNotificationSettings(req),
    onSuccess: (data) => queryClient.setQueryData(['notifications'], data),
  })
}

export function useTestNotification() {
  return useMutation({
    meta: { errorTitle: 'Test message not sent', successTitle: 'Test message sent' },
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
    meta: { errorTitle: 'Failed to delete node', successTitle: 'Node deleted' },
    mutationFn: (id: string) => api.deleteNode(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['nodes'] })
    },
  })
}

export function useCreateServerWithConfig() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'Failed to create peer' },
    mutationFn: (vars: { networkId: string; data: any }) =>
      api.createServerWithConfig(vars.networkId, vars.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['nodes'] })
    },
  })
}

export function useUpdateNode() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'Failed to update node', successTitle: 'Node updated' },
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

export function useCreateUser() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { inlineError: true, successTitle: 'User created' },
    mutationFn: (data: { username: string; password: string }) =>
      api.createUser(data.username, data.password),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
    },
  })
}

export function useDeleteUser() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'Failed to delete user', successTitle: 'User deleted' },
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
    meta: { errorTitle: 'Failed to unban IP', successTitle: 'IP unbanned' },
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
    meta: { errorTitle: 'Failed to open port', successTitle: 'Port opened' },
    mutationFn: (request: OpenPortRequest) => api.openPort(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'host'] })
    },
  })
}

export function useClosePort() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'Failed to close port', successTitle: 'Port closed' },
    mutationFn: (request: ClosePortRequest) => api.closePort(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'host'] })
    },
  })
}

export function useBlockIP() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'Failed to block IP', successTitle: 'IP blocked' },
    mutationFn: (request: BlockIPRequest) => api.blockIP(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'host'] })
    },
  })
}

export function useAllowIP() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'Failed to allow IP', successTitle: 'IP allowed' },
    mutationFn: (request: AllowIPRequest) => api.allowIP(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'host'] })
    },
  })
}

export function useDeleteFirewallRule() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'Failed to delete rule', successTitle: 'Rule deleted' },
    mutationFn: (request: DeleteRuleRequest) => api.deleteFirewallRule(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'host'] })
    },
  })
}

export function useImportFirewallRules() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'Failed to import rules', successTitle: 'Rules imported' },
    mutationFn: (request: ImportRulesRequest) => api.importFirewallRules(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'host'] })
    },
  })
}

export function useResetFirewall() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'Failed to reset firewall', successTitle: 'Firewall reset' },
    mutationFn: () => api.resetFirewall(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'host'] })
    },
  })
}

// ====================
// VPN Firewall Hooks
// ====================

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
    meta: { errorTitle: 'Failed to save VPN rule', successTitle: 'VPN rule created' },
    mutationFn: (request: VPNFirewallRuleRequest) => api.createVPNFirewallRule(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'vpn'] })
    },
  })
}

export function useUpdateVPNFirewallRule() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'Failed to save VPN rule', successTitle: 'VPN rule updated' },
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
    meta: { errorTitle: 'Failed to delete VPN rule', successTitle: 'VPN rule deleted' },
    mutationFn: (id: string) => api.deleteVPNFirewallRule(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall', 'vpn'] })
    },
  })
}

export function useApplyVPNFirewallRules() {
  const queryClient = useQueryClient()
  return useMutation({
    meta: { errorTitle: 'Failed to apply VPN rules', successTitle: 'VPN rules applied' },
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
    refetchInterval: (query) => (query.state.data?.pending ? 5000 : 30000),
  })
}

export function useFirewallV2Preview(enabled: boolean) {
  return useQuery({
    queryKey: ['firewall', 'v2', 'preview'],
    queryFn: () => api.getFirewallV2Preview(),
    enabled,
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
    'Failed to open service'
  )
export const useDeleteFirewallV2Service = () =>
  useFirewallV2Mutation((id: string) => api.deleteFirewallV2Service(id), 'Failed to remove service')
export const useCreateFirewallV2IPRule = () =>
  useFirewallV2Mutation(
    (req: FirewallV2IPRuleRequest) => api.createFirewallV2IPRule(req),
    'Failed to add IP rule'
  )
export const useDeleteFirewallV2IPRule = () =>
  useFirewallV2Mutation((id: string) => api.deleteFirewallV2IPRule(id), 'Failed to remove IP rule')
export const useCreateFirewallV2Forward = () =>
  useFirewallV2Mutation(
    (req: FirewallV2ForwardRequest) => api.createFirewallV2Forward(req),
    'Failed to add port forward'
  )
export const useDeleteFirewallV2Forward = () =>
  useFirewallV2Mutation(
    (id: string) => api.deleteFirewallV2Forward(id),
    'Failed to remove port forward'
  )
export const useSetFirewallV2Egress = () =>
  useFirewallV2Mutation(
    (v: { nodeId: string; enabled: boolean }) => api.setFirewallV2Egress(v.nodeId, v.enabled),
    'Failed to change full tunnel'
  )
export const useConfirmFirewallV2 = () =>
  useFirewallV2Mutation((id: string) => api.confirmFirewallV2(id), 'Failed to confirm the change')
export const useRestoreFirewallV2History = () =>
  useFirewallV2Mutation(
    (id: string) => api.restoreFirewallV2History(id),
    'Failed to restore the firewall state'
  )
