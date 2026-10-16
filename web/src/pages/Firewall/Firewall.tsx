import { useQueryClient } from '@tanstack/react-query'
import {
  Activity,
  Download,
  Gauge,
  History,
  Network,
  Plus,
  RefreshCw,
  RotateCcw,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
} from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  api,
  useAllowIP,
  useApplyVPNFirewallRules,
  useBlockIP,
  useCan,
  useClosePort,
  useCreateVPNFirewallRule,
  useDeleteFirewallRule,
  useDeleteVPNFirewallRule,
  useFirewallRules,
  useFirewallV2State,
  useNetworks,
  useOpenPort,
  useResetFirewall,
  useUpdateVPNFirewallRule,
  useVPNFirewallRules,
} from '@/api/client'
import { HelpTip } from '@/components/HelpTip'
import { PageHeader } from '@/components/Layout'
import { Button, Modal } from '@/components/ui'
import { type AdvancedSection, advancedLocked, type FirewallTab } from '@/lib/firewallTabs'
import { engineMode } from '@/lib/firewallV2'
import { pairRulePriority } from '@/lib/policyMatrix'
import type { ChainInfo, FirewallRule, VPNFirewallRule, VPNFirewallRuleRequest } from '@/types'
import { AdvancedTab } from './AdvancedTab'
import { HistoryTab } from './HistoryTab'
import { LimitsTab } from './LimitsTab'
import { LiveTab } from './LiveTab'
import { OverviewTab } from './OverviewTab'
import { PolicyMatrix } from './PolicyMatrix'
import { ServerTab } from './ServerTab'
import { SystemRulesTab } from './SystemRulesTab'
import { TabBar, type TabItem, TabPanel } from './TabBar'
import { VPNRuleModal } from './VPNRuleModal'
import { VPNRulesTab } from './VPNRulesTab'

export const Firewall: React.FC = () => {
  const { t } = useTranslation('firewall')
  // Host firewall changes are admin-only, VPN rules operator (P9a).
  const isAdmin = useCan('admin')
  const isOperator = useCan('operator')
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<FirewallTab>('overview')
  const [advancedSection, setAdvancedSection] = useState<AdvancedSection>('nft')
  const [selectedChain, setSelectedChain] = useState<string>('INPUT')

  // Modals
  const [showOpenPortModal, setShowOpenPortModal] = useState(false)
  const [showBlockIPModal, setShowBlockIPModal] = useState(false)
  const [showAllowIPModal, setShowAllowIPModal] = useState(false)
  const [showVPNRuleModal, setShowVPNRuleModal] = useState(false)
  const [editingVPNRule, setEditingVPNRule] = useState<VPNFirewallRule | null>(null)

  // Forms
  const [openPortForm, setOpenPortForm] = useState({ port: '', protocol: 'tcp', source: '' })
  const [blockIPForm, setBlockIPForm] = useState({ ip: '', ports: '' })
  const [allowIPForm, setAllowIPForm] = useState({ ip: '', ports: '' })
  const [vpnRuleForm, setVPNRuleForm] = useState<VPNFirewallRuleRequest>({
    name: '',
    description: '',
    source_type: 'any',
    dest_type: 'any',
    protocol: 'all',
    port: '',
    action: 'accept',
    priority: 100,
    enabled: true,
  })

  // Data queries
  const {
    data: firewallStatus,
    isLoading: rulesLoading,
    refetch: refetchRules,
  } = useFirewallRules()
  const { data: vpnRules, isLoading: vpnLoading, refetch: refetchVPN } = useVPNFirewallRules()
  const { data: networks } = useNetworks()
  // The engine (nftables or iptables) decides the Advanced tab's lock badge.
  const v2State = useFirewallV2State()
  const engine = engineMode({ data: v2State.data, error: v2State.error })

  // Mutations
  const openPortMutation = useOpenPort()
  const closePortMutation = useClosePort()
  const blockIPMutation = useBlockIP()
  const allowIPMutation = useAllowIP()
  const deleteRuleMutation = useDeleteFirewallRule()
  const resetFirewallMutation = useResetFirewall()
  const createVPNRuleMutation = useCreateVPNFirewallRule()
  const updateVPNRuleMutation = useUpdateVPNFirewallRule()
  const deleteVPNRuleMutation = useDeleteVPNFirewallRule()
  const applyVPNRulesMutation = useApplyVPNFirewallRules()

  // Refresh reloads what every tab shows, the policy matrix included.
  const handleRefresh = () => {
    refetchRules()
    refetchVPN()
    queryClient.invalidateQueries({ queryKey: ['firewall', 'vpn', 'matrix'] })
  }

  // Get chains data
  const chains = firewallStatus?.chains || []
  const currentChain = chains.find((c: ChainInfo) => c.name === selectedChain)

  // Calculate stats
  const blockedIPs = firewallStatus?.blocked_ips || 0
  const openPorts = firewallStatus?.open_ports || 0
  const vpnRuleCount = vpnRules?.length || 0

  // Get blocked IPs from rules
  const getBlockedIPs = (): FirewallRule[] => {
    const blocked: FirewallRule[] = []
    chains.forEach((chain: ChainInfo) => {
      chain.rules?.forEach((rule: FirewallRule) => {
        if (rule.target === 'DROP' && rule.source !== 'anywhere' && rule.source !== '0.0.0.0/0') {
          blocked.push(rule)
        }
      })
    })
    return blocked
  }

  // Get open ports from rules
  const getOpenPorts = (): FirewallRule[] => {
    const ports: FirewallRule[] = []
    chains.forEach((chain: ChainInfo) => {
      if (chain.name === 'INPUT') {
        chain.rules?.forEach((rule: FirewallRule) => {
          if (rule.target === 'ACCEPT' && rule.port && rule.port !== '-') {
            ports.push(rule)
          }
        })
      }
    })
    return ports
  }

  // Close port handler
  const handleClosePort = async (port: number, protocol: string, isProtected: boolean) => {
    if (isProtected) {
      alert(t('alerts.portProtected'))
      return
    }
    if (!confirm(t('confirm.closePort', { port, protocol }))) return
    try {
      await closePortMutation.mutateAsync({ port, protocol })
    } catch (error) {
      // The mutation cache shows the server's message as a toast.
      console.error('Failed to close port:', error)
    }
  }

  // Handlers
  const handleOpenPort = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await openPortMutation.mutateAsync({
        port: parseInt(openPortForm.port, 10),
        protocol: openPortForm.protocol,
        source: openPortForm.source || undefined,
      })
      setShowOpenPortModal(false)
      setOpenPortForm({ port: '', protocol: 'tcp', source: '' })
    } catch (error) {
      console.error('Failed to open port:', error)
    }
  }

  const handleBlockIP = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await blockIPMutation.mutateAsync({
        ip: blockIPForm.ip,
        ports: blockIPForm.ports || undefined,
      })
      setShowBlockIPModal(false)
      setBlockIPForm({ ip: '', ports: '' })
    } catch (error) {
      console.error('Failed to block IP:', error)
    }
  }

  const handleAllowIP = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await allowIPMutation.mutateAsync({
        ip: allowIPForm.ip,
        ports: allowIPForm.ports || undefined,
      })
      setShowAllowIPModal(false)
      setAllowIPForm({ ip: '', ports: '' })
    } catch (error) {
      console.error('Failed to allow IP:', error)
    }
  }

  const handleDeleteRule = async (chain: string, lineNumber: number, isProtected: boolean) => {
    if (isProtected) {
      alert(t('alerts.ruleProtected'))
      return
    }
    if (!confirm(t('confirm.deleteRule', { number: lineNumber, chain }))) return
    try {
      await deleteRuleMutation.mutateAsync({ chain, line_number: lineNumber })
    } catch (error) {
      console.error('Failed to delete rule:', error)
    }
  }

  const handleUnblockIP = async (chain: string, lineNumber: number) => {
    if (!confirm(t('confirm.unblockIp'))) return
    try {
      await deleteRuleMutation.mutateAsync({ chain, line_number: lineNumber, force: true })
    } catch (error) {
      console.error('Failed to unblock IP:', error)
    }
  }

  const handleExportRules = async () => {
    try {
      const rules = await api.exportFirewallRules()
      const blob = new Blob([rules], { type: 'text/plain' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `firewall-rules-${new Date().toISOString().split('T')[0]}.txt`
      a.click()
      URL.revokeObjectURL(url)
    } catch (error) {
      console.error('Failed to export rules:', error)
    }
  }

  const handleResetFirewall = async () => {
    if (!confirm(t('confirm.reset'))) return
    try {
      await resetFirewallMutation.mutateAsync()
    } catch (error) {
      console.error('Failed to reset firewall:', error)
    }
  }

  // VPN Rule handlers
  const handleVPNRuleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      if (editingVPNRule) {
        await updateVPNRuleMutation.mutateAsync({ id: editingVPNRule.id, request: vpnRuleForm })
      } else {
        await createVPNRuleMutation.mutateAsync(vpnRuleForm)
      }
      setShowVPNRuleModal(false)
      setEditingVPNRule(null)
      resetVPNRuleForm()
    } catch (error) {
      console.error('Failed to save VPN rule:', error)
    }
  }

  const handleEditVPNRule = (rule: VPNFirewallRule) => {
    setEditingVPNRule(rule)
    setVPNRuleForm({
      name: rule.name,
      description: rule.description || '',
      source_type: rule.source_type,
      source_network_id: rule.source_network_id,
      source_node_id: rule.source_node_id,
      source_group_id: rule.source_group_id,
      source_ip: rule.source_ip,
      dest_type: rule.dest_type,
      dest_network_id: rule.dest_network_id,
      dest_node_id: rule.dest_node_id,
      dest_group_id: rule.dest_group_id,
      dest_ip: rule.dest_ip,
      protocol: rule.protocol,
      port: rule.port || '',
      action: rule.action,
      priority: rule.priority,
      enabled: rule.enabled,
    })
    setShowVPNRuleModal(true)
  }

  const handleDeleteVPNRule = async (id: string, name: string) => {
    if (!confirm(t('confirm.deleteVpnRule', { name }))) return
    try {
      await deleteVPNRuleMutation.mutateAsync(id)
    } catch (error) {
      console.error('Failed to delete VPN rule:', error)
    }
  }

  // A click on the policy matrix opens a new rule for that network pair.
  const handleCreateRuleForPair = (
    from: { id: string; name: string },
    to: { id: string; name: string }
  ) => {
    setEditingVPNRule(null)
    setVPNRuleForm({
      // The name column holds 255 characters.
      name: `${from.name} → ${to.name}`.slice(0, 255),
      description: '',
      source_type: 'network',
      source_network_id: from.id,
      dest_type: 'network',
      dest_network_id: to.id,
      protocol: 'all',
      port: '',
      action: 'accept',
      priority: pairRulePriority((vpnRules || []).map((r) => r.priority)),
      enabled: true,
    })
    setShowVPNRuleModal(true)
  }

  const resetVPNRuleForm = () => {
    setVPNRuleForm({
      name: '',
      description: '',
      source_type: 'any',
      dest_type: 'any',
      protocol: 'all',
      port: '',
      action: 'accept',
      priority: 100,
      enabled: true,
    })
  }

  const tabs: TabItem<FirewallTab>[] = [
    { id: 'overview', label: t('tabs.overview'), icon: Shield },
    { id: 'server', label: t('tabs.server'), icon: ShieldCheck },
    { id: 'networks', label: t('tabs.networks'), icon: Network, count: vpnRuleCount },
    { id: 'limits', label: t('tabs.limits'), icon: Gauge },
    {
      id: 'advanced',
      label: t('tabs.advancedTop'),
      icon: SlidersHorizontal,
      locked: advancedLocked(engine) ? t('tabs.locked') : undefined,
    },
  ]
  const advancedTabs: TabItem<AdvancedSection>[] = [
    { id: 'nft', label: t('tabs.nft'), icon: SlidersHorizontal },
    { id: 'live', label: t('tabs.live'), icon: Activity },
    { id: 'history', label: t('tabs.history'), icon: History },
    { id: 'system-rules', label: t('tabs.systemRules'), icon: ShieldCheck },
  ]

  if (rulesLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('page.title')}
        description={t('page.description')}
        actions={
          <div className="flex items-center gap-2">
            {isAdmin && (
              <Button variant="secondary" size="sm" onClick={handleExportRules}>
                <Download className="w-4 h-4 mr-1" /> {t('actions.export')}
              </Button>
            )}
            {isAdmin && (
              <Button
                variant="secondary"
                size="sm"
                onClick={handleResetFirewall}
                loading={resetFirewallMutation.isPending}
              >
                <RotateCcw className="w-4 h-4 mr-1" /> {t('actions.reset')}
              </Button>
            )}
            <Button variant="secondary" size="sm" onClick={handleRefresh}>
              <RefreshCw className="w-4 h-4 mr-1" /> {t('common:actions.refresh')}
            </Button>
          </div>
        }
      />

      <TabBar
        tabs={tabs}
        active={activeTab}
        onChange={setActiveTab}
        label={t('tabs.sections')}
        idPrefix="fw"
      />

      <TabPanel idPrefix="fw" id={activeTab}>
        {activeTab === 'overview' && (
          <OverviewTab
            blockedIPs={blockedIPs}
            openPorts={openPorts}
            vpnRuleCount={vpnRuleCount}
            engine={engine}
            isAdmin={isAdmin}
            onGo={setActiveTab}
            onOpenPort={() => setShowOpenPortModal(true)}
            onBlockIP={() => setShowBlockIPModal(true)}
            onAllowIP={() => setShowAllowIPModal(true)}
          />
        )}

        {/* Server protection: open ports, blocked/allowed IPs, host rules */}
        {activeTab === 'server' && (
          <ServerTab
            isAdmin={isAdmin}
            chains={chains}
            selectedChain={selectedChain}
            onChainChange={setSelectedChain}
            currentChain={currentChain}
            openPorts={getOpenPorts()}
            blockedIPs={getBlockedIPs()}
            onOpenPort={() => setShowOpenPortModal(true)}
            onBlockIP={() => setShowBlockIPModal(true)}
            onAllowIP={() => setShowAllowIPModal(true)}
            onClosePort={handleClosePort}
            closeLoading={closePortMutation.isPending}
            onUnblock={handleUnblockIP}
            onDeleteRule={handleDeleteRule}
            deleteLoading={deleteRuleMutation.isPending}
            onExport={handleExportRules}
            onRefresh={handleRefresh}
          />
        )}

        {/* Between networks: policy matrix and VPN rules */}
        {activeTab === 'networks' && (
          <>
            {isOperator && (
              <div className="flex justify-end">
                <Button
                  variant="primary"
                  size="sm"
                  onClick={() => {
                    resetVPNRuleForm()
                    setEditingVPNRule(null)
                    setShowVPNRuleModal(true)
                  }}
                >
                  <Plus className="mr-1 h-4 w-4" /> {t('actions.vpnRule')}
                </Button>
              </div>
            )}
            <PolicyMatrix onCreateRule={handleCreateRuleForPair} />
            <VPNRulesTab
              rules={vpnRules || []}
              loading={vpnLoading}
              onEditRule={handleEditVPNRule}
              onDeleteRule={handleDeleteVPNRule}
              onApplyRules={() => applyVPNRulesMutation.mutate()}
              applyLoading={applyVPNRulesMutation.isPending}
              deleteLoading={deleteVPNRuleMutation.isPending}
            />
          </>
        )}

        {activeTab === 'limits' && <LimitsTab />}

        {/* nftables engine (firewall v2): services, IP rules, forwards, full
            tunnel; live counters; change history; generated system rules */}
        {activeTab === 'advanced' && (
          <>
            <TabBar
              tabs={advancedTabs}
              active={advancedSection}
              onChange={setAdvancedSection}
              label={t('tabs.advancedSections')}
              idPrefix="fw-adv"
              size="sm"
            />
            <TabPanel idPrefix="fw-adv" id={advancedSection}>
              {advancedSection === 'nft' && <AdvancedTab />}
              {advancedSection === 'live' && <LiveTab />}
              {advancedSection === 'history' && <HistoryTab />}
              {advancedSection === 'system-rules' && <SystemRulesTab />}
            </TabPanel>
          </>
        )}
      </TabPanel>

      {/* Open Port Modal */}
      <Modal
        isOpen={showOpenPortModal}
        onClose={() => setShowOpenPortModal(false)}
        title={t('actions.openPort')}
        size="md"
      >
        <form onSubmit={handleOpenPort} className="space-y-4">
          <div>
            <label htmlFor="fw-1" className="block text-sm font-medium mb-1">
              {t('forms.portNumber')}
              <HelpTip k="helpFirewall:openPort.port" />
            </label>
            <input
              data-help="helpFirewall:openPort.port"
              id="fw-1"
              type="number"
              required
              min="1"
              max="65535"
              value={openPortForm.port}
              onChange={(e) => setOpenPortForm({ ...openPortForm, port: e.target.value })}
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
              placeholder={t('forms.portPlaceholder')}
            />
          </div>
          <div>
            <label htmlFor="fw-2" className="block text-sm font-medium mb-1">
              {t('common:fields.protocol')}
              <HelpTip k="helpFirewall:openPort.protocol" />
            </label>
            <select
              data-help="helpFirewall:openPort.protocol"
              id="fw-2"
              value={openPortForm.protocol}
              onChange={(e) => setOpenPortForm({ ...openPortForm, protocol: e.target.value })}
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
            >
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="both">{t('forms.both')}</option>
            </select>
          </div>
          <div>
            <label htmlFor="fw-3" className="block text-sm font-medium mb-1">
              {t('forms.sourceIpOptional')}
              <HelpTip k="helpFirewall:openPort.source" />
            </label>
            <input
              data-help="helpFirewall:openPort.source"
              id="fw-3"
              type="text"
              value={openPortForm.source}
              onChange={(e) => setOpenPortForm({ ...openPortForm, source: e.target.value })}
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
              placeholder={t('forms.sourceIpPlaceholder')}
            />
          </div>
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" type="button" onClick={() => setShowOpenPortModal(false)}>
              {t('common:actions.cancel')}
            </Button>
            <Button variant="primary" type="submit" loading={openPortMutation.isPending}>
              {t('actions.openPort')}
            </Button>
          </div>
        </form>
      </Modal>

      {/* Block IP Modal */}
      <Modal
        isOpen={showBlockIPModal}
        onClose={() => setShowBlockIPModal(false)}
        title={t('forms.blockIpTitle')}
        size="md"
      >
        <form onSubmit={handleBlockIP} className="space-y-4">
          <div>
            <label htmlFor="fw-4" className="block text-sm font-medium mb-1">
              {t('forms.ipOrCidr')}
              <HelpTip k="helpFirewall:blockIp.ip" />
            </label>
            <input
              data-help="helpFirewall:blockIp.ip"
              id="fw-4"
              type="text"
              required
              value={blockIPForm.ip}
              onChange={(e) => setBlockIPForm({ ...blockIPForm, ip: e.target.value })}
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
              placeholder={t('forms.ipPlaceholder')}
            />
          </div>
          <div>
            <label htmlFor="fw-5" className="block text-sm font-medium mb-1">
              {t('forms.portsOptional')}
              <HelpTip k="helpFirewall:blockIp.ports" />
            </label>
            <input
              data-help="helpFirewall:blockIp.ports"
              id="fw-5"
              type="text"
              value={blockIPForm.ports}
              onChange={(e) => setBlockIPForm({ ...blockIPForm, ports: e.target.value })}
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
              placeholder={t('forms.portsPlaceholder')}
            />
          </div>
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" type="button" onClick={() => setShowBlockIPModal(false)}>
              {t('common:actions.cancel')}
            </Button>
            <Button variant="danger" type="submit" loading={blockIPMutation.isPending}>
              {t('actions.blockIp')}
            </Button>
          </div>
        </form>
      </Modal>

      {/* Allow IP Modal */}
      <Modal
        isOpen={showAllowIPModal}
        onClose={() => setShowAllowIPModal(false)}
        title={t('forms.allowIpTitle')}
        size="md"
      >
        <form onSubmit={handleAllowIP} className="space-y-4">
          <div>
            <label htmlFor="fw-6" className="block text-sm font-medium mb-1">
              {t('forms.ipOrCidr')}
              <HelpTip k="helpFirewall:allowIp.ip" />
            </label>
            <input
              data-help="helpFirewall:allowIp.ip"
              id="fw-6"
              type="text"
              required
              value={allowIPForm.ip}
              onChange={(e) => setAllowIPForm({ ...allowIPForm, ip: e.target.value })}
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
              placeholder={t('forms.ipPlaceholder')}
            />
          </div>
          <div>
            <label htmlFor="fw-7" className="block text-sm font-medium mb-1">
              {t('forms.portsOptional')}
              <HelpTip k="helpFirewall:allowIp.ports" />
            </label>
            <input
              data-help="helpFirewall:allowIp.ports"
              id="fw-7"
              type="text"
              value={allowIPForm.ports}
              onChange={(e) => setAllowIPForm({ ...allowIPForm, ports: e.target.value })}
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
              placeholder={t('forms.portsPlaceholder')}
            />
          </div>
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" type="button" onClick={() => setShowAllowIPModal(false)}>
              {t('common:actions.cancel')}
            </Button>
            <Button variant="primary" type="submit" loading={allowIPMutation.isPending}>
              {t('actions.allowIp')}
            </Button>
          </div>
        </form>
      </Modal>

      {/* VPN Rule Modal */}
      <VPNRuleModal
        isOpen={showVPNRuleModal}
        onClose={() => {
          setShowVPNRuleModal(false)
          setEditingVPNRule(null)
        }}
        form={vpnRuleForm}
        setForm={setVPNRuleForm}
        onSubmit={handleVPNRuleSubmit}
        isEditing={!!editingVPNRule}
        loading={createVPNRuleMutation.isPending || updateVPNRuleMutation.isPending}
        networks={networks || []}
      />
    </div>
  )
}
