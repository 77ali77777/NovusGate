import { Ban, CheckCircle, Download, Globe, Lock, Plus, RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Badge, Button, Card } from '@/components/ui'
import type { ChainInfo, FirewallRule } from '@/types'
import { BlockedIPsTab } from './BlockedIPsTab'
import { HostRulesTab } from './HostRulesTab'
import { OpenPortsTab } from './OpenPortsTab'

interface ServerTabProps {
  isAdmin: boolean
  chains: ChainInfo[]
  selectedChain: string
  onChainChange: (chain: string) => void
  currentChain?: ChainInfo
  openPorts: FirewallRule[]
  blockedIPs: FirewallRule[]
  onOpenPort: () => void
  onBlockIP: () => void
  onAllowIP: () => void
  onClosePort: (port: number, protocol: string, isProtected: boolean) => void
  closeLoading: boolean
  onUnblock: (chain: string, lineNumber: number) => void
  onDeleteRule: (chain: string, lineNumber: number, isProtected: boolean) => void
  deleteLoading: boolean
  onExport: () => void
  onRefresh: () => void
}

// ServerTab: protection of the server itself (host firewall): open ports,
// blocked addresses, allowed addresses. The raw iptables chains fold away
// under "Technical details". The three host actions live only here.
export const ServerTab = (p: ServerTabProps) => {
  const { t } = useTranslation('firewall')
  return (
    <div className="space-y-6">
      <Card className="p-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-2">
            {p.isAdmin && (
              <>
                <Button variant="primary" size="sm" onClick={p.onOpenPort}>
                  <Plus className="mr-1 h-4 w-4" /> {t('actions.openPort')}
                </Button>
                <Button variant="danger" size="sm" onClick={p.onBlockIP}>
                  <Ban className="mr-1 h-4 w-4" /> {t('actions.blockIp')}
                </Button>
                <Button variant="secondary" size="sm" onClick={p.onAllowIP}>
                  <CheckCircle className="mr-1 h-4 w-4" /> {t('actions.allowIp')}
                </Button>
              </>
            )}
          </div>
          <div className="flex items-center gap-2">
            {p.isAdmin && (
              <Button
                variant="ghost"
                size="sm"
                onClick={p.onExport}
                title={t('actions.exportRules')}
                aria-label={t('actions.exportRules')}
              >
                <Download className="h-4 w-4" aria-hidden="true" />
              </Button>
            )}
            <Button
              variant="ghost"
              size="sm"
              onClick={p.onRefresh}
              title={t('common:actions.refresh')}
              aria-label={t('common:actions.refresh')}
            >
              <RefreshCw className="h-4 w-4" aria-hidden="true" />
            </Button>
          </div>
        </div>
      </Card>

      <section className="space-y-3">
        <h3 className="flex items-center gap-2 font-semibold">
          <Globe className="h-4 w-4 text-green-600" /> {t('tabs.openPorts')}
        </h3>
        <OpenPortsTab
          openPorts={p.openPorts}
          onClosePort={p.onClosePort}
          closeLoading={p.closeLoading}
        />
      </section>

      <section className="space-y-3">
        <h3 className="flex items-center gap-2 font-semibold">
          <Ban className="h-4 w-4 text-red-600" /> {t('tabs.blockedIps')}
        </h3>
        <BlockedIPsTab
          blockedIPs={p.blockedIPs}
          onUnblock={p.onUnblock}
          unblockLoading={p.deleteLoading}
        />
      </section>

      <details className="group rounded-xl border border-gray-200 dark:border-gray-700">
        <summary className="cursor-pointer select-none p-4">
          <span className="font-semibold">{t('overview.techDetails')}</span>
          <span className="block text-sm text-gray-500">{t('overview.techDetailsHint')}</span>
        </summary>
        <div className="space-y-4 border-t border-gray-200 p-4 dark:border-gray-700">
          <div>
            <h4 className="font-medium">{t('overview.chainPolicies')}</h4>
            <p className="mb-2 text-sm text-gray-500">{t('overview.chainPoliciesHint')}</p>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
              {p.chains.map((chain) => (
                <div
                  key={chain.name}
                  className="flex items-center justify-between rounded-lg bg-gray-50 p-3 dark:bg-gray-700/50"
                >
                  <div className="flex items-center gap-2">
                    <Lock className="h-4 w-4 text-gray-500" />
                    <span className="font-medium">{chain.name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant={chain.policy === 'ACCEPT' ? 'success' : 'danger'}>
                      {chain.policy}
                    </Badge>
                    <span className="text-sm text-gray-500">
                      {t('overview.rulesCount', { count: chain.rules?.length || 0 })}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div>
            <h4 className="mb-2 font-medium">{t('tabs.hostRules')}</h4>
            <HostRulesTab
              chains={p.chains}
              selectedChain={p.selectedChain}
              onChainChange={p.onChainChange}
              currentChain={p.currentChain}
              onDeleteRule={p.onDeleteRule}
              deleteLoading={p.deleteLoading}
            />
          </div>
        </div>
      </details>
    </div>
  )
}
