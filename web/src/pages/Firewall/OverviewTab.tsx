import { ArrowRight, Ban, CheckCircle, Cpu, Network, Plus, Shield } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Card } from '@/components/ui'
import type { FirewallTab } from '@/lib/firewallTabs'
import type { EngineMode } from '@/lib/firewallV2'

interface OverviewTabProps {
  blockedIPs: number
  openPorts: number
  vpnRuleCount: number
  engine: EngineMode
  isAdmin: boolean // the quick actions change the host firewall: admin only
  onGo: (tab: FirewallTab) => void
  onOpenPort: () => void
  onBlockIP: () => void
  onAllowIP: () => void
}

// OverviewTab: the firewall in plain words (what the server lets in, what
// passes between networks, which engine runs) and the common actions.
export const OverviewTab = ({
  blockedIPs,
  openPorts,
  vpnRuleCount,
  engine,
  isAdmin,
  onGo,
  onOpenPort,
  onBlockIP,
  onAllowIP,
}: OverviewTabProps) => {
  const { t } = useTranslation('firewall')
  const summary = [
    {
      tab: 'server' as const,
      icon: Shield,
      tone: 'bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400',
      title: t('overview.serverTitle'),
      line: `${t('overview.openPortsCount', { count: openPorts })}, ${t('overview.blockedIpsCount', { count: blockedIPs })}`,
      hint: t('overview.serverHint'),
    },
    {
      tab: 'networks' as const,
      icon: Network,
      tone: 'bg-purple-100 text-purple-600 dark:bg-purple-900/30 dark:text-purple-400',
      title: t('overview.networksTitle'),
      line: t('overview.vpnRulesCount', { count: vpnRuleCount }),
      hint: t('overview.networksHint'),
    },
    {
      tab: 'advanced' as const,
      icon: Cpu,
      tone:
        engine === 'iptables'
          ? 'bg-amber-100 text-amber-600 dark:bg-amber-900/30 dark:text-amber-400'
          : 'bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-400',
      title: t('overview.engineTitle'),
      line: t(`overview.engine.${engine}`),
      hint: t(`overview.engineHint.${engine}`),
    },
  ]
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {summary.map((s) => (
          <Card key={s.tab} className="p-4">
            <div className="flex items-start gap-3">
              <div
                className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${s.tone}`}
              >
                <s.icon className="h-5 w-5" />
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-sm text-gray-500">{s.title}</p>
                <p className="font-semibold text-gray-900 dark:text-white">{s.line}</p>
                <p className="mt-1 text-sm text-gray-500">{s.hint}</p>
                <button
                  type="button"
                  onClick={() => onGo(s.tab)}
                  className="mt-2 inline-flex items-center gap-1 text-sm font-medium text-blue-600 hover:underline dark:text-blue-400"
                >
                  {t('overview.view')} <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
              </div>
            </div>
          </Card>
        ))}
      </div>

      {/* Quick Actions */}
      {isAdmin && (
        <Card padding="none">
          <div className="p-4 border-b border-gray-200 dark:border-gray-700">
            <h3 className="font-semibold">{t('overview.quickActions')}</h3>
            <p className="text-sm text-gray-500">{t('overview.quickActionsHint')}</p>
          </div>
          <div className="p-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <button
                type="button"
                onClick={onOpenPort}
                className="flex items-center gap-3 p-4 bg-green-50 dark:bg-green-900/20 rounded-lg hover:bg-green-100 dark:hover:bg-green-900/30 transition-colors"
              >
                <div className="w-10 h-10 rounded-full bg-green-100 dark:bg-green-900/50 flex items-center justify-center">
                  <Plus className="w-5 h-5 text-green-600" />
                </div>
                <div className="text-left">
                  <p className="font-medium text-green-700 dark:text-green-300">
                    {t('actions.openPort')}
                  </p>
                  <p className="text-sm text-green-600 dark:text-green-400">
                    {t('overview.openPortHint')}
                  </p>
                </div>
              </button>
              <button
                type="button"
                onClick={onBlockIP}
                className="flex items-center gap-3 p-4 bg-red-50 dark:bg-red-900/20 rounded-lg hover:bg-red-100 dark:hover:bg-red-900/30 transition-colors"
              >
                <div className="w-10 h-10 rounded-full bg-red-100 dark:bg-red-900/50 flex items-center justify-center">
                  <Ban className="w-5 h-5 text-red-600" />
                </div>
                <div className="text-left">
                  <p className="font-medium text-red-700 dark:text-red-300">
                    {t('actions.blockIp')}
                  </p>
                  <p className="text-sm text-red-600 dark:text-red-400">
                    {t('overview.blockIpHint')}
                  </p>
                </div>
              </button>
              <button
                type="button"
                onClick={onAllowIP}
                className="flex items-center gap-3 p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg hover:bg-blue-100 dark:hover:bg-blue-900/30 transition-colors"
              >
                <div className="w-10 h-10 rounded-full bg-blue-100 dark:bg-blue-900/50 flex items-center justify-center">
                  <CheckCircle className="w-5 h-5 text-blue-600" />
                </div>
                <div className="text-left">
                  <p className="font-medium text-blue-700 dark:text-blue-300">
                    {t('actions.allowIp')}
                  </p>
                  <p className="text-sm text-blue-600 dark:text-blue-400">
                    {t('overview.allowIpHint')}
                  </p>
                </div>
              </button>
            </div>
          </div>
        </Card>
      )}
    </div>
  )
}
