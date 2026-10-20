import {
  AlertTriangle,
  ArrowLeftRight,
  ArrowRight,
  CheckCircle,
  Info,
  Monitor,
  Network,
  RefreshCw,
  Server,
  Shield,
  Trash2,
  Users,
  XCircle,
} from 'lucide-react'
import { Trans, useTranslation } from 'react-i18next'

import { useAllowed, useNetworks } from '@/api/client'
import { HelpTip } from '@/components/HelpTip'
import { Badge, Button, Card } from '@/components/ui'
import { networkLabelById } from '@/lib/networkDisplay'
import type { VPNFirewallRule } from '@/types'

// VPN Rules Tab Component
interface VPNRulesTabProps {
  rules: VPNFirewallRule[]
  loading: boolean
  onEditRule: (rule: VPNFirewallRule) => void
  onDeleteRule: (id: string, name: string) => void
  onApplyRules: () => void
  applyLoading: boolean
  deleteLoading: boolean
}

export const VPNRulesTab = ({
  rules,
  loading,
  onEditRule,
  onDeleteRule,
  onApplyRules,
  applyLoading,
  deleteLoading,
}: VPNRulesTabProps) => {
  const { t } = useTranslation('firewall')
  const canEdit = useAllowed('vpn_rules', 'edit')
  const { data: allNets } = useNetworks()
  // Markup for the <accept> and <drop> tags of the step 4 translation.
  const acceptTag = <strong className="text-green-600" />
  const dropTag = <strong className="text-red-600" />
  const getEndpointDisplay = (rule: VPNFirewallRule, type: 'source' | 'dest') => {
    const endpointType = type === 'source' ? rule.source_type : rule.dest_type
    const networkId = type === 'source' ? rule.source_network_id : rule.dest_network_id
    const rawNetworkName = type === 'source' ? rule.source_network_name : rule.dest_network_name
    const networkName = networkLabelById(allNets, networkId, rawNetworkName ?? '', t)
    const nodeName = type === 'source' ? rule.source_node_name : rule.dest_node_name
    const ip = type === 'source' ? rule.source_ip : rule.dest_ip
    const groupName = type === 'source' ? rule.source_group_name : rule.dest_group_name

    switch (endpointType) {
      case 'any':
        return <span className="text-gray-500">{t('common:state.any')}</span>
      case 'network':
        return (
          <span className="flex items-center gap-1">
            <Network className="w-3 h-3 text-blue-500" />
            {networkName || t('vpnRules.unknownNetwork')}
          </span>
        )
      case 'node':
        return (
          <span className="flex items-center gap-1">
            <Server className="w-3 h-3 text-green-500" />
            {nodeName || t('vpnRules.unknownNode')}
          </span>
        )
      case 'group':
        return (
          <span className="flex items-center gap-1">
            <Users className="w-3 h-3 text-purple-500" />
            {groupName || t('vpnRules.unknownGroup')}
          </span>
        )
      case 'custom':
        return <span className="font-mono text-sm">{ip}</span>
      default:
        return <span className="text-gray-500">-</span>
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Re-apply all: saving a rule already applies it; this is a full re-sync */}
      <Card className="p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-sm text-gray-500">{t('vpnRules.intro')}</p>
          </div>
          {canEdit && (
            <div className="flex items-center gap-1">
              <Button variant="secondary" size="sm" onClick={onApplyRules} loading={applyLoading}>
                <RefreshCw className="w-4 h-4 mr-1" /> {t('actions.applyRules')}
              </Button>
              <HelpTip k="helpFirewall:vpnRules.reapply" />
            </div>
          )}
        </div>
      </Card>

      {/* Rules List */}
      <Card padding="none">
        {rules.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-800">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    {t('common:fields.priority')}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    {t('common:fields.name')}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    {t('common:fields.source')}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    {t('common:fields.destination')}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    {t('common:fields.protocol')}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    {t('common:fields.port')}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    {t('common:fields.action')}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    {t('common:fields.status')}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    {t('common:fields.actions')}
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {rules.map((rule) => (
                  <tr key={rule.id} className={!rule.enabled ? 'opacity-50' : ''}>
                    <td className="px-4 py-3 text-sm font-mono">{rule.priority}</td>
                    <td className="px-4 py-3">
                      <div>
                        <p className="font-medium">{rule.name}</p>
                        {rule.description && (
                          <p className="text-xs text-gray-500 truncate max-w-[200px]">
                            {rule.description}
                          </p>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm">{getEndpointDisplay(rule, 'source')}</td>
                    <td className="px-4 py-3 text-sm">
                      {/* The arrow says the direction: one-way or both ways */}
                      <span className="flex items-center gap-2">
                        {rule.bidirectional ? (
                          <span title={t('vpnRules.mutual')} className="text-blue-600">
                            <ArrowLeftRight className="w-4 h-4" aria-label={t('vpnRules.mutual')} />
                          </span>
                        ) : (
                          <span title={t('vpnRules.oneWay')} className="text-gray-400">
                            <ArrowRight className="w-4 h-4" aria-label={t('vpnRules.oneWay')} />
                          </span>
                        )}
                        {getEndpointDisplay(rule, 'dest')}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm uppercase">{rule.protocol}</td>
                    <td className="px-4 py-3 text-sm font-mono">
                      {rule.port || t('vpnRules.allPorts')}
                    </td>
                    <td className="px-4 py-3">
                      <Badge
                        variant={
                          rule.action === 'accept'
                            ? 'success'
                            : rule.action === 'drop'
                              ? 'danger'
                              : 'warning'
                        }
                      >
                        {rule.action === 'accept'
                          ? 'ACCEPT'
                          : rule.action === 'drop'
                            ? 'DROP'
                            : 'REJECT'}
                      </Badge>
                    </td>
                    <td className="px-4 py-3">
                      <Badge variant={rule.enabled ? 'success' : 'default'}>
                        {rule.enabled ? t('common:status.active') : t('common:status.disabled')}
                      </Badge>
                    </td>
                    <td className="px-4 py-3">
                      <div className={canEdit ? 'flex items-center gap-1' : 'hidden'}>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => onEditRule(rule)}
                          title={t('common:actions.edit')}
                        >
                          <Shield className="w-4 h-4 text-blue-500" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => onDeleteRule(rule.id, rule.name)}
                          loading={deleteLoading}
                          title={t('common:actions.delete')}
                        >
                          <Trash2 className="w-4 h-4 text-red-500" />
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-8 px-6">
            <div className="max-w-3xl mx-auto">
              {/* Header */}
              <div className="text-center mb-8">
                <div className="w-16 h-16 rounded-full bg-gradient-to-br from-purple-100 to-indigo-100 dark:from-purple-900/30 dark:to-indigo-900/30 flex items-center justify-center mx-auto mb-4">
                  <Network className="w-8 h-8 text-purple-600 dark:text-purple-400" />
                </div>
                <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">
                  {t('vpnRules.empty.title')}
                </h3>
                <p className="text-gray-600 dark:text-gray-400">{t('vpnRules.empty.subtitle')}</p>
              </div>

              {/* What is VPN Rules */}
              <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-5 mb-6">
                <h4 className="font-semibold text-blue-900 dark:text-blue-100 mb-3 flex items-center gap-2">
                  <Info className="w-5 h-5" />
                  {t('vpnRules.empty.whatTitle')}
                </h4>
                <p className="text-blue-800 dark:text-blue-200 text-sm leading-relaxed">
                  <Trans
                    t={t}
                    i18nKey="vpnRules.empty.whatBody"
                    components={{
                      code: (
                        <code className="bg-blue-100 dark:bg-blue-800 px-1.5 py-0.5 rounded text-xs font-mono" />
                      ),
                    }}
                  />
                </p>
              </div>

              {/* Use Cases */}
              <div className="grid md:grid-cols-2 gap-4 mb-6">
                <div className="bg-green-50 dark:bg-green-900/20 rounded-lg p-4">
                  <h5 className="font-medium text-green-900 dark:text-green-100 mb-2 flex items-center gap-2">
                    <CheckCircle className="w-4 h-4" />
                    {t('vpnRules.empty.allowTitle')}
                  </h5>
                  <ul className="text-sm text-green-800 dark:text-green-200 space-y-1.5">
                    <li>• {t('vpnRules.empty.allow1')}</li>
                    <li>• {t('vpnRules.empty.allow2')}</li>
                    <li>• {t('vpnRules.empty.allow3')}</li>
                  </ul>
                </div>
                <div className="bg-red-50 dark:bg-red-900/20 rounded-lg p-4">
                  <h5 className="font-medium text-red-900 dark:text-red-100 mb-2 flex items-center gap-2">
                    <XCircle className="w-4 h-4" />
                    {t('vpnRules.empty.blockTitle')}
                  </h5>
                  <ul className="text-sm text-red-800 dark:text-red-200 space-y-1.5">
                    <li>• {t('vpnRules.empty.block1')}</li>
                    <li>• {t('vpnRules.empty.block2')}</li>
                    <li>• {t('vpnRules.empty.block3')}</li>
                  </ul>
                </div>
              </div>

              {/* How it works */}
              <div className="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-5 mb-6">
                <h4 className="font-semibold text-gray-900 dark:text-white mb-3">
                  {t('vpnRules.empty.howTitle')}
                </h4>
                <div className="flex items-center justify-between text-sm mb-4">
                  <div className="text-center">
                    <div className="w-12 h-12 rounded-lg bg-blue-100 dark:bg-blue-900/50 flex items-center justify-center mx-auto mb-2">
                      <Monitor className="w-6 h-6 text-blue-600" />
                    </div>
                    <span className="text-gray-600 dark:text-gray-400">
                      {t('vpnRules.empty.sourceNode')}
                    </span>
                  </div>
                  <ArrowRight className="w-5 h-5 text-gray-400" />
                  <div className="text-center">
                    <div className="w-12 h-12 rounded-lg bg-purple-100 dark:bg-purple-900/50 flex items-center justify-center mx-auto mb-2">
                      <Server className="w-6 h-6 text-purple-600" />
                    </div>
                    <span className="text-gray-600 dark:text-gray-400">
                      {t('vpnRules.empty.vpnServer')}
                    </span>
                    <div className="text-xs text-purple-600 dark:text-purple-400 mt-1">
                      {t('vpnRules.empty.forwardRules')}
                    </div>
                  </div>
                  <ArrowRight className="w-5 h-5 text-gray-400" />
                  <div className="text-center">
                    <div className="w-12 h-12 rounded-lg bg-green-100 dark:bg-green-900/50 flex items-center justify-center mx-auto mb-2">
                      <Monitor className="w-6 h-6 text-green-600" />
                    </div>
                    <span className="text-gray-600 dark:text-gray-400">
                      {t('vpnRules.empty.destNode')}
                    </span>
                  </div>
                </div>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  {t('vpnRules.empty.howBody')}
                </p>
              </div>

              {/* Important Note */}
              <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg p-4 mb-6">
                <h5 className="font-medium text-amber-900 dark:text-amber-100 mb-2 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4" />
                  {t('vpnRules.empty.noteTitle')}
                </h5>
                <p className="text-sm text-amber-800 dark:text-amber-200">
                  <Trans
                    t={t}
                    i18nKey="vpnRules.empty.noteBody"
                    components={{
                      code: (
                        <code className="bg-amber-100 dark:bg-amber-800 px-1.5 py-0.5 rounded text-xs font-mono" />
                      ),
                    }}
                  />
                </p>
              </div>

              {/* Quick Start */}
              <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-5">
                <h4 className="font-semibold text-gray-900 dark:text-white mb-4">
                  {t('vpnRules.empty.startTitle')}
                </h4>
                <ol className="space-y-3 text-sm">
                  <li className="flex items-start gap-3">
                    <span className="flex-shrink-0 w-6 h-6 rounded-full bg-purple-100 dark:bg-purple-900/50 text-purple-600 dark:text-purple-400 flex items-center justify-center text-xs font-bold">
                      1
                    </span>
                    <span className="text-gray-600 dark:text-gray-400">
                      <Trans
                        t={t}
                        i18nKey="vpnRules.empty.step1"
                        components={{
                          strong: <strong className="text-gray-900 dark:text-white" />,
                        }}
                      />
                    </span>
                  </li>
                  <li className="flex items-start gap-3">
                    <span className="flex-shrink-0 w-6 h-6 rounded-full bg-purple-100 dark:bg-purple-900/50 text-purple-600 dark:text-purple-400 flex items-center justify-center text-xs font-bold">
                      2
                    </span>
                    <span className="text-gray-600 dark:text-gray-400">
                      {t('vpnRules.empty.step2')}
                    </span>
                  </li>
                  <li className="flex items-start gap-3">
                    <span className="flex-shrink-0 w-6 h-6 rounded-full bg-purple-100 dark:bg-purple-900/50 text-purple-600 dark:text-purple-400 flex items-center justify-center text-xs font-bold">
                      3
                    </span>
                    <span className="text-gray-600 dark:text-gray-400">
                      {t('vpnRules.empty.step3')}
                    </span>
                  </li>
                  <li className="flex items-start gap-3">
                    <span className="flex-shrink-0 w-6 h-6 rounded-full bg-purple-100 dark:bg-purple-900/50 text-purple-600 dark:text-purple-400 flex items-center justify-center text-xs font-bold">
                      4
                    </span>
                    <span className="text-gray-600 dark:text-gray-400">
                      <Trans
                        t={t}
                        i18nKey="vpnRules.empty.step4"
                        components={{ accept: acceptTag, drop: dropTag }}
                      />
                    </span>
                  </li>
                </ol>
              </div>
            </div>
          </div>
        )}
      </Card>
    </div>
  )
}
