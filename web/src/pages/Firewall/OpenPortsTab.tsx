import { AlertTriangle, Globe, Lock, XCircle } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Badge, Button, Card } from '@/components/ui'
import type { FirewallRule } from '@/types'

interface OpenPortsTabProps {
  openPorts: FirewallRule[]
  onClosePort: (port: number, protocol: string, isProtected: boolean) => void
  closeLoading: boolean
}

export const OpenPortsTab = ({ openPorts, onClosePort, closeLoading }: OpenPortsTabProps) => {
  const { t } = useTranslation('firewall')
  // Parse port number from rule - handles formats like "22", "dpt:22", "8000:9000"
  const parsePort = (portStr: string | undefined): number => {
    if (!portStr || portStr === '-') return 0
    // Extract first number from string (handles "dpt:22", "22", etc.)
    const match = portStr.match(/(\d+)/)
    return match ? parseInt(match[1], 10) : 0
  }

  // Handle close port with validation
  const handleClosePortClick = (rule: FirewallRule) => {
    const port = parsePort(rule.port)
    if (port === 0) {
      alert(t('alerts.invalidPort'))
      return
    }
    // Ensure protocol is lowercase and valid for close port operation
    let protocol = (rule.protocol || 'tcp').toLowerCase()
    // If protocol is 'all' or 'icmp', default to 'both' for tcp/udp
    if (protocol === 'all' || protocol === 'icmp') {
      protocol = 'both'
    }
    onClosePort(port, protocol, rule.protected)
  }

  return (
    <div className="space-y-4">
      {/* Open Ports List */}
      <Card padding="none">
        {openPorts.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-800">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    {t('common:fields.port')}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    {t('common:fields.protocol')}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    {t('common:fields.source')}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    {t('common:fields.interface')}
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
                {openPorts.map((rule, index) => (
                  <tr
                    key={`${rule.chain}-${rule.number}-${index}`}
                    className={rule.protected ? 'bg-yellow-50 dark:bg-yellow-900/10' : ''}
                  >
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-8 h-8 rounded-full bg-green-100 dark:bg-green-900/50 flex items-center justify-center">
                          <Globe className="w-4 h-4 text-green-600" />
                        </div>
                        <span className="font-mono font-bold text-lg">{rule.port}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <Badge variant="info">{rule.protocol.toUpperCase()}</Badge>
                    </td>
                    <td className="px-4 py-3 text-sm font-mono">
                      {rule.source === 'anywhere' || rule.source === '0.0.0.0/0' ? (
                        <span className="text-gray-500">{t('common:state.any')}</span>
                      ) : (
                        rule.source
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {rule.in_interface || rule.interface || '-'}
                    </td>
                    <td className="px-4 py-3">
                      {rule.protected ? (
                        <Badge variant="warning">
                          <Lock className="w-3 h-3 mr-1" /> {t('openPorts.protected')}
                        </Badge>
                      ) : (
                        <Badge variant="success">{t('openPorts.open')}</Badge>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {rule.protected ? (
                        <span className="flex items-center gap-1 text-xs text-yellow-600 dark:text-yellow-400">
                          <Lock className="w-3 h-3" /> SSH/WireGuard/API
                        </span>
                      ) : (
                        <Button
                          variant="danger"
                          size="sm"
                          onClick={() => handleClosePortClick(rule)}
                          loading={closeLoading}
                        >
                          <XCircle className="w-4 h-4 mr-1" /> {t('common:actions.close')}
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-12 text-gray-500">
            <Globe className="w-12 h-12 mx-auto mb-3 text-gray-400" />
            <p className="font-medium">{t('openPorts.emptyTitle')}</p>
            <p className="text-sm">{t('openPorts.emptyHint')}</p>
          </div>
        )}
      </Card>

      {/* Info Card */}
      <Card className="p-4 bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800">
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-blue-600 dark:text-blue-400 mt-0.5" />
          <div>
            <h4 className="font-medium text-blue-700 dark:text-blue-300">
              {t('openPorts.protectedTitle')}
            </h4>
            <p className="text-sm text-blue-600 dark:text-blue-400 mt-1">
              {t('openPorts.protectedText')}
            </p>
          </div>
        </div>
      </Card>
    </div>
  )
}
