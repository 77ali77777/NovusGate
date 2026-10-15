import { Gauge, Grid3x3 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useFirewallPolicyMatrix } from '@/api/client'
import { Card } from '@/components/ui'
import { matrixReason } from '@/lib/matrixReason'

type Verdict = 'allow' | 'deny' | 'partial'

const cellStyle: Record<Verdict, string> = {
  allow: 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300',
  deny: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300',
  partial: 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300',
}

export interface MatrixNetwork {
  id: string
  name: string
}

interface PolicyMatrixProps {
  onCreateRule: (from: MatrixNetwork, to: MatrixNetwork) => void
}

// PolicyMatrix: which VPN network may reach which. The backend evaluates the
// VPN rules like the firewall does (nodes and custom addresses resolved).
// Clicking a cell opens a new rule for that pair.
export const PolicyMatrix = ({ onCreateRule }: PolicyMatrixProps) => {
  const { t } = useTranslation('firewall')
  const { data: m, isLoading, isError } = useFirewallPolicyMatrix(true)
  const cellLabel: Record<Verdict, string> = {
    allow: t('matrix.allow'),
    deny: t('matrix.deny'),
    partial: t('matrix.partial'),
  }
  if (isLoading) return <Card className="mb-4 text-sm text-gray-500">{t('matrix.loading')}</Card>
  if (isError || !m)
    return <Card className="mb-4 text-sm text-red-600">{t('matrix.loadError')}</Card>
  if (m.networks.length === 0) return null
  return (
    <Card className="mb-4">
      <div className="mb-3 flex items-center gap-2">
        <Grid3x3 className="h-5 w-5 text-blue-500" />
        <div>
          <h3 className="text-lg font-semibold">{t('matrix.title')}</h3>
          <p className="text-sm text-gray-500">
            {t('matrix.help')} {m.nft_enforcing ? t('matrix.helpNft') : t('matrix.helpIptables')}
          </p>
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="text-sm">
          <thead>
            <tr>
              <th className="p-2 text-left text-xs text-gray-500">{t('matrix.fromTo')}</th>
              {m.networks.map((to) => (
                <th key={to.id} className="p-2 text-left font-medium">
                  {to.name}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {m.networks.map((from) => (
              <tr key={from.id}>
                <th className="p-2 text-left font-medium">{from.name}</th>
                {m.networks.map((to) => {
                  const c = m.cells[from.id]?.[to.id]
                  if (!c) return <td key={to.id} />
                  const title = `${t('matrix.cellTitle', { from: from.name, to: to.name, reason: matrixReason(t, c) })}${c.rules.length ? `\n${t('matrix.cellRules', { rules: c.rules.join(', ') })}` : ''}${c.limited ? `\n${t('matrix.cellLimited')}` : ''}`
                  return (
                    <td key={to.id} className="p-1">
                      <button
                        type="button"
                        title={title}
                        aria-label={title}
                        onClick={() => onCreateRule(from, to)}
                        className={`w-full rounded px-3 py-2 text-xs font-semibold ${cellStyle[c.verdict]}`}
                      >
                        {cellLabel[c.verdict]}
                        {c.limited && <Gauge className="ml-1 inline h-3 w-3" aria-hidden />}
                      </button>
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}
