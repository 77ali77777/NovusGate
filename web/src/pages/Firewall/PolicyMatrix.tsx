import { Gauge, Grid3x3, Info } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useFirewallPolicyMatrix, useNetworks } from '@/api/client'
import { Card } from '@/components/ui'
import { matrixReason, matrixShortReason } from '@/lib/matrixReason'
import { networkLabelById } from '@/lib/networkDisplay'
import { present } from '@/lib/present'

// The API sends the verdict as a plain string; unknown values render unstyled.
type Verdict = string

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
  const { data: allNets } = useNetworks()
  const cellLabel: Record<Verdict, string> = {
    allow: t('matrix.allow'),
    deny: t('matrix.deny'),
    partial: t('matrix.partial'),
  }
  if (isLoading) return <Card className="mb-4 text-sm text-gray-500">{t('matrix.loading')}</Card>
  if (isError || !m)
    return <Card className="mb-4 text-sm text-red-600">{t('matrix.loadError')}</Card>
  // Shown names: wg0 is "Admin VPN" (lib/networkDisplay).
  const networks = present(m.networks).map((n) => ({
    ...n,
    name: networkLabelById(allNets, n.id, n.name, t),
  }))
  const cells = m.cells ?? {}
  if (networks.length === 0) return null
  // Equal columns (the row header too); below this width the card scrolls.
  const minWidth = `${(networks.length + 1) * 8}rem`
  return (
    <Card className="mb-4">
      <div className="mb-3 flex items-start gap-2">
        <Grid3x3 className="mt-0.5 h-5 w-5 shrink-0 text-blue-500" />
        <div className="min-w-0">
          <h3 className="text-lg font-semibold">{t('matrix.title')}</h3>
          <p className="text-sm text-gray-500">{t('matrix.help')}</p>
        </div>
      </div>
      <p className="mb-3 flex items-start gap-2 rounded-lg bg-blue-50 px-3 py-2 text-sm text-blue-800 dark:bg-blue-900/20 dark:text-blue-200">
        <Info className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
        {m.nft_enforcing ? t('matrix.helpNft') : t('matrix.helpIptables')}
      </p>
      <div className="overflow-x-auto">
        <table className="w-full table-fixed text-sm" style={{ minWidth }}>
          <thead>
            <tr>
              <th scope="col" className="p-2 text-left text-xs font-medium text-gray-500">
                {t('matrix.fromTo')}
              </th>
              {networks.map((to) => (
                <th key={to.id} scope="col" className="break-words p-2 text-left font-medium">
                  {to.name}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {networks.map((from) => (
              <tr key={from.id}>
                <th scope="row" className="break-words p-2 text-left font-medium">
                  {from.name}
                </th>
                {networks.map((to) => {
                  const c = cells[from.id]?.[to.id]
                  if (!c) return <td key={to.id} />
                  const title = `${t('matrix.cellTitle', { from: from.name, to: to.name, reason: matrixReason(t, c) })}${(c.rules ?? []).length ? `\n${t('matrix.cellRules', { rules: (c.rules ?? []).join(', ') })}` : ''}${c.limited ? `\n${t('matrix.cellLimited')}` : ''}`
                  return (
                    <td key={to.id} className="p-1 align-top">
                      <button
                        type="button"
                        title={title}
                        aria-label={title}
                        onClick={() => onCreateRule(from, to)}
                        className={`flex w-full flex-col items-center rounded px-2 py-2 text-xs ${cellStyle[c.verdict]}`}
                      >
                        <span className="font-semibold">
                          {cellLabel[c.verdict] ?? c.verdict}
                          {c.limited && <Gauge className="ml-1 inline h-3 w-3" aria-hidden />}
                        </span>
                        <span className="mt-0.5 w-full truncate font-normal opacity-80">
                          {matrixShortReason(t, c)}
                        </span>
                      </button>
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {/* Legend: what the colours mean and what a click does */}
      <ul className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-gray-600 dark:text-gray-400">
        {(['allow', 'deny', 'partial'] as const).map((v) => (
          <li key={v} className="flex items-center gap-1.5">
            <span className={`inline-block h-3 w-3 rounded ${cellStyle[v]}`} aria-hidden="true" />
            <span className="font-semibold">{cellLabel[v]}</span> — {t(`matrix.legend.${v}`)}
          </li>
        ))}
        <li className="flex items-center gap-1.5">
          <Gauge className="h-3 w-3" aria-hidden="true" /> {t('matrix.cellLimited')}
        </li>
      </ul>
      <p className="mt-2 text-xs text-gray-500">{t('matrix.legend.click')}</p>
    </Card>
  )
}
