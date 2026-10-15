import { Grid3x3 } from 'lucide-react'
import { useFirewallPolicyMatrix } from '@/api/client'
import { Card } from '@/components/ui'

type Verdict = 'allow' | 'deny' | 'partial'

const cellStyle: Record<Verdict, string> = {
  allow: 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300',
  deny: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300',
  partial: 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300',
}

const cellLabel: Record<Verdict, string> = { allow: 'Allow', deny: 'Deny', partial: 'Partial' }

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
  const { data: m, isLoading, isError } = useFirewallPolicyMatrix(true)
  if (isLoading)
    return <Card className="mb-4 text-sm text-gray-500">Loading network policies…</Card>
  if (isError || !m)
    return <Card className="mb-4 text-sm text-red-600">Network policies could not be loaded.</Card>
  if (m.networks.length === 0) return null
  return (
    <Card className="mb-4">
      <div className="mb-3 flex items-center gap-2">
        <Grid3x3 className="h-5 w-5 text-blue-500" />
        <div>
          <h3 className="text-lg font-semibold">Network policies</h3>
          <p className="text-sm text-gray-500">
            Rows are the source network, columns the destination. Partial: some ports, protocols or
            hosts are treated differently. Click a cell to add a rule for that pair.
            {m.nft_enforcing
              ? ' Without a rule, networks are isolated from each other.'
              : ' In iptables mode VPN traffic is accepted unless a rule drops it.'}
          </p>
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="text-sm">
          <thead>
            <tr>
              <th className="p-2 text-left text-xs text-gray-500">from \ to</th>
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
                  const title = `${from.name} → ${to.name}: ${c.reason}${c.rules.length ? `\nRules: ${c.rules.join(', ')}` : ''}`
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
