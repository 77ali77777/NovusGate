import { ArrowLeft, Network as NetworkIcon } from 'lucide-react'
import { Link, useParams } from 'react-router-dom'
import {
  useFirewallPolicyMatrix,
  useNetwork,
  useNetworks,
  useNodes,
  useVPNFirewallRules,
} from '@/api/client'
import { PageHeader } from '@/components/Layout'
import { Badge, Card } from '@/components/ui'

const verdictVariant = { allow: 'success', deny: 'danger', partial: 'warning' } as const

const Field = ({ label, value }: { label: string; value?: string | number }) => (
  <div>
    <p className="text-xs uppercase text-gray-500">{label}</p>
    <p className="break-all font-mono text-sm">{value ?? '—'}</p>
  </div>
)

// NetworkDetailPage: one VPN network with its peers, its policies towards
// the other networks and the VPN rules that name it.
export const NetworkDetailPage = () => {
  const { id = '' } = useParams()
  const { data: network, isLoading } = useNetwork(id)
  const { data: nodes = [] } = useNodes(id)
  const { data: networks = [] } = useNetworks()
  const { data: matrix } = useFirewallPolicyMatrix(!!id)
  const { data: rules = [] } = useVPNFirewallRules()

  if (isLoading) return <p className="text-sm text-gray-500">Loading…</p>
  if (!network) return <p className="text-sm text-gray-500">Network not found.</p>

  const online = nodes.filter((n) => n.status === 'online').length
  const others = networks.filter((n) => n.id !== id)
  const myRules = rules.filter((r) => r.source_network_id === id || r.dest_network_id === id)

  return (
    <div className="space-y-6">
      <Link
        to="/networks"
        className="inline-flex items-center gap-1 text-sm text-blue-600 hover:underline"
      >
        <ArrowLeft className="h-4 w-4" /> Networks
      </Link>
      <PageHeader
        title={network.name}
        description={`${network.cidr} · ${online} of ${nodes.length} peers online`}
      />

      <Card padding="lg">
        <div className="mb-4 flex items-center gap-2">
          <NetworkIcon className="h-5 w-5 text-blue-500" />
          <h3 className="text-lg font-semibold">Hub</h3>
        </div>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <Field label="Address range" value={network.cidr} />
          <Field label="Interface" value={network.interface_name} />
          <Field label="Listen port (UDP)" value={network.listen_port} />
          <Field label="Endpoint" value={network.server_endpoint} />
          <div className="md:col-span-2">
            <Field label="Server public key" value={network.server_public_key} />
          </div>
        </div>
      </Card>

      <Card padding="lg">
        <h3 className="mb-3 text-lg font-semibold">Peers</h3>
        {nodes.length === 0 ? (
          <p className="text-sm text-gray-500">No peers in this network.</p>
        ) : (
          <div className="divide-y divide-gray-100 dark:divide-gray-700">
            {nodes.map((n) => (
              <Link
                key={n.id}
                to={`/nodes/${n.id}`}
                className="flex items-center justify-between py-2 hover:bg-gray-50 dark:hover:bg-gray-800"
              >
                <span className="font-medium">{n.name}</span>
                <span className="flex items-center gap-3">
                  <span className="font-mono text-xs text-gray-500">{n.virtual_ip}</span>
                  <Badge
                    variant={
                      n.status === 'online'
                        ? 'success'
                        : n.status === 'expired'
                          ? 'danger'
                          : 'default'
                    }
                  >
                    {n.status}
                  </Badge>
                </span>
              </Link>
            ))}
          </div>
        )}
      </Card>

      {matrix && others.length > 0 && (
        <Card padding="lg">
          <h3 className="mb-3 text-lg font-semibold">Policies</h3>
          <div className="divide-y divide-gray-100 dark:divide-gray-700">
            {others.map((o) => {
              const out = matrix.cells[id]?.[o.id]
              const into = matrix.cells[o.id]?.[id]
              return (
                <div
                  key={o.id}
                  className="flex flex-wrap items-center justify-between gap-2 py-2 text-sm"
                >
                  <Link
                    to={`/networks/${o.id}`}
                    className="font-medium text-blue-600 hover:underline"
                  >
                    {o.name}
                  </Link>
                  <span className="flex items-center gap-3">
                    {out && (
                      <span title={out.reason}>
                        to it <Badge variant={verdictVariant[out.verdict]}>{out.verdict}</Badge>
                      </span>
                    )}
                    {into && (
                      <span title={into.reason}>
                        from it <Badge variant={verdictVariant[into.verdict]}>{into.verdict}</Badge>
                      </span>
                    )}
                  </span>
                </div>
              )
            })}
          </div>
        </Card>
      )}

      <Card padding="lg">
        <h3 className="mb-3 text-lg font-semibold">VPN rules naming this network</h3>
        {myRules.length === 0 ? (
          <p className="text-sm text-gray-500">None.</p>
        ) : (
          <div className="divide-y divide-gray-100 dark:divide-gray-700">
            {myRules.map((r) => (
              <div
                key={r.id}
                className="flex flex-wrap items-center justify-between gap-2 py-2 text-sm"
              >
                <span className="font-medium">{r.name}</span>
                <span className="flex items-center gap-2">
                  <span className="text-xs text-gray-500">
                    {r.source_network_name || r.source_node_name || r.source_ip || r.source_type} →{' '}
                    {r.dest_network_name || r.dest_node_name || r.dest_ip || r.dest_type}
                  </span>
                  <Badge variant={r.action === 'accept' ? 'success' : 'danger'}>{r.action}</Badge>
                  {!r.enabled && <Badge>disabled</Badge>}
                </span>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}
