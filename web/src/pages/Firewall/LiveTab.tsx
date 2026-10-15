import { Activity } from 'lucide-react'
import { useFirewallV2Live } from '@/api/client'
import { Badge, Card, Table } from '@/components/ui'
import { formatAgo, formatBytes, usagePercent } from '@/lib/firewallV2'

// LiveTab: what the host's firewall does now. Counters and dropped sources
// reset whenever a change is applied (the nftables table is replaced).
export const LiveTab = () => {
  const { data: live, isLoading } = useFirewallV2Live()
  if (isLoading) return <p className="text-sm text-gray-500">Loading…</p>
  if (!live) return <p className="text-sm text-gray-500">The live view is not available.</p>

  const counters = live.counters.map((c, i) => ({ ...c, id: String(i) }))
  const dropped = live.dropped.map((d) => ({ ...d, id: d.address }))
  const ct = live.conntrack
  const pct = usagePercent(ct.count, ct.max)

  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-center gap-3">
          <Activity className="h-5 w-5 text-blue-500" />
          <span className="text-sm text-gray-500">Engine</span>
          <Badge variant={live.table_loaded ? 'success' : 'warning'} size="md">
            {live.mode}
          </Badge>
          <span className="text-sm text-gray-500">Refreshes every 10 s</span>
        </div>
        {!live.table_loaded && (
          <p className="mt-3 rounded-lg bg-blue-50 p-3 text-sm text-blue-700 dark:bg-blue-900/20">
            The nftables table is not loaded (engine mode {live.mode}), so there are no rule
            counters or dropped sources. Connection tracking is shown below.
          </p>
        )}
        {live.error && (
          <p className="mt-3 rounded-lg bg-red-50 p-3 text-sm text-red-700 dark:bg-red-900/20">
            {live.error}
          </p>
        )}
      </Card>

      <Card>
        <h3 className="mb-3 text-lg font-semibold">Connection tracking</h3>
        {!ct.available ? (
          <p className="text-sm text-gray-500">conntrack is not available on this host.</p>
        ) : (
          <div className="space-y-3">
            <div>
              <div className="mb-1 flex justify-between text-sm">
                <span>
                  {ct.count.toLocaleString()} of {ct.max.toLocaleString()} entries
                </span>
                <span className={pct >= 80 ? 'font-semibold text-red-600' : 'text-gray-500'}>
                  {pct}%
                </span>
              </div>
              <div className="h-2 rounded bg-gray-200 dark:bg-gray-700">
                <div
                  className={`h-2 rounded ${pct >= 80 ? 'bg-red-500' : 'bg-blue-500'}`}
                  style={{ width: `${pct}%` }}
                />
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              {Object.entries(ct.by_protocol ?? {}).map(([proto, n]) => (
                <Badge key={proto} variant="info">
                  {proto}: {n}
                </Badge>
              ))}
              {Object.entries(ct.tcp_states ?? {}).map(([state, n]) => (
                <Badge key={state}>
                  {state}: {n}
                </Badge>
              ))}
            </div>
            {ct.truncated && (
              <p className="text-xs text-gray-500">Only the first 200,000 entries were counted.</p>
            )}
          </div>
        )}
      </Card>

      <Card>
        <h3 className="mb-1 text-lg font-semibold">Dropped sources (last hour)</h3>
        <p className="mb-3 text-sm text-gray-500">
          Addresses whose packets reached the default drop of the input chain, up to 4096 per IP
          family.
        </p>
        <Table<(typeof dropped)[number]>
          data={dropped}
          emptyMessage={
            live.table_loaded ? 'Nothing was dropped in the last hour' : 'Not available'
          }
          columns={[
            {
              key: 'address',
              header: 'Address',
              render: (d) => <span className="font-mono">{d.address}</span>,
            },
            { key: 'seen', header: 'Last dropped', render: (d) => formatAgo(d.seconds_ago) },
          ]}
        />
      </Card>

      <Card>
        <h3 className="mb-1 text-lg font-semibold">Rule counters</h3>
        <p className="mb-3 text-sm text-gray-500">
          Packets and bytes each counting rule matched since the last change.
        </p>
        <Table<(typeof counters)[number]>
          data={counters}
          emptyMessage="No counters"
          columns={[
            { key: 'chain', header: 'Chain', render: (c) => <Badge>{c.chain}</Badge> },
            {
              key: 'rule',
              header: 'Rule',
              render: (c) => (
                <div>
                  {c.comment && <p className="text-sm font-medium">{c.comment}</p>}
                  {c.rule && <p className="font-mono text-xs text-gray-500">{c.rule}</p>}
                </div>
              ),
            },
            { key: 'packets', header: 'Packets', render: (c) => c.packets.toLocaleString() },
            { key: 'bytes', header: 'Bytes', render: (c) => formatBytes(c.bytes) },
          ]}
        />
      </Card>
    </div>
  )
}
