import { Activity } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useFirewallV2Live } from '@/api/client'
import { Badge, Card, Table } from '@/components/ui'
import { locale } from '@/i18n'
import { formatAgo, formatBytes, usagePercent } from '@/lib/firewallV2'

// LiveTab: what the host's firewall does now. Counters and dropped sources
// reset whenever a change is applied (the nftables table is replaced).
export const LiveTab = () => {
  const { t } = useTranslation('firewallv2')
  const { data: live, isLoading } = useFirewallV2Live()
  if (isLoading) return <p className="text-sm text-gray-500">{t('common:state.loading')}</p>
  if (!live) return <p className="text-sm text-gray-500">{t('live.unavailable')}</p>

  const counters = live.counters.map((c, i) => ({ ...c, id: String(i) }))
  const dropped = live.dropped.map((d) => ({ ...d, id: d.address }))
  const ct = live.conntrack
  const pct = usagePercent(ct.count, ct.max)

  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-center gap-3">
          <Activity className="h-5 w-5 text-blue-500" />
          <span className="text-sm text-gray-500">{t('engine')}</span>
          <Badge variant={live.table_loaded ? 'success' : 'warning'} size="md">
            {live.mode}
          </Badge>
          <span className="text-sm text-gray-500">{t('live.refreshInterval')}</span>
        </div>
        {!live.table_loaded && (
          <p className="mt-3 rounded-lg bg-blue-50 p-3 text-sm text-blue-700 dark:bg-blue-900/20">
            {t('live.tableNotLoaded', { mode: live.mode })}
          </p>
        )}
        {live.error && (
          <p className="mt-3 rounded-lg bg-red-50 p-3 text-sm text-red-700 dark:bg-red-900/20">
            {live.error}
          </p>
        )}
      </Card>

      <Card>
        <h3 className="mb-3 text-lg font-semibold">{t('live.conntrackTitle')}</h3>
        {!ct.available ? (
          <p className="text-sm text-gray-500">{t('live.conntrackUnavailable')}</p>
        ) : (
          <div className="space-y-3">
            <div>
              <div className="mb-1 flex justify-between text-sm">
                <span>
                  {t('live.conntrackUsage', {
                    used: ct.count.toLocaleString(locale()),
                    max: ct.max.toLocaleString(locale()),
                  })}
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
            {ct.truncated && <p className="text-xs text-gray-500">{t('live.truncated')}</p>}
          </div>
        )}
      </Card>

      <Card>
        <h3 className="mb-1 text-lg font-semibold">{t('live.droppedTitle')}</h3>
        <p className="mb-3 text-sm text-gray-500">{t('live.droppedIntro')}</p>
        <Table<(typeof dropped)[number]>
          data={dropped}
          emptyMessage={live.table_loaded ? t('live.droppedEmpty') : t('live.notAvailable')}
          columns={[
            {
              key: 'address',
              header: t('live.address'),
              render: (d) => <span className="font-mono">{d.address}</span>,
            },
            {
              key: 'seen',
              header: t('live.lastDropped'),
              render: (d) => {
                const ago = formatAgo(d.seconds_ago)
                return t(ago.key, { count: ago.count })
              },
            },
          ]}
        />
      </Card>

      <Card>
        <h3 className="mb-1 text-lg font-semibold">{t('live.countersTitle')}</h3>
        <p className="mb-3 text-sm text-gray-500">{t('live.countersIntro')}</p>
        <Table<(typeof counters)[number]>
          data={counters}
          emptyMessage={t('live.countersEmpty')}
          columns={[
            { key: 'chain', header: t('live.chain'), render: (c) => <Badge>{c.chain}</Badge> },
            {
              key: 'rule',
              header: t('live.rule'),
              render: (c) => (
                <div>
                  {c.comment && <p className="text-sm font-medium">{c.comment}</p>}
                  {c.rule && <p className="font-mono text-xs text-gray-500">{c.rule}</p>}
                </div>
              ),
            },
            {
              key: 'packets',
              header: t('live.packets'),
              render: (c) => c.packets.toLocaleString(locale()),
            },
            { key: 'bytes', header: t('live.bytes'), render: (c) => formatBytes(c.bytes) },
          ]}
        />
      </Card>
    </div>
  )
}
