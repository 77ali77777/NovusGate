import {
  ArrowLeft,
  LayoutGrid,
  Network as NetworkIcon,
  Server,
  Share2,
  Shield,
  Users,
} from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useParams } from 'react-router-dom'
import {
  useCan,
  useFirewallPolicyMatrix,
  useGroups,
  useLimits,
  useNetwork,
  useNetworks,
  useNodes,
  useSetNetworkDNS,
  useVPNFirewallRules,
} from '@/api/client'
import { PageHeader } from '@/components/Layout'
import { NetworkDNSStatus, NetworkInterfaceStatus } from '@/components/NetworkStatus'
import { FirewallPendingNotice, NetworkTunnel } from '@/components/Tunnel'
import { Badge, Button, Card, Input } from '@/components/ui'
import { formatDateTime } from '@/i18n'
import { matrixReason } from '@/lib/matrixReason'
import { networkLabel } from '@/lib/networkDisplay'
import {
  deviceMemberships,
  groupsInNetwork,
  limitsInNetwork,
  networkKpis,
  rulesForNetwork,
  topTraffic,
} from '@/lib/networkOverview'
import { formatBytes } from '@/lib/quota'
import { TabBar, type TabItem } from '@/pages/Firewall/TabBar'
import { NetworkTopology } from './NetworkTopology'

const verdictVariant: Record<string, 'success' | 'danger' | 'warning'> = {
  allow: 'success',
  deny: 'danger',
  partial: 'warning',
}

const Field = ({ label, value }: { label: string; value?: string | number }) => (
  <div>
    <p className="text-xs uppercase text-gray-500">{label}</p>
    <p className="break-all font-mono text-sm">{value ?? '—'}</p>
  </div>
)

// NetworkDetailPage: one VPN network with its peers, its policies towards
// the other networks and the VPN rules that name it.
// ClientDNSForm: the DNS servers this network's client configs use (P10a).
// New and re-downloaded configs pick it up; configs already on devices keep
// what they have.
const ClientDNSForm = ({ id, current }: { id: string; current: string }) => {
  const { t } = useTranslation('networks')
  const canEdit = useCan('operator')
  const save = useSetNetworkDNS()
  const [value, setValue] = useState<string | null>(null)
  const shown = value ?? current
  return (
    <form
      className="flex flex-wrap items-end gap-2"
      onSubmit={(e) => {
        e.preventDefault()
        save.mutate({ id, clientDNS: shown }, { onSuccess: () => setValue(null) })
      }}
    >
      <div className="min-w-[16rem] flex-1">
        <Input
          help="helpNetworks:clientDns"
          label={t('detail.clientDns')}
          placeholder={t('detail.clientDnsDefault')}
          helperText={t('detail.clientDnsHint')}
          value={shown}
          disabled={!canEdit}
          onChange={(e) => setValue(e.target.value)}
        />
      </div>
      {canEdit && (
        <Button
          type="submit"
          loading={save.isPending}
          disabled={value === null || value === current}
        >
          {t('common:actions.save')}
        </Button>
      )}
    </form>
  )
}

type NetworkTab = 'overview' | 'devices' | 'access' | 'groups' | 'topology'

// Kpi is one number of the network's summary row.
const Kpi = ({
  label,
  value,
  hint,
  tone,
}: {
  label: string
  value: string | number
  hint?: string
  tone?: string
}) => (
  <Card className="p-4">
    <p className="text-xs uppercase text-gray-500">{label}</p>
    <p className={`mt-1 text-2xl font-semibold ${tone ?? ''}`}>{value}</p>
    {hint && <p className="mt-1 text-xs text-gray-500">{hint}</p>}
  </Card>
)

const statusVariant = (s: string) =>
  s === 'online' ? 'success' : s === 'expired' ? 'danger' : 'default'

export const NetworkDetailPage = () => {
  const { t } = useTranslation('networks')
  const { id = '' } = useParams()
  const { data: network, isLoading } = useNetwork(id)
  const { data: nodes = [] } = useNodes(id)
  const { data: networks = [] } = useNetworks()
  const { data: matrix } = useFirewallPolicyMatrix(!!id)
  const { data: rules = [] } = useVPNFirewallRules()
  const groups = (useGroups().data?.groups ?? []).filter((g) => g !== null)
  const profiles = (useLimits().data?.profiles ?? []).filter((p) => p !== null)
  const [tab, setTab] = useState<NetworkTab>('overview')

  if (isLoading) return <p className="text-sm text-gray-500">{t('common:state.loading')}</p>
  if (!network) return <p className="text-sm text-gray-500">{t('detail.notFound')}</p>

  const label = networkLabel(network, t)
  const others = networks.filter((n) => n.id !== id)
  const nodeIds = new Set(nodes.map((n) => n.id))
  const kpi = networkKpis(nodes, network.tunnel_mode, new Date())
  const myGroups = groupsInNetwork(groups, id)
  const myRules = rulesForNetwork(
    rules,
    id,
    nodeIds,
    myGroups.map((g) => g.id)
  )
  const myLimits = limitsInNetwork(profiles, nodeIds, groups)
  const top = topTraffic(nodes, 5)
  const attention = kpi.outdated + kpi.expiringSoon + kpi.expired

  // endName: how a rule end reads (names come with the rule).
  const endName = (type: string, net?: string, node?: string, group?: string, ip?: string) =>
    (type === 'network' && net) ||
    (type === 'node' && node) ||
    (type === 'group' && group) ||
    (type === 'custom' && ip) ||
    t(`ruleEndpoint.${type}`, { defaultValue: type })

  const tabs: TabItem<NetworkTab>[] = [
    { id: 'overview', label: t('page.tabs.overview'), icon: LayoutGrid },
    { id: 'devices', label: t('page.tabs.devices'), icon: Server, count: nodes.length },
    { id: 'access', label: t('page.tabs.access'), icon: Shield, count: myRules.length },
    {
      id: 'groups',
      label: t('page.tabs.groups'),
      icon: Users,
      count: myGroups.length + myLimits.length,
    },
    { id: 'topology', label: t('page.tabs.topology'), icon: Share2 },
  ]

  return (
    <div className="space-y-6">
      <Link
        to="/networks"
        className="inline-flex items-center gap-1 text-sm text-blue-600 hover:underline"
      >
        <ArrowLeft className="h-4 w-4" /> {t('title')}
      </Link>
      <PageHeader
        title={label.name}
        description={t('detail.summary', {
          cidr: network.cidr,
          online: kpi.online,
          count: kpi.total,
        })}
      />
      {label.note && (
        <p className="rounded-lg bg-blue-50 p-3 text-sm text-blue-800 dark:bg-blue-900/20 dark:text-blue-200">
          {label.note}
        </p>
      )}
      <FirewallPendingNotice />

      {/* Summary: the numbers someone opening the network wants first */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
        <Kpi
          label={t('page.kpi.devices')}
          value={`${kpi.online} / ${kpi.total}`}
          hint={t('page.kpi.devicesHint', { offline: kpi.offline, expired: kpi.expired })}
        />
        <Kpi
          label={t('page.kpi.traffic')}
          value={formatBytes(kpi.rx + kpi.tx)}
          hint={t('page.kpi.trafficHint', { rx: formatBytes(kpi.rx), tx: formatBytes(kpi.tx) })}
        />
        <Kpi
          label={t('page.kpi.fullTunnel')}
          value={kpi.fullTunnel}
          hint={t(`page.kpi.mode.${network.tunnel_mode}`, { defaultValue: network.tunnel_mode })}
        />
        <Kpi
          label={t('page.kpi.rules')}
          value={myRules.length}
          hint={t('page.kpi.rulesHint', { groups: myGroups.length, limits: myLimits.length })}
        />
        <Kpi
          label={t('page.kpi.attention')}
          value={attention}
          tone={
            attention > 0
              ? 'text-amber-600 dark:text-amber-400'
              : 'text-green-600 dark:text-green-400'
          }
          hint={t('page.kpi.attentionHint', {
            outdated: kpi.outdated,
            soon: kpi.expiringSoon,
            expired: kpi.expired,
          })}
        />
      </div>

      <TabBar
        tabs={tabs}
        active={tab}
        onChange={setTab}
        label={t('page.tabs.label')}
        idPrefix="network-tab"
      />

      {tab === 'overview' && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <Card padding="lg">
            <div className="mb-4 flex items-center gap-2">
              <NetworkIcon className="h-5 w-5 text-blue-500" />
              <h3 className="text-lg font-semibold">{t('detail.hub')}</h3>
            </div>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <Field label={t('detail.addressRange')} value={network.cidr} />
              <Field label={t('common:fields.interface')} value={network.interface_name} />
              <Field label={t('detail.listenPortUdp')} value={network.listen_port} />
              <Field label={t('detail.endpoint')} value={network.server_endpoint} />
              <div>
                <p className="text-xs uppercase text-gray-500">{t('tunnel.label')}</p>
                <NetworkTunnel network={network} />
              </div>
              <div className="md:col-span-2">
                <Field label={t('detail.serverPublicKey')} value={network.server_public_key} />
              </div>
            </div>
            <div className="mt-4 border-t border-gray-100 pt-4 dark:border-gray-700">
              <NetworkInterfaceStatus network={network} />
            </div>
            <div className="mt-4">
              <ClientDNSForm id={network.id} current={network.client_dns} />
            </div>
            <div className="mt-4 border-t border-gray-100 pt-4 dark:border-gray-700">
              <NetworkDNSStatus network={network} />
            </div>
          </Card>
          <Card padding="lg">
            <h3 className="mb-3 text-lg font-semibold">{t('page.topTraffic')}</h3>
            {top.length === 0 ? (
              <p className="text-sm text-gray-500">{t('page.noTraffic')}</p>
            ) : (
              <ul className="space-y-3">
                {top.map((d) => (
                  <li key={d.id}>
                    <div className="flex justify-between text-sm">
                      <Link
                        to={`/nodes/${d.id}`}
                        className="font-medium text-blue-600 hover:underline"
                      >
                        {d.name}
                      </Link>
                      <span className="text-gray-500">{formatBytes(d.total)}</span>
                    </div>
                    <div className="mt-1 h-2 rounded bg-gray-100 dark:bg-gray-700">
                      <div
                        className="h-2 rounded bg-blue-500"
                        style={{ width: `${Math.max(3, (d.total / top[0].total) * 100)}%` }}
                      />
                    </div>
                  </li>
                ))}
              </ul>
            )}
            <p className="mt-4 text-xs text-gray-500">{t('page.trafficNote')}</p>
          </Card>
        </div>
      )}

      {tab === 'devices' && (
        <Card padding="none">
          {nodes.length === 0 ? (
            <p className="p-6 text-sm text-gray-500">{t('detail.noPeers')}</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500 dark:bg-gray-800">
                  <tr>
                    <th className="px-4 py-3">{t('page.cols.device')}</th>
                    <th className="px-4 py-3">{t('page.cols.status')}</th>
                    <th className="px-4 py-3">{t('page.cols.lastSeen')}</th>
                    <th className="px-4 py-3">{t('page.cols.traffic')}</th>
                    <th className="px-4 py-3">{t('page.cols.tunnel')}</th>
                    <th className="px-4 py-3">{t('page.cols.groups')}</th>
                    <th className="px-4 py-3">{t('page.cols.limits')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                  {nodes.map((n) => {
                    const m = deviceMemberships(n.id, groups, profiles)
                    return (
                      <tr key={n.id}>
                        <td className="px-4 py-3">
                          <Link
                            to={`/nodes/${n.id}`}
                            className="font-medium text-blue-600 hover:underline"
                          >
                            {n.name}
                          </Link>
                          <p className="font-mono text-xs text-gray-500">{n.virtual_ip}</p>
                          {n.config_outdated && (
                            <Badge variant="warning">{t('nodes:outdated.badge')}</Badge>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <Badge variant={statusVariant(n.status)}>
                            {t(`common:status.${n.status}`, { defaultValue: n.status })}
                          </Badge>
                          {n.expires_at && (
                            <p className="mt-1 text-xs text-gray-500">
                              {t('page.expires', { at: formatDateTime(n.expires_at) })}
                            </p>
                          )}
                        </td>
                        <td className="px-4 py-3 text-xs text-gray-500">
                          {n.last_seen && !n.last_seen.startsWith('0001')
                            ? formatDateTime(n.last_seen)
                            : '—'}
                        </td>
                        <td className="px-4 py-3 text-xs">
                          ↓ {formatBytes(n.transfer_rx ?? 0)}
                          <br />↑ {formatBytes(n.transfer_tx ?? 0)}
                        </td>
                        <td className="px-4 py-3 text-xs">
                          {t(`page.kpi.mode.${n.tunnel_override || network.tunnel_mode}`, {
                            defaultValue: n.tunnel_override || network.tunnel_mode,
                          })}
                        </td>
                        <td className="px-4 py-3 text-xs">{m.groups.join(', ') || '—'}</td>
                        <td className="px-4 py-3 text-xs">{m.limits.join(', ') || '—'}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}

      {tab === 'access' && (
        <div className="space-y-6">
          {matrix && others.length > 0 && (
            <Card padding="lg">
              <h3 className="mb-1 text-lg font-semibold">{t('detail.policies')}</h3>
              <p className="mb-3 text-sm text-gray-500">{t('page.policiesHint')}</p>
              <div className="divide-y divide-gray-100 dark:divide-gray-700">
                {others.map((o) => {
                  const out = matrix.cells?.[id]?.[o.id]
                  const into = matrix.cells?.[o.id]?.[id]
                  const otherName = networkLabel(o, t).name
                  return (
                    <div
                      key={o.id}
                      className="flex flex-wrap items-center justify-between gap-2 py-2 text-sm"
                    >
                      <Link
                        to={`/networks/${o.id}`}
                        className="font-medium text-blue-600 hover:underline"
                      >
                        {otherName}
                      </Link>
                      <span className="flex flex-wrap items-center gap-3">
                        {out && (
                          <span title={matrixReason(t, out)}>
                            {t('detail.toIt', { name: otherName })}{' '}
                            <Badge variant={verdictVariant[out.verdict]}>
                              {t(`verdict.${out.verdict}`, { defaultValue: out.verdict })}
                            </Badge>
                          </span>
                        )}
                        {into && (
                          <span title={matrixReason(t, into)}>
                            {t('detail.fromIt', { name: otherName })}{' '}
                            <Badge variant={verdictVariant[into.verdict]}>
                              {t(`verdict.${into.verdict}`, { defaultValue: into.verdict })}
                            </Badge>
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
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <div>
                <h3 className="text-lg font-semibold">{t('detail.rules')}</h3>
                <p className="text-sm text-gray-500">{t('page.rulesHint')}</p>
              </div>
              <Link to="/firewall" className="text-sm text-blue-600 hover:underline">
                {t('page.manageRules')}
              </Link>
            </div>
            {myRules.length === 0 ? (
              <p className="text-sm text-gray-500">{t('detail.noRules')}</p>
            ) : (
              <div className="divide-y divide-gray-100 dark:divide-gray-700">
                {myRules.map(({ rule: r, side }) => (
                  <div
                    key={r.id}
                    className="flex flex-wrap items-center justify-between gap-2 py-2 text-sm"
                  >
                    <span>
                      <span className="font-medium">{r.name}</span>
                      <span className="ml-2 text-xs text-gray-500">{t(`page.side.${side}`)}</span>
                    </span>
                    <span className="flex items-center gap-2">
                      <span className="text-xs text-gray-500">
                        {endName(
                          r.source_type,
                          r.source_network_name,
                          r.source_node_name,
                          r.source_group_name,
                          r.source_ip
                        )}{' '}
                        {r.bidirectional ? '⇄' : '→'}{' '}
                        {endName(
                          r.dest_type,
                          r.dest_network_name,
                          r.dest_node_name,
                          r.dest_group_name,
                          r.dest_ip
                        )}
                        {r.protocol !== 'all' &&
                          ` · ${r.protocol.toUpperCase()}${r.port ? ` ${r.port}` : ''}`}
                      </span>
                      <Badge variant={r.action === 'accept' ? 'success' : 'danger'}>
                        {t(`ruleAction.${r.action}`, { defaultValue: r.action })}
                      </Badge>
                      {!r.enabled && <Badge>{t('common:status.disabled')}</Badge>}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      )}

      {tab === 'groups' && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <Card padding="lg">
            <h3 className="mb-3 text-lg font-semibold">{t('page.groupsTitle')}</h3>
            {myGroups.length === 0 ? (
              <p className="text-sm text-gray-500">{t('page.noGroups')}</p>
            ) : (
              <ul className="divide-y divide-gray-100 text-sm dark:divide-gray-700">
                {myGroups.map((g) => (
                  <li key={g.id} className="flex justify-between py-2">
                    <Link to="/groups" className="font-medium text-blue-600 hover:underline">
                      {g.name}
                    </Link>
                    <span className="text-gray-500">
                      {t('page.groupCount', { here: g.here, total: g.total })}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <Card padding="lg">
            <h3 className="mb-3 text-lg font-semibold">{t('page.limitsTitle')}</h3>
            {myLimits.length === 0 ? (
              <p className="text-sm text-gray-500">{t('page.noLimits')}</p>
            ) : (
              <ul className="divide-y divide-gray-100 text-sm dark:divide-gray-700">
                {myLimits.map((p) => (
                  <li key={p.id} className="py-2">
                    <div className="flex justify-between">
                      <Link to="/firewall" className="font-medium text-blue-600 hover:underline">
                        {p.name}
                      </Link>
                      <span className="text-gray-500">
                        {t('page.limitDevices', { count: p.devices })}
                      </span>
                    </div>
                    <p className="text-xs text-gray-500">
                      {[
                        p.down_kbps ? t('page.limitDown', { v: p.down_kbps }) : '',
                        p.up_kbps ? t('page.limitUp', { v: p.up_kbps }) : '',
                        p.quota_mb ? t('page.limitQuota', { v: p.quota_mb }) : '',
                      ]
                        .filter(Boolean)
                        .join(' · ') || t('page.limitOther')}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>
      )}

      {tab === 'topology' && (
        <Card padding="none">
          <NetworkTopology
            network={{ id, name: label.name }}
            others={others.map((o) => ({ id: o.id, name: networkLabel(o, t).name }))}
            devices={nodes.map((n) => ({ id: n.id, name: n.name, status: n.status }))}
            cells={matrix?.cells ?? undefined}
          />
          <p className="p-4 text-xs text-gray-500">{t('page.topologyHint')}</p>
        </Card>
      )}
    </div>
  )
}
