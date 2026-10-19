import { ArrowLeft, Network as NetworkIcon } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useParams } from 'react-router-dom'
import {
  useCan,
  useFirewallPolicyMatrix,
  useNetwork,
  useNetworks,
  useNodes,
  useSetNetworkDNS,
  useVPNFirewallRules,
} from '@/api/client'
import { PageHeader } from '@/components/Layout'
import { NetworkInterfaceStatus } from '@/components/NetworkStatus'
import { FirewallPendingNotice, NetworkTunnel } from '@/components/Tunnel'
import { Badge, Button, Card, Input } from '@/components/ui'
import { matrixReason } from '@/lib/matrixReason'
import { networkLabel } from '@/lib/networkDisplay'

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

export const NetworkDetailPage = () => {
  const { t } = useTranslation('networks')
  const { id = '' } = useParams()
  const { data: network, isLoading } = useNetwork(id)
  const { data: nodes = [] } = useNodes(id)
  const { data: networks = [] } = useNetworks()
  const { data: matrix } = useFirewallPolicyMatrix(!!id)
  const { data: rules = [] } = useVPNFirewallRules()

  if (isLoading) return <p className="text-sm text-gray-500">{t('common:state.loading')}</p>
  if (!network) return <p className="text-sm text-gray-500">{t('detail.notFound')}</p>

  const online = nodes.filter((n) => n.status === 'online').length
  const others = networks.filter((n) => n.id !== id)
  const myRules = rules.filter((r) => r.source_network_id === id || r.dest_network_id === id)
  const label = networkLabel(network, t)

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
        description={t('detail.summary', { cidr: network.cidr, online, count: nodes.length })}
      />
      {label.note && (
        <p className="rounded-lg bg-blue-50 p-3 text-sm text-blue-800 dark:bg-blue-900/20 dark:text-blue-200">
          {label.note}
        </p>
      )}
      <FirewallPendingNotice />

      <Card padding="lg">
        <div className="mb-4 flex items-center gap-2">
          <NetworkIcon className="h-5 w-5 text-blue-500" />
          <h3 className="text-lg font-semibold">{t('detail.hub')}</h3>
        </div>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
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
      </Card>

      <Card padding="lg">
        <h3 className="mb-3 text-lg font-semibold">{t('detail.peers')}</h3>
        {nodes.length === 0 ? (
          <p className="text-sm text-gray-500">{t('detail.noPeers')}</p>
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
                    {t(`common:status.${n.status}`, { defaultValue: n.status })}
                  </Badge>
                </span>
              </Link>
            ))}
          </div>
        )}
      </Card>

      {matrix && others.length > 0 && (
        <Card padding="lg">
          <h3 className="mb-3 text-lg font-semibold">{t('detail.policies')}</h3>
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
                  {/* Directions spelled out (C12): from this network to the
                      other one, and from the other one into this network. */}
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
        <h3 className="mb-3 text-lg font-semibold">{t('detail.rules')}</h3>
        {myRules.length === 0 ? (
          <p className="text-sm text-gray-500">{t('detail.noRules')}</p>
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
                    {r.source_network_name ||
                      r.source_node_name ||
                      r.source_ip ||
                      t(`ruleEndpoint.${r.source_type}`, { defaultValue: r.source_type })}{' '}
                    {r.bidirectional ? '⇄' : '→'}{' '}
                    {r.dest_network_name ||
                      r.dest_node_name ||
                      r.dest_ip ||
                      t(`ruleEndpoint.${r.dest_type}`, { defaultValue: r.dest_type })}
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
  )
}
