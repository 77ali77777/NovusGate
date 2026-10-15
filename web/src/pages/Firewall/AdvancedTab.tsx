import { AlertTriangle, CheckCircle, Clock, Eye, Plus, Trash2 } from 'lucide-react'
import type React from 'react'
import { useEffect, useState } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import {
  useCan,
  useConfirmFirewallV2,
  useCreateFirewallV2Forward,
  useCreateFirewallV2IPRule,
  useCreateFirewallV2Service,
  useDeleteFirewallV2Forward,
  useDeleteFirewallV2IPRule,
  useDeleteFirewallV2Service,
  useFirewallV2Preview,
  useFirewallV2State,
  useNodes,
  useSetFirewallV2Egress,
} from '@/api/client'
import { Badge, Button, Card, Input, Select, Table } from '@/components/ui'
import { formatDateTime } from '@/i18n'
import { formatPorts, parseList, secondsLeft, toRFC3339 } from '@/lib/firewallV2'
import { present } from '@/lib/present'
import { useCurrentNetworkId } from '@/store'
import type {
  FirewallV2Forward,
  FirewallV2IPRule,
  FirewallV2Pending,
  FirewallV2Service,
} from '@/types'

const protocolOptions = [
  { value: 'tcp', label: 'TCP' },
  { value: 'udp', label: 'UDP' },
]

// Pending change: the host already runs it; without Confirm it is rolled back.
export const PendingBanner = ({ pending }: { pending: FirewallV2Pending }) => {
  const { t } = useTranslation('firewallv2')
  const confirm = useConfirmFirewallV2()
  const isAdmin = useCan('admin')
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(t)
  }, [])
  const left = secondsLeft(pending.deadline, now)
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-amber-300 bg-amber-50 p-4 dark:bg-amber-900/20">
      <div className="flex items-start gap-3">
        <Clock className="mt-0.5 h-5 w-5 text-amber-600" />
        <div>
          <p className="font-semibold text-amber-800">{t('pending.title')}</p>
          <p className="text-sm text-amber-700">
            <Trans
              t={t}
              i18nKey="pending.body"
              values={{ left }}
              components={{ strong: <strong /> }}
            />
          </p>
        </div>
      </div>
      <Button
        onClick={() => confirm.mutate(pending.id)}
        loading={confirm.isPending}
        disabled={left === 0 || !isAdmin}
      >
        <CheckCircle className="mr-1 h-4 w-4" />
        {t('pending.confirm')}
      </Button>
    </div>
  )
}

const ServicesSection = ({
  services,
  disabled,
}: {
  services: FirewallV2Service[]
  disabled: boolean
}) => {
  const { t } = useTranslation('firewallv2')
  const create = useCreateFirewallV2Service()
  const remove = useDeleteFirewallV2Service()
  const [form, setForm] = useState({
    protocol: 'tcp',
    from: '',
    to: '',
    sources: '',
    iface: '',
    comment: '',
  })
  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const from = Number(form.from)
    create.mutate(
      {
        protocol: form.protocol as 'tcp' | 'udp',
        port_from: from,
        port_to: form.to ? Number(form.to) : from,
        sources: parseList(form.sources),
        interface: form.iface || undefined,
        comment: form.comment || undefined,
      },
      { onSuccess: () => setForm({ ...form, from: '', to: '', sources: '', comment: '' }) }
    )
  }
  return (
    <Card>
      <h3 className="mb-1 font-semibold">{t('services.title')}</h3>
      <p className="mb-4 text-sm text-gray-500">{t('services.intro')}</p>
      <form onSubmit={submit} className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-6">
        <Select
          label={t('common:fields.protocol')}
          options={protocolOptions}
          value={form.protocol}
          onChange={(e) => setForm({ ...form, protocol: e.target.value })}
        />
        <Input
          label={t('common:fields.port')}
          type="number"
          min={1}
          max={65535}
          required
          value={form.from}
          onChange={(e) => setForm({ ...form, from: e.target.value })}
        />
        <Input
          label={t('services.toPort')}
          type="number"
          min={1}
          max={65535}
          value={form.to}
          onChange={(e) => setForm({ ...form, to: e.target.value })}
        />
        <Input
          label={t('services.sourcesOptional')}
          placeholder={t('services.sourcesPlaceholder')}
          value={form.sources}
          onChange={(e) => setForm({ ...form, sources: e.target.value })}
        />
        <Input
          label={t('services.interfaceOptional')}
          placeholder={t('services.interfacePlaceholder')}
          value={form.iface}
          onChange={(e) => setForm({ ...form, iface: e.target.value })}
        />
        <Input
          label={t('common:fields.comment')}
          value={form.comment}
          onChange={(e) => setForm({ ...form, comment: e.target.value })}
        />
        <div className="col-span-2 md:col-span-6 flex justify-end">
          <Button type="submit" size="sm" loading={create.isPending} disabled={disabled}>
            <Plus className="mr-1 h-4 w-4" />
            {t('services.submit')}
          </Button>
        </div>
      </form>
      <Table<FirewallV2Service>
        data={services}
        emptyMessage={t('services.empty')}
        columns={[
          {
            key: 'protocol',
            header: t('common:fields.protocol'),
            render: (s) => <Badge variant="info">{s.protocol.toUpperCase()}</Badge>,
          },
          {
            key: 'ports',
            header: t('common:fields.port'),
            render: (s) => <span className="font-mono">{formatPorts(s.port_from, s.port_to)}</span>,
          },
          {
            key: 'sources',
            header: t('services.sources'),
            render: (s) => (
              <span className="font-mono text-xs">
                {s.sources?.length ? s.sources.join(', ') : t('common:state.any')}
              </span>
            ),
          },
          {
            key: 'interface',
            header: t('common:fields.interface'),
            render: (s) => s.interface || '-',
          },
          { key: 'comment', header: t('common:fields.comment'), render: (s) => s.comment || '-' },
          {
            key: 'actions',
            header: '',
            render: (s) => (
              <Button
                variant="ghost"
                size="sm"
                aria-label={t('services.removeAria')}
                disabled={disabled}
                onClick={() => {
                  if (
                    confirm(
                      t('services.confirmRemove', {
                        protocol: s.protocol,
                        ports: formatPorts(s.port_from, s.port_to),
                      })
                    )
                  )
                    remove.mutate(s.id)
                }}
              >
                <Trash2 className="h-4 w-4 text-red-600" />
              </Button>
            ),
          },
        ]}
      />
    </Card>
  )
}

const IPRulesSection = ({ rules, disabled }: { rules: FirewallV2IPRule[]; disabled: boolean }) => {
  const { t } = useTranslation('firewallv2')
  const create = useCreateFirewallV2IPRule()
  const remove = useDeleteFirewallV2IPRule()
  const [form, setForm] = useState({
    action: 'block',
    prefix: '',
    protocol: 'tcp',
    ports: '',
    expires: '',
    comment: '',
  })
  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    create.mutate(
      {
        action: form.action as 'block' | 'allow',
        prefix: form.prefix,
        protocol: form.ports ? form.protocol : undefined,
        ports: form.ports || undefined,
        expires_at: toRFC3339(form.expires),
        comment: form.comment || undefined,
      },
      { onSuccess: () => setForm({ ...form, prefix: '', ports: '', expires: '', comment: '' }) }
    )
  }
  return (
    <Card>
      <h3 className="mb-1 font-semibold">{t('ipRules.title')}</h3>
      <p className="mb-4 text-sm text-gray-500">{t('ipRules.intro')}</p>
      <form onSubmit={submit} className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-6">
        <Select
          label={t('common:fields.action')}
          options={[
            { value: 'block', label: t('ipRules.block') },
            { value: 'allow', label: t('ipRules.allow') },
          ]}
          value={form.action}
          onChange={(e) => setForm({ ...form, action: e.target.value })}
        />
        <Input
          label={t('ipRules.prefix')}
          required
          placeholder="203.0.113.7"
          value={form.prefix}
          onChange={(e) => setForm({ ...form, prefix: e.target.value })}
        />
        <Select
          label={t('common:fields.protocol')}
          options={protocolOptions}
          value={form.protocol}
          onChange={(e) => setForm({ ...form, protocol: e.target.value })}
        />
        <Input
          label={t('ipRules.portsOptional')}
          placeholder={t('ipRules.portsPlaceholder')}
          value={form.ports}
          onChange={(e) => setForm({ ...form, ports: e.target.value })}
        />
        <Input
          label={t('ipRules.expiresOptional')}
          type="datetime-local"
          value={form.expires}
          onChange={(e) => setForm({ ...form, expires: e.target.value })}
        />
        <Input
          label={t('common:fields.comment')}
          value={form.comment}
          onChange={(e) => setForm({ ...form, comment: e.target.value })}
        />
        <div className="col-span-2 md:col-span-6 flex justify-end">
          <Button
            type="submit"
            size="sm"
            variant={form.action === 'block' ? 'danger' : 'primary'}
            loading={create.isPending}
            disabled={disabled}
          >
            <Plus className="mr-1 h-4 w-4" />
            {t('ipRules.submit')}
          </Button>
        </div>
      </form>
      <Table<FirewallV2IPRule>
        data={rules}
        emptyMessage={t('ipRules.empty')}
        columns={[
          {
            key: 'action',
            header: t('common:fields.action'),
            render: (r) => (
              <Badge variant={r.action === 'block' ? 'danger' : 'success'}>
                {r.action === 'block' ? t('ipRules.badgeBlock') : t('ipRules.badgeAllow')}
              </Badge>
            ),
          },
          {
            key: 'prefix',
            header: t('ipRules.address'),
            render: (r) => <span className="font-mono">{r.prefix}</span>,
          },
          {
            key: 'ports',
            header: t('common:fields.ports'),
            render: (r) => (r.ports ? `${r.protocol ?? 'tcp'} ${r.ports}` : t('ipRules.allPorts')),
          },
          {
            key: 'expires_at',
            header: t('ipRules.expires'),
            render: (r) => (r.expires_at ? formatDateTime(r.expires_at) : t('ipRules.never')),
          },
          { key: 'origin', header: t('ipRules.origin'), render: (r) => <Badge>{r.origin}</Badge> },
          { key: 'comment', header: t('common:fields.comment'), render: (r) => r.comment || '-' },
          {
            key: 'actions',
            header: '',
            render: (r) => (
              <Button
                variant="ghost"
                size="sm"
                aria-label={t('ipRules.removeAria')}
                disabled={disabled}
                onClick={() => {
                  const question =
                    r.action === 'block'
                      ? 'ipRules.confirmRemoveBlock'
                      : 'ipRules.confirmRemoveAllow'
                  if (confirm(t(question, { prefix: r.prefix }))) remove.mutate(r.id)
                }}
              >
                <Trash2 className="h-4 w-4 text-red-600" />
              </Button>
            ),
          },
        ]}
      />
    </Card>
  )
}

const ForwardsSection = ({
  forwards,
  disabled,
}: {
  forwards: FirewallV2Forward[]
  disabled: boolean
}) => {
  const { t } = useTranslation('firewallv2')
  const create = useCreateFirewallV2Forward()
  const remove = useDeleteFirewallV2Forward()
  const [form, setForm] = useState({
    protocol: 'tcp',
    publicPort: '',
    targetIP: '',
    targetPort: '',
    comment: '',
  })
  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    create.mutate(
      {
        protocol: form.protocol as 'tcp' | 'udp',
        public_port: Number(form.publicPort),
        target_ip: form.targetIP,
        target_port: Number(form.targetPort || form.publicPort),
        comment: form.comment || undefined,
      },
      {
        onSuccess: () =>
          setForm({ ...form, publicPort: '', targetIP: '', targetPort: '', comment: '' }),
      }
    )
  }
  return (
    <Card>
      <h3 className="mb-1 font-semibold">{t('forwards.title')}</h3>
      <p className="mb-4 text-sm text-gray-500">{t('forwards.intro')}</p>
      <form onSubmit={submit} className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-5">
        <Select
          label={t('common:fields.protocol')}
          options={protocolOptions}
          value={form.protocol}
          onChange={(e) => setForm({ ...form, protocol: e.target.value })}
        />
        <Input
          label={t('forwards.publicPort')}
          type="number"
          min={1}
          max={65535}
          required
          value={form.publicPort}
          onChange={(e) => setForm({ ...form, publicPort: e.target.value })}
        />
        <Input
          label={t('forwards.targetIp')}
          required
          placeholder="10.20.0.5"
          value={form.targetIP}
          onChange={(e) => setForm({ ...form, targetIP: e.target.value })}
        />
        <Input
          label={t('forwards.targetPort')}
          type="number"
          min={1}
          max={65535}
          placeholder={t('forwards.targetPortPlaceholder')}
          value={form.targetPort}
          onChange={(e) => setForm({ ...form, targetPort: e.target.value })}
        />
        <Input
          label={t('common:fields.comment')}
          value={form.comment}
          onChange={(e) => setForm({ ...form, comment: e.target.value })}
        />
        <div className="col-span-2 md:col-span-5 flex justify-end">
          <Button type="submit" size="sm" loading={create.isPending} disabled={disabled}>
            <Plus className="mr-1 h-4 w-4" />
            {t('forwards.submit')}
          </Button>
        </div>
      </form>
      <Table<FirewallV2Forward>
        data={forwards}
        emptyMessage={t('forwards.empty')}
        columns={[
          {
            key: 'protocol',
            header: t('common:fields.protocol'),
            render: (f) => <Badge variant="info">{f.protocol.toUpperCase()}</Badge>,
          },
          {
            key: 'public_port',
            header: t('forwards.publicPort'),
            render: (f) => <span className="font-mono">{f.public_port}</span>,
          },
          {
            key: 'target',
            header: t('forwards.target'),
            render: (f) => <span className="font-mono">{`${f.target_ip}:${f.target_port}`}</span>,
          },
          { key: 'comment', header: t('common:fields.comment'), render: (f) => f.comment || '-' },
          {
            key: 'actions',
            header: '',
            render: (f) => (
              <Button
                variant="ghost"
                size="sm"
                aria-label={t('forwards.removeAria')}
                disabled={disabled}
                onClick={() => {
                  if (
                    confirm(
                      t('forwards.confirmRemove', { protocol: f.protocol, port: f.public_port })
                    )
                  )
                    remove.mutate(f.id)
                }}
              >
                <Trash2 className="h-4 w-4 text-red-600" />
              </Button>
            ),
          },
        ]}
      />
    </Card>
  )
}

// Full tunnel: a node may send its internet traffic out through the server.
const EgressSection = ({ egressIds, disabled }: { egressIds: string[]; disabled: boolean }) => {
  const { t } = useTranslation('firewallv2')
  const networkId = useCurrentNetworkId()
  const { data: nodes = [] } = useNodes(networkId || '')
  const setEgress = useSetFirewallV2Egress()
  return (
    <Card>
      <h3 className="mb-1 font-semibold">{t('egress.title')}</h3>
      <p className="mb-4 text-sm text-gray-500">{t('egress.intro')}</p>
      {nodes.length === 0 ? (
        <p className="text-sm text-gray-500">{t('egress.noNodes')}</p>
      ) : (
        <div className="divide-y divide-gray-100 dark:divide-gray-700">
          {nodes.map((n) => {
            const on = egressIds.includes(n.id)
            return (
              <div key={n.id} className="flex items-center justify-between py-2">
                <div>
                  <span className="font-medium">{n.name}</span>
                  <span className="ml-2 font-mono text-xs text-gray-500">{n.virtual_ip}</span>
                </div>
                <Button
                  size="sm"
                  variant={on ? 'secondary' : 'primary'}
                  disabled={disabled}
                  loading={setEgress.isPending && setEgress.variables?.nodeId === n.id}
                  onClick={() => setEgress.mutate({ nodeId: n.id, enabled: !on })}
                >
                  {on ? t('common:actions.disable') : t('common:actions.enable')}
                </Button>
              </div>
            )
          })}
        </div>
      )}
    </Card>
  )
}

const PreviewSection = () => {
  const { t } = useTranslation('firewallv2')
  const [show, setShow] = useState(false)
  const { data, isFetching, refetch } = useFirewallV2Preview(show)
  return (
    <Card>
      <div className="mb-3 flex items-center justify-between">
        <div>
          <h3 className="font-semibold">{t('preview.title')}</h3>
          <p className="text-sm text-gray-500">{t('preview.intro')}</p>
        </div>
        <Button
          variant="secondary"
          size="sm"
          loading={isFetching}
          onClick={() => (show ? refetch() : setShow(true))}
        >
          <Eye className="mr-1 h-4 w-4" />
          {show ? t('common:actions.refresh') : t('common:actions.show')}
        </Button>
      </div>
      {data?.warnings?.map((w) => (
        <p key={w} className="mb-2 flex items-center gap-2 text-sm text-amber-700">
          <AlertTriangle className="h-4 w-4" />
          {w}
        </p>
      ))}
      {show && data && (
        <pre className="max-h-96 overflow-auto rounded-lg bg-gray-900 p-4 font-mono text-xs text-green-300">
          {data.script}
        </pre>
      )}
    </Card>
  )
}

export const AdvancedTab = () => {
  const { t } = useTranslation('firewallv2')
  const { data: state, isLoading } = useFirewallV2State()
  // Host firewall changes are admin-only (P9a).
  const isAdmin = useCan('admin')
  if (isLoading) return <p className="text-sm text-gray-500">{t('common:state.loading')}</p>
  if (!state) return <p className="text-sm text-gray-500">{t('engineUnavailable')}</p>
  const enforcing = state.mode === 'nft'
  const locked = !enforcing || !!state.pending || !isAdmin
  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-center gap-3">
          <span className="text-sm text-gray-500">{t('engine')}</span>
          <Badge variant={enforcing ? 'success' : 'warning'} size="md">
            {state.mode}
          </Badge>
          {state.ssh_ports && (
            <span className="text-sm text-gray-500">
              {t('sshProtected')} <span className="font-mono">{state.ssh_ports.join(', ')}</span>
            </span>
          )}
          {state.egress_interface && (
            <span className="text-sm text-gray-500">
              {t('internetInterface')} <span className="font-mono">{state.egress_interface}</span>
            </span>
          )}
        </div>
        {!enforcing && (
          <p className="mt-3 rounded-lg bg-blue-50 p-3 text-sm text-blue-700 dark:bg-blue-900/20">
            <Trans
              t={t}
              i18nKey="notEnforcing"
              values={{ mode: state.mode }}
              components={{ code: <span className="font-mono" /> }}
            />
          </p>
        )}
        {state.host_error && (
          <p className="mt-3 rounded-lg bg-red-50 p-3 text-sm text-red-700 dark:bg-red-900/20">
            {state.host_error}
          </p>
        )}
      </Card>
      {state.pending && <PendingBanner pending={state.pending} />}
      <ServicesSection services={present(state.services)} disabled={locked} />
      <IPRulesSection rules={present(state.ip_rules)} disabled={locked} />
      <ForwardsSection forwards={present(state.forwards)} disabled={locked} />
      <EgressSection egressIds={state.egress_node_ids ?? []} disabled={locked} />
      <PreviewSection />
    </div>
  )
}
