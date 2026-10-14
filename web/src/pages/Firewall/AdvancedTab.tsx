import { AlertTriangle, CheckCircle, Clock, Eye, Plus, Trash2 } from 'lucide-react'
import type React from 'react'
import { useEffect, useState } from 'react'
import {
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
import { formatPorts, parseList, secondsLeft, toRFC3339 } from '@/lib/firewallV2'
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
const PendingBanner = ({ pending }: { pending: FirewallV2Pending }) => {
  const confirm = useConfirmFirewallV2()
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
          <p className="font-semibold text-amber-800">Change applied — confirm it</p>
          <p className="text-sm text-amber-700">
            If you can still reach the panel, confirm. Without confirmation the previous rules come
            back in <strong>{left} s</strong>.
          </p>
        </div>
      </div>
      <Button
        onClick={() => confirm.mutate(pending.id)}
        loading={confirm.isPending}
        disabled={left === 0}
      >
        <CheckCircle className="mr-1 h-4 w-4" />
        Confirm change
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
      <h3 className="mb-1 font-semibold">Services (open ports)</h3>
      <p className="mb-4 text-sm text-gray-500">
        Ports reachable on the server, optionally only from given sources.
      </p>
      <form onSubmit={submit} className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-6">
        <Select
          label="Protocol"
          options={protocolOptions}
          value={form.protocol}
          onChange={(e) => setForm({ ...form, protocol: e.target.value })}
        />
        <Input
          label="Port"
          type="number"
          min={1}
          max={65535}
          required
          value={form.from}
          onChange={(e) => setForm({ ...form, from: e.target.value })}
        />
        <Input
          label="To port (optional)"
          type="number"
          min={1}
          max={65535}
          value={form.to}
          onChange={(e) => setForm({ ...form, to: e.target.value })}
        />
        <Input
          label="Sources (optional)"
          placeholder="any, or 203.0.113.0/24, …"
          value={form.sources}
          onChange={(e) => setForm({ ...form, sources: e.target.value })}
        />
        <Input
          label="Interface (optional)"
          placeholder="e.g. wg1"
          value={form.iface}
          onChange={(e) => setForm({ ...form, iface: e.target.value })}
        />
        <Input
          label="Comment"
          value={form.comment}
          onChange={(e) => setForm({ ...form, comment: e.target.value })}
        />
        <div className="col-span-2 md:col-span-6 flex justify-end">
          <Button type="submit" size="sm" loading={create.isPending} disabled={disabled}>
            <Plus className="mr-1 h-4 w-4" />
            Open service
          </Button>
        </div>
      </form>
      <Table<FirewallV2Service>
        data={services}
        emptyMessage="No services"
        columns={[
          {
            key: 'protocol',
            header: 'Protocol',
            render: (s) => <Badge variant="info">{s.protocol.toUpperCase()}</Badge>,
          },
          {
            key: 'ports',
            header: 'Port',
            render: (s) => <span className="font-mono">{formatPorts(s.port_from, s.port_to)}</span>,
          },
          {
            key: 'sources',
            header: 'Sources',
            render: (s) => (
              <span className="font-mono text-xs">
                {s.sources?.length ? s.sources.join(', ') : 'Any'}
              </span>
            ),
          },
          { key: 'interface', header: 'Interface', render: (s) => s.interface || '-' },
          { key: 'comment', header: 'Comment', render: (s) => s.comment || '-' },
          {
            key: 'actions',
            header: '',
            render: (s) => (
              <Button
                variant="ghost"
                size="sm"
                aria-label="Remove service"
                disabled={disabled}
                onClick={() => {
                  if (confirm(`Close ${s.protocol}/${formatPorts(s.port_from, s.port_to)}?`))
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
      <h3 className="mb-1 font-semibold">IP rules</h3>
      <p className="mb-4 text-sm text-gray-500">
        Block or allow an address, on all or some ports, optionally until a date. Allow never opens
        the panel, database or API ports.
      </p>
      <form onSubmit={submit} className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-6">
        <Select
          label="Action"
          options={[
            { value: 'block', label: 'Block' },
            { value: 'allow', label: 'Allow' },
          ]}
          value={form.action}
          onChange={(e) => setForm({ ...form, action: e.target.value })}
        />
        <Input
          label="IP or CIDR"
          required
          placeholder="203.0.113.7"
          value={form.prefix}
          onChange={(e) => setForm({ ...form, prefix: e.target.value })}
        />
        <Select
          label="Protocol"
          options={protocolOptions}
          value={form.protocol}
          onChange={(e) => setForm({ ...form, protocol: e.target.value })}
        />
        <Input
          label="Ports (optional)"
          placeholder="all, or 22,80,8000-8100"
          value={form.ports}
          onChange={(e) => setForm({ ...form, ports: e.target.value })}
        />
        <Input
          label="Expires (optional)"
          type="datetime-local"
          value={form.expires}
          onChange={(e) => setForm({ ...form, expires: e.target.value })}
        />
        <Input
          label="Comment"
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
            Add rule
          </Button>
        </div>
      </form>
      <Table<FirewallV2IPRule>
        data={rules}
        emptyMessage="No IP rules"
        columns={[
          {
            key: 'action',
            header: 'Action',
            render: (r) => (
              <Badge variant={r.action === 'block' ? 'danger' : 'success'}>
                {r.action.toUpperCase()}
              </Badge>
            ),
          },
          {
            key: 'prefix',
            header: 'Address',
            render: (r) => <span className="font-mono">{r.prefix}</span>,
          },
          {
            key: 'ports',
            header: 'Ports',
            render: (r) => (r.ports ? `${r.protocol ?? 'tcp'} ${r.ports}` : 'All'),
          },
          {
            key: 'expires_at',
            header: 'Expires',
            render: (r) =>
              r.expires_at ? new Date(r.expires_at).toLocaleString('az-AZ') : 'Never',
          },
          { key: 'origin', header: 'Origin', render: (r) => <Badge>{r.origin}</Badge> },
          { key: 'comment', header: 'Comment', render: (r) => r.comment || '-' },
          {
            key: 'actions',
            header: '',
            render: (r) => (
              <Button
                variant="ghost"
                size="sm"
                aria-label="Remove IP rule"
                disabled={disabled}
                onClick={() => {
                  if (confirm(`Remove the ${r.action} rule for ${r.prefix}?`)) remove.mutate(r.id)
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
      <h3 className="mb-1 font-semibold">Port forwarding</h3>
      <p className="mb-4 text-sm text-gray-500">
        Publish a VPN node's port on the server's public address.
      </p>
      <form onSubmit={submit} className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-5">
        <Select
          label="Protocol"
          options={protocolOptions}
          value={form.protocol}
          onChange={(e) => setForm({ ...form, protocol: e.target.value })}
        />
        <Input
          label="Public port"
          type="number"
          min={1}
          max={65535}
          required
          value={form.publicPort}
          onChange={(e) => setForm({ ...form, publicPort: e.target.value })}
        />
        <Input
          label="Node VPN IP"
          required
          placeholder="10.20.0.5"
          value={form.targetIP}
          onChange={(e) => setForm({ ...form, targetIP: e.target.value })}
        />
        <Input
          label="Node port"
          type="number"
          min={1}
          max={65535}
          placeholder="same as public"
          value={form.targetPort}
          onChange={(e) => setForm({ ...form, targetPort: e.target.value })}
        />
        <Input
          label="Comment"
          value={form.comment}
          onChange={(e) => setForm({ ...form, comment: e.target.value })}
        />
        <div className="col-span-2 md:col-span-5 flex justify-end">
          <Button type="submit" size="sm" loading={create.isPending} disabled={disabled}>
            <Plus className="mr-1 h-4 w-4" />
            Add forward
          </Button>
        </div>
      </form>
      <Table<FirewallV2Forward>
        data={forwards}
        emptyMessage="No port forwards"
        columns={[
          {
            key: 'protocol',
            header: 'Protocol',
            render: (f) => <Badge variant="info">{f.protocol.toUpperCase()}</Badge>,
          },
          {
            key: 'public_port',
            header: 'Public port',
            render: (f) => <span className="font-mono">{f.public_port}</span>,
          },
          {
            key: 'target',
            header: 'Target',
            render: (f) => <span className="font-mono">{`${f.target_ip}:${f.target_port}`}</span>,
          },
          { key: 'comment', header: 'Comment', render: (f) => f.comment || '-' },
          {
            key: 'actions',
            header: '',
            render: (f) => (
              <Button
                variant="ghost"
                size="sm"
                aria-label="Remove port forward"
                disabled={disabled}
                onClick={() => {
                  if (confirm(`Remove the forward of ${f.protocol}/${f.public_port}?`))
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
  const networkId = useCurrentNetworkId()
  const { data: nodes = [] } = useNodes(networkId || '')
  const setEgress = useSetFirewallV2Egress()
  return (
    <Card>
      <h3 className="mb-1 font-semibold">Full tunnel (internet through the server)</h3>
      <p className="mb-4 text-sm text-gray-500">
        Nodes of the network selected in the sidebar. Enabling it changes the node's config (all
        IPv4 traffic, DNS 1.1.1.1): download the config again on the device.
      </p>
      {nodes.length === 0 ? (
        <p className="text-sm text-gray-500">No nodes in the selected network.</p>
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
                  {on ? 'Disable' : 'Enable'}
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
  const [show, setShow] = useState(false)
  const { data, isFetching, refetch } = useFirewallV2Preview(show)
  return (
    <Card>
      <div className="mb-3 flex items-center justify-between">
        <div>
          <h3 className="font-semibold">Ruleset preview</h3>
          <p className="text-sm text-gray-500">
            The nftables ruleset the engine builds from the rules above.
          </p>
        </div>
        <Button
          variant="secondary"
          size="sm"
          loading={isFetching}
          onClick={() => (show ? refetch() : setShow(true))}
        >
          <Eye className="mr-1 h-4 w-4" />
          {show ? 'Refresh' : 'Show'}
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
  const { data: state, isLoading } = useFirewallV2State()
  if (isLoading) return <p className="text-sm text-gray-500">Loading…</p>
  if (!state) return <p className="text-sm text-gray-500">The nftables engine is not available.</p>
  const enforcing = state.mode === 'nft'
  const locked = !enforcing || !!state.pending
  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-center gap-3">
          <span className="text-sm text-gray-500">Engine</span>
          <Badge variant={enforcing ? 'success' : 'warning'} size="md">
            {state.mode}
          </Badge>
          {state.ssh_ports && (
            <span className="text-sm text-gray-500">
              SSH protected: <span className="font-mono">{state.ssh_ports.join(', ')}</span>
            </span>
          )}
          {state.egress_interface && (
            <span className="text-sm text-gray-500">
              Internet interface: <span className="font-mono">{state.egress_interface}</span>
            </span>
          )}
        </div>
        {!enforcing && (
          <p className="mt-3 rounded-lg bg-blue-50 p-3 text-sm text-blue-700 dark:bg-blue-900/20">
            These rules are applied only with <span className="font-mono">FIREWALL_ENGINE=nft</span>
            . In {state.mode} mode changes are refused; the preview works in every mode.
          </p>
        )}
        {state.host_error && (
          <p className="mt-3 rounded-lg bg-red-50 p-3 text-sm text-red-700 dark:bg-red-900/20">
            {state.host_error}
          </p>
        )}
      </Card>
      {state.pending && <PendingBanner pending={state.pending} />}
      <ServicesSection services={state.services ?? []} disabled={locked} />
      <IPRulesSection rules={state.ip_rules ?? []} disabled={locked} />
      <ForwardsSection forwards={state.forwards ?? []} disabled={locked} />
      <EgressSection egressIds={state.egress_node_ids ?? []} disabled={locked} />
      <PreviewSection />
    </div>
  )
}
