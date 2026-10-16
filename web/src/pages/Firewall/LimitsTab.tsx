import { Gauge, Link2, Pencil, Plus, Trash2, X } from 'lucide-react'
import { useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  useCan,
  useCreateLimit,
  useDeleteLimit,
  useGroups,
  useLimits,
  useNetworks,
  useNodes,
  useSetLimitBindings,
  useUpdateLimit,
} from '@/api/client'
import { HelpTip } from '@/components/HelpTip'
import { Badge, Button, Card, EmptyState, Input, Modal } from '@/components/ui'
import { formatRate, kbpsToMbps, mbpsToKbps, scheduleSummary } from '@/lib/limits'
import { formatBytes, gbToMb, mbToGb } from '@/lib/quota'
import type { LimitProfile, LimitProfileRequest, NodeLimit, ScheduleWindow } from '@/types'
import { EngineDisabled } from './EngineOff'

const weekOrder = [1, 2, 3, 4, 5, 6, 0] // Monday first

function dayNames(t: (k: string) => string): string[] {
  return [0, 1, 2, 3, 4, 5, 6].map((d) => t(`days.${d}`))
}

// LimitsTab: limit profiles (P9b): per-node speed, connection and time
// limits, bound to nodes or groups. Only the nftables engine enforces them.
export const LimitsTab = () => {
  const { t } = useTranslation('limits')
  const { data, isLoading, isError } = useLimits()
  const { data: groupData } = useGroups()
  const canEdit = useCan('operator')
  const deleteLimit = useDeleteLimit()
  const [editing, setEditing] = useState<LimitProfile | 'new' | null>(null)
  const [binding, setBinding] = useState<LimitProfile | null>(null)
  const profiles = data?.profiles ?? []
  const nodeLimits = data?.node_limits ?? []
  const groupName = new Map(
    (groupData?.groups ?? []).filter((g) => g !== null).map((g) => [g.id, g.name])
  )
  const names = dayNames(t)

  if (isLoading) return <p className="text-sm text-gray-500">{t('common:state.loading')}</p>
  if (isError) return <p className="text-sm text-red-600">{t('loadError')}</p>

  return (
    <div className="space-y-4">
      {data && !data.enforcing && (
        <EngineDisabled compact why={t('firewallv2:engineOff.limitsWhy')} />
      )}
      <Card>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-sm text-gray-500">{t('intro')}</p>
          {canEdit && (
            <Button size="sm" onClick={() => setEditing('new')}>
              <Plus className="mr-1 h-4 w-4" /> {t('add')}
            </Button>
          )}
        </div>
      </Card>
      {profiles.length === 0 ? (
        <Card>
          <EmptyState
            icon={<Gauge className="h-10 w-10" />}
            title={t('empty')}
            description={t('emptyHint')}
          />
        </Card>
      ) : (
        profiles.map((p) => {
          const nodes = nodeLimits.filter((l) => l.profile_id === p.id)
          return (
            <Card key={p.id}>
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div className="min-w-0 space-y-2">
                  <p className="font-semibold text-gray-900 dark:text-white">{p.name}</p>
                  <div className="flex flex-wrap gap-1">
                    {p.down_kbps != null && (
                      <Badge variant="info">{t('down', { rate: formatRate(p.down_kbps) })}</Badge>
                    )}
                    {p.up_kbps != null && (
                      <Badge variant="info">{t('up', { rate: formatRate(p.up_kbps) })}</Badge>
                    )}
                    {p.max_connections != null && (
                      <Badge variant="warning">
                        {t('connections', { count: p.max_connections })}
                      </Badge>
                    )}
                    {p.quota_mb != null && (
                      <Badge variant="danger">
                        {t(p.quota_action === 'throttle' ? 'quotaThrottle' : 'quotaBlock', {
                          quota: formatBytes(p.quota_mb * 1e6),
                          day: p.quota_reset_day,
                          rate: p.throttle_kbps != null ? formatRate(p.throttle_kbps) : '',
                        })}
                      </Badge>
                    )}
                  </div>
                  {(p.schedule ?? []).length > 0 && (
                    <p className="text-sm text-gray-600 dark:text-gray-300">
                      {t('scheduleLine', {
                        schedule: scheduleSummary(p.schedule, names),
                        zone: p.timezone,
                      })}
                    </p>
                  )}
                  <p className="text-xs text-gray-500">
                    {t('boundSummary', {
                      nodes: nodes.length,
                      groups:
                        (p.group_ids ?? []).map((id) => groupName.get(id) ?? id).join(', ') || '—',
                    })}
                  </p>
                </div>
                {canEdit && (
                  <div className="flex shrink-0 items-center gap-1">
                    <Button variant="secondary" size="sm" onClick={() => setBinding(p)}>
                      <Link2 className="mr-1 h-4 w-4" /> {t('bindings')}
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setEditing(p)}
                      title={t('common:actions.edit')}
                    >
                      <Pencil className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      title={t('common:actions.delete')}
                      loading={deleteLimit.isPending && deleteLimit.variables === p.id}
                      onClick={() => {
                        if (confirm(t('deleteConfirm', { name: p.name }))) deleteLimit.mutate(p.id)
                      }}
                    >
                      <Trash2 className="h-4 w-4 text-red-500" />
                    </Button>
                  </div>
                )}
              </div>
            </Card>
          )
        })
      )}
      {editing && (
        <ProfileModal
          profile={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
        />
      )}
      {binding && (
        <BindingsModal profile={binding} nodeLimits={nodeLimits} onClose={() => setBinding(null)} />
      )}
    </div>
  )
}

// browserZones lists the time zones the browser knows, with the given one
// first if it is missing.
function browserZones(current: string): string[] {
  const intl = Intl as unknown as { supportedValuesOf?: (k: string) => string[] }
  const zones = intl.supportedValuesOf?.('timeZone') ?? []
  const all = zones.includes('UTC') ? zones : ['UTC', ...zones]
  return all.includes(current) ? all : [current, ...all]
}

const emptyWindow = (): ScheduleWindow => ({ days: [1, 2, 3, 4, 5], from: '08:00', to: '18:00' })

const ProfileModal = ({
  profile,
  onClose,
}: {
  profile: LimitProfile | null
  onClose: () => void
}) => {
  const { t } = useTranslation('limits')
  const create = useCreateLimit()
  const update = useUpdateLimit()
  const [name, setName] = useState(profile?.name ?? '')
  const [down, setDown] = useState(kbpsToMbps(profile?.down_kbps))
  const [up, setUp] = useState(kbpsToMbps(profile?.up_kbps))
  const [conns, setConns] = useState(
    profile?.max_connections != null ? String(profile.max_connections) : ''
  )
  const [zone, setZone] = useState(
    profile?.timezone ?? Intl.DateTimeFormat().resolvedOptions().timeZone ?? 'UTC'
  )
  const [quotaGb, setQuotaGb] = useState(mbToGb(profile?.quota_mb))
  const [quotaAction, setQuotaAction] = useState(profile?.quota_action || 'block')
  const [throttle, setThrottle] = useState(kbpsToMbps(profile?.throttle_kbps))
  const [resetDay, setResetDay] = useState(profile?.quota_reset_day || 1)
  const [windows, setWindows] = useState<ScheduleWindow[]>(profile?.schedule ?? [])
  // Stable React keys for the window rows, kept beside the windows.
  const nextKey = useRef(windows.length)
  const [keys, setKeys] = useState<number[]>(() => windows.map((_, i) => i))
  const addWindow = () => {
    setWindows([...windows, emptyWindow()])
    setKeys([...keys, nextKey.current++])
  }
  const removeWindow = (i: number) => {
    setWindows(windows.filter((_, j) => j !== i))
    setKeys(keys.filter((_, j) => j !== i))
  }
  const [error, setError] = useState('')
  const names = dayNames(t)

  const setWindow = (i: number, w: ScheduleWindow) =>
    setWindows(windows.map((x, j) => (j === i ? w : x)))

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const downKbps = mbpsToKbps(down)
    const upKbps = mbpsToKbps(up)
    if (downKbps === 'invalid' || upKbps === 'invalid') {
      setError(t('errors.speed'))
      return
    }
    const maxConns = conns.trim() === '' ? null : Number(conns)
    if (maxConns !== null && !(Number.isInteger(maxConns) && maxConns > 0)) {
      setError(t('errors.connections'))
      return
    }
    if (windows.some((w) => (w.days ?? []).length === 0)) {
      setError(t('errors.noDays'))
      return
    }
    const quotaMb = gbToMb(quotaGb)
    if (quotaMb === 'invalid') {
      setError(t('errors.quota'))
      return
    }
    const throttleKbps = mbpsToKbps(throttle)
    if (throttleKbps === 'invalid' || (quotaAction === 'throttle' && throttleKbps === null)) {
      setError(t('errors.throttle'))
      return
    }
    const req: LimitProfileRequest = {
      name,
      down_kbps: downKbps,
      up_kbps: upKbps,
      max_connections: maxConns,
      timezone: zone,
      schedule: windows,
      quota_mb: quotaMb,
      quota_action: quotaAction,
      throttle_kbps: throttleKbps,
      quota_reset_day: resetDay,
    }
    setError('')
    // On failure the mutation toast shows the server's message; the modal stays open.
    if (profile) update.mutate({ id: profile.id, req }, { onSuccess: onClose })
    else create.mutate(req, { onSuccess: onClose })
  }

  return (
    <Modal isOpen onClose={onClose} title={profile ? t('editTitle') : t('addTitle')} size="lg">
      <form onSubmit={submit} className="space-y-4">
        {error && <p className="text-sm text-red-600">{error}</p>}
        <Input
          label={t('name')}
          help="helpLimits:profile.name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <Input
            label={t('downLabel')}
            help="helpLimits:profile.downKbps"
            value={down}
            onChange={(e) => setDown(e.target.value)}
            placeholder={t('unlimited')}
            inputMode="decimal"
          />
          <Input
            label={t('upLabel')}
            help="helpLimits:profile.upKbps"
            value={up}
            onChange={(e) => setUp(e.target.value)}
            placeholder={t('unlimited')}
            inputMode="decimal"
          />
          <Input
            label={t('connectionsLabel')}
            help="helpLimits:profile.maxConnections"
            value={conns}
            onChange={(e) => setConns(e.target.value)}
            placeholder={t('unlimited')}
            inputMode="numeric"
          />
        </div>
        <p className="text-xs text-gray-500">{t('perNodeHint')}</p>

        <div className="space-y-2">
          <p className="text-sm font-medium">{t('quota')}</p>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-4">
            <Input
              label={t('quotaLabel')}
              help="helpLimits:quota.size"
              value={quotaGb}
              onChange={(e) => setQuotaGb(e.target.value)}
              placeholder={t('noQuota')}
              inputMode="decimal"
            />
            <label className="block text-sm">
              {t('quotaActionLabel')}
              <HelpTip k="helpLimits:quota.action" />
              <select
                data-help="helpLimits:quota.action"
                value={quotaAction}
                onChange={(e) => setQuotaAction(e.target.value)}
                className="mt-1 w-full rounded-lg border px-3 py-2 dark:border-gray-600 dark:bg-gray-700"
              >
                <option value="block">{t('quotaActions.block')}</option>
                <option value="throttle">{t('quotaActions.throttle')}</option>
              </select>
            </label>
            <Input
              label={t('throttleLabel')}
              help="helpLimits:quota.throttle"
              value={throttle}
              onChange={(e) => setThrottle(e.target.value)}
              disabled={quotaAction !== 'throttle'}
              inputMode="decimal"
            />
            <label className="block text-sm">
              {t('resetDayLabel')}
              <HelpTip k="helpLimits:quota.resetDay" />
              <select
                data-help="helpLimits:quota.resetDay"
                value={resetDay}
                onChange={(e) => setResetDay(Number(e.target.value))}
                className="mt-1 w-full rounded-lg border px-3 py-2 dark:border-gray-600 dark:bg-gray-700"
              >
                {Array.from({ length: 28 }, (_, i) => i + 1).map((d) => (
                  <option key={d} value={d}>
                    {d}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <p className="text-xs text-gray-500">{t('quotaHint')}</p>
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <p className="text-sm font-medium">
              {t('schedule')}
              <HelpTip k="helpLimits:schedule.window" />
            </p>
            <Button type="button" variant="secondary" size="sm" onClick={addWindow}>
              <Plus className="mr-1 h-4 w-4" /> {t('addWindow')}
            </Button>
          </div>
          <p className="text-xs text-gray-500">
            {windows.length === 0 ? t('scheduleNone') : t('scheduleHint')}
          </p>
          {windows.map((w, i) => (
            <div key={keys[i]} className="space-y-2 rounded-lg border p-3 dark:border-gray-600">
              <div className="flex flex-wrap gap-1">
                {weekOrder.map((d) => {
                  const on = (w.days ?? []).includes(d)
                  return (
                    <button
                      key={d}
                      type="button"
                      aria-pressed={on}
                      onClick={() =>
                        setWindow(i, {
                          ...w,
                          days: on ? (w.days ?? []).filter((x) => x !== d) : [...(w.days ?? []), d],
                        })
                      }
                      className={`rounded px-2 py-1 text-xs ${on ? 'bg-blue-600 text-white' : 'bg-gray-100 dark:bg-gray-700'}`}
                    >
                      {names[d]}
                    </button>
                  )
                })}
              </div>
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <input
                  type="time"
                  data-help="helpLimits:schedule.window"
                  aria-label={t('from')}
                  value={w.from}
                  onChange={(e) => setWindow(i, { ...w, from: e.target.value })}
                  className="rounded-lg border px-2 py-1 dark:border-gray-600 dark:bg-gray-700"
                  required
                />
                <span>–</span>
                <input
                  type="time"
                  data-help="helpLimits:schedule.window"
                  aria-label={t('to')}
                  value={w.to === '24:00' ? '' : w.to}
                  disabled={w.to === '24:00'}
                  onChange={(e) => setWindow(i, { ...w, to: e.target.value })}
                  className="rounded-lg border px-2 py-1 dark:border-gray-600 dark:bg-gray-700"
                  required={w.to !== '24:00'}
                />
                <label className="flex items-center gap-1">
                  <input
                    type="checkbox"
                    data-help="helpLimits:schedule.window"
                    checked={w.to === '24:00'}
                    onChange={(e) =>
                      setWindow(i, { ...w, to: e.target.checked ? '24:00' : '18:00' })
                    }
                  />
                  {t('endOfDay')}
                </label>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  title={t('removeWindow')}
                  onClick={() => removeWindow(i)}
                >
                  <X className="h-4 w-4" />
                </Button>
              </div>
            </div>
          ))}
          <label className="block text-sm">
            {t('timezone')}
            <HelpTip k="helpLimits:schedule.timezone" />
            <select
              data-help="helpLimits:schedule.timezone"
              value={zone}
              onChange={(e) => setZone(e.target.value)}
              className="mt-1 w-full rounded-lg border px-3 py-2 dark:border-gray-600 dark:bg-gray-700"
            >
              {browserZones(zone).map((z) => (
                <option key={z} value={z}>
                  {z}
                </option>
              ))}
            </select>
          </label>
        </div>

        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" onClick={onClose}>
            {t('common:actions.cancel')}
          </Button>
          <Button type="submit" loading={create.isPending || update.isPending}>
            {t('common:actions.save')}
          </Button>
        </div>
      </form>
    </Modal>
  )
}

// BindingsModal picks the groups and the nodes (one network at a time; the
// selection is kept across networks) bound to a profile.
const BindingsModal = ({
  profile,
  nodeLimits,
  onClose,
}: {
  profile: LimitProfile
  nodeLimits: NodeLimit[]
  onClose: () => void
}) => {
  const { t } = useTranslation('limits')
  const save = useSetLimitBindings()
  const { data: networks = [] } = useNetworks()
  const { data: groupData } = useGroups()
  const groups = (groupData?.groups ?? []).filter((g) => g !== null)
  const [networkId, setNetworkId] = useState('')
  const { data: nodes = [], isLoading } = useNodes(networkId)
  const [groupIds, setGroupIds] = useState<string[]>(profile.group_ids ?? [])
  // node id -> label for every selected node; nodes bound directly are
  // labelled by address until their network is opened.
  const [selected, setSelected] = useState<Map<string, string>>(() => {
    const direct = new Set(profile.node_ids ?? [])
    return new Map(
      nodeLimits
        .filter((l) => direct.has(l.node_id) && !l.group_id)
        .map((l) => [l.node_id, l.virtual_ip])
    )
  })

  const toggleNode = (id: string, label: string) => {
    const next = new Map(selected)
    if (next.has(id)) next.delete(id)
    else next.set(id, label)
    setSelected(next)
  }

  return (
    <Modal isOpen onClose={onClose} title={t('bindingsTitle', { name: profile.name })} size="lg">
      <div className="space-y-4">
        <div>
          <p className="text-sm font-medium">
            {t('groupsLabel')}
            <HelpTip k="helpLimits:bindings.groups" />
          </p>
          {groups.length === 0 ? (
            <p className="text-sm text-gray-500">{t('noGroups')}</p>
          ) : (
            <div className="mt-1 flex flex-wrap gap-3">
              {groups.map((g) => (
                <label key={g.id} className="flex items-center gap-1 text-sm">
                  <input
                    type="checkbox"
                    data-help="helpLimits:bindings.groups"
                    checked={groupIds.includes(g.id)}
                    onChange={(e) =>
                      setGroupIds(
                        e.target.checked ? [...groupIds, g.id] : groupIds.filter((x) => x !== g.id)
                      )
                    }
                  />
                  {g.name}
                </label>
              ))}
            </div>
          )}
        </div>
        <label className="block text-sm font-medium">
          {t('nodesLabel')}
          <HelpTip k="helpLimits:bindings.network" />
          <select
            data-help="helpLimits:bindings.network"
            value={networkId}
            onChange={(e) => setNetworkId(e.target.value)}
            className="mt-1 w-full rounded-lg border px-3 py-2 dark:border-gray-600 dark:bg-gray-700"
          >
            <option value="">{t('selectNetwork')}</option>
            {networks.map((n) => (
              <option key={n.id} value={n.id}>
                {n.name} ({n.cidr})
              </option>
            ))}
          </select>
        </label>
        {networkId && (
          <div className="max-h-56 overflow-y-auto rounded-lg border dark:border-gray-600">
            {isLoading ? (
              <p className="p-3 text-sm text-gray-500">{t('common:state.loading')}</p>
            ) : nodes.length === 0 ? (
              <p className="p-3 text-sm text-gray-500">{t('noNodes')}</p>
            ) : (
              nodes.map((n) => {
                const label = `${n.name} (${n.virtual_ip})`
                return (
                  <label key={n.id} className="flex items-center gap-2 px-3 py-2 text-sm">
                    <input
                      type="checkbox"
                      data-help="helpLimits:bindings.nodes"
                      checked={selected.has(n.id)}
                      onChange={() => toggleNode(n.id, label)}
                    />
                    {label}
                  </label>
                )
              })
            )}
          </div>
        )}
        <div>
          <p className="text-sm font-medium">
            {t('selectedNodes', { count: selected.size })}
            <HelpTip k="helpLimits:bindings.nodes" />
          </p>
          <div className="mt-1 flex flex-wrap gap-1">
            {[...selected.entries()].map(([nodeId, label]) => (
              <Badge key={nodeId}>{label}</Badge>
            ))}
          </div>
        </div>
        <p className="text-xs text-gray-500">{t('bindingsHint')}</p>
        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" onClick={onClose}>
            {t('common:actions.cancel')}
          </Button>
          <Button
            loading={save.isPending}
            onClick={() =>
              save.mutate(
                { id: profile.id, nodeIds: [...selected.keys()], groupIds },
                { onSuccess: onClose }
              )
            }
          >
            {t('common:actions.save')}
          </Button>
        </div>
      </div>
    </Modal>
  )
}
