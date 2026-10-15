import { format } from 'date-fns'
import { Power, RefreshCw, RotateCcw } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  api,
  useHostNetwork,
  useHostSystem,
  useServerChange,
  useServerServices,
  useSysctl,
  useUpgradablePackages,
  useUpgradeJob,
} from '@/api/client'
import { Badge, Button, Card, Input, Select } from '@/components/ui'
import { dateFnsLocale } from '@/i18n'
import { addressRows, routeRows, type Step, sysctlField } from '@/lib/serverAdmin'
import { ConfirmWordModal } from './ConfirmWordModal'

const stateVariant = (state: string) =>
  state === 'active' ? 'success' : state === 'failed' ? 'danger' : 'default'

const when = (iso: string | null | undefined) =>
  iso ? format(new Date(iso), 'PPpp', { locale: dateFnsLocale() }) : '—'

const Loading = ({ isLoading, isError }: { isLoading: boolean; isError: boolean }) => {
  const { t } = useTranslation('server')
  if (isLoading) return <p className="p-6 text-sm text-gray-500">{t('common:state.loading')}</p>
  if (isError) return <p className="p-6 text-sm text-red-600">{t('loadError')}</p>
  return null
}

// ServicesTab: docker, fail2ban and the wg-quick units, with restart.
export const ServicesTab = ({ step }: { step: Step }) => {
  const { t } = useTranslation('server')
  const { data, isLoading, isError } = useServerServices()
  const restart = useServerChange<void>('toasts:failedToRestartService', 'toasts:serviceRestarted')
  const [restarting, setRestarting] = useState('')
  return (
    <Card padding="none">
      <Loading isLoading={isLoading} isError={isError} />
      {data && (
        <ul className="divide-y divide-gray-100 dark:divide-gray-700">
          {data.map((s) => (
            <li key={s.name} className="flex items-center justify-between gap-4 p-4">
              <div className="flex items-center gap-3">
                <span className="font-mono text-sm text-gray-900 dark:text-white">{s.name}</span>
                <Badge variant={stateVariant(s.state)}>{s.state}</Badge>
              </div>
              <Button
                size="sm"
                variant="secondary"
                loading={restart.isPending && restarting === s.name}
                disabled={restart.isPending}
                onClick={() => {
                  if (!confirm(t('services.restartConfirm', { name: s.name }))) return
                  setRestarting(s.name)
                  restart.mutate(() => step(() => api.restartServerService(s.name)))
                }}
              >
                <RotateCcw className="mr-1 h-4 w-4" aria-hidden="true" />
                {t('services.restart')}
              </Button>
            </li>
          ))}
        </ul>
      )}
      <p className="border-t border-gray-100 p-4 text-xs text-gray-500 dark:border-gray-700">
        {t('services.hint')}
      </p>
    </Card>
  )
}

// NetworkTab: the host's interfaces and routes, read-only.
export const NetworkTab = () => {
  const { t } = useTranslation('server')
  const { data, isLoading, isError } = useHostNetwork()
  const links = addressRows(data?.addresses)
  const routes = routeRows(data?.routes)
  const th = 'px-4 py-2 text-left text-xs font-medium uppercase text-gray-500'
  const td = 'px-4 py-2 font-mono text-sm text-gray-900 dark:text-white'
  return (
    <div className="space-y-6">
      <Loading isLoading={isLoading} isError={isError} />
      {data && (
        <>
          <Card padding="none">
            <h2 className="p-4 font-medium text-gray-900 dark:text-white">
              {t('network.interfaces')}
            </h2>
            <table className="w-full">
              <thead>
                <tr>
                  <th className={th}>{t('network.name')}</th>
                  <th className={th}>{t('network.state')}</th>
                  <th className={th}>{t('network.addresses')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                {links.map((l) => (
                  <tr key={l.name}>
                    <td className={td}>{l.name}</td>
                    <td className={td}>{l.state}</td>
                    <td className={td}>{l.addresses.join(', ') || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
          <Card padding="none">
            <h2 className="p-4 font-medium text-gray-900 dark:text-white">{t('network.routes')}</h2>
            <table className="w-full">
              <thead>
                <tr>
                  <th className={th}>{t('network.destination')}</th>
                  <th className={th}>{t('network.gateway')}</th>
                  <th className={th}>{t('network.device')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                {routes.map((r) => (
                  <tr key={`${r.dst}-${r.dev}-${r.gateway}`}>
                    <td className={td}>{r.dst}</td>
                    <td className={td}>{r.gateway || '—'}</td>
                    <td className={td}>{r.dev}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
          <p className="text-xs text-gray-500">{t('network.readOnly')}</p>
        </>
      )}
    </div>
  )
}

// KernelTab: the managed sysctl settings. A change is live at once and is
// undone by the host unless it is kept within confirm_within seconds.
export const KernelTab = ({ step }: { step: Step }) => {
  const { t } = useTranslation('server')
  const { data, isLoading, isError, refetch } = useSysctl()
  const [draft, setDraft] = useState<Record<string, string>>({})
  const [left, setLeft] = useState(0)
  // The server knows whether a change waits (its rollback timer), so the
  // countdown survives a tab switch or a reload.
  const pending = !!data?.pending
  const deadline = data?.pending_until ? Date.parse(data.pending_until) : null
  const apply = useServerChange<unknown>('toasts:failedToApplySysctl')
  const keep = useServerChange<void>('toasts:failedToKeepSysctl', 'toasts:sysctlKept')

  useEffect(() => {
    if (deadline === null) return
    const tick = () => {
      const s = Math.max(0, Math.ceil((deadline - Date.now()) / 1000))
      setLeft(s)
    }
    tick()
    const id = setInterval(tick, 1000)
    // The host restores the old values at the deadline: read them again.
    const done = setTimeout(() => refetch(), Math.max(0, deadline - Date.now()) + 2000)
    return () => {
      clearInterval(id)
      clearTimeout(done)
    }
  }, [deadline, refetch])

  const values = data?.values ?? {}
  const changed = Object.fromEntries(
    Object.entries(draft).filter(([k, v]) => v !== '' && v !== values[k])
  )

  return (
    <Card>
      <Loading isLoading={isLoading} isError={isError} />
      {data && (
        <div className="space-y-4">
          {pending && (
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg bg-yellow-50 p-3 text-sm text-yellow-900 dark:bg-yellow-900/40 dark:text-yellow-200">
              <span>
                {deadline !== null
                  ? t('kernel.pending', { seconds: left })
                  : t('kernel.pendingUnknown')}
              </span>
              <Button
                size="sm"
                loading={keep.isPending}
                onClick={() => keep.mutate(() => step(() => api.confirmSysctl()))}
              >
                {t('kernel.keep')}
              </Button>
            </div>
          )}
          {(data.keys ?? []).map((key) => {
            const field = sysctlField(key)
            const value = draft[key] ?? values[key] ?? ''
            const onChange = (v: string) => setDraft((d) => ({ ...d, [key]: v }))
            return field?.kind === 'select' ? (
              <Select
                key={key}
                label={key}
                value={value}
                onChange={(e) => onChange(e.target.value)}
                options={[
                  ...(field.options.includes(value) ? [] : [{ value, label: value || '—' }]),
                  ...field.options.map((o) => ({ value: o, label: o })),
                ]}
              />
            ) : (
              <Input
                key={key}
                label={key}
                type={field?.kind === 'number' ? 'number' : 'text'}
                min={field?.kind === 'number' ? field.min : undefined}
                max={field?.kind === 'number' ? field.max : undefined}
                value={value}
                onChange={(e) => onChange(e.target.value)}
              />
            )
          })}
          <p className="text-xs text-gray-500">{t('kernel.hint')}</p>
          <div className="flex justify-end gap-2">
            <Button
              variant="secondary"
              onClick={() => setDraft({})}
              disabled={!Object.keys(draft).length}
            >
              {t('kernel.reset')}
            </Button>
            <Button
              loading={apply.isPending}
              disabled={!Object.keys(changed).length || pending}
              onClick={() =>
                apply.mutate(() => step(() => api.setSysctl(changed)), {
                  onSuccess: () => setDraft({}),
                })
              }
            >
              {t('kernel.apply')}
            </Button>
          </div>
        </div>
      )}
    </Card>
  )
}

// The time zones the browser knows, for the time zone field's suggestions.
const timeZones: string[] =
  (Intl as unknown as { supportedValuesOf?: (key: string) => string[] }).supportedValuesOf?.(
    'timeZone'
  ) ?? []

// SystemTab: host name, clock, packages and reboot.
export const SystemTab = ({ step }: { step: Step }) => {
  const { t } = useTranslation('server')
  const { data, isLoading, isError } = useHostSystem()
  const [hostname, setHostname] = useState('')
  const [timezone, setTimezone] = useState('')
  const [ntp, setNtp] = useState<boolean | null>(null)
  const [rebootOpen, setRebootOpen] = useState(false)
  const saveName = useServerChange<unknown>('toasts:failedToSetHostname', 'toasts:hostnameSet')
  const saveZone = useServerChange<unknown>('toasts:failedToSetTimezone', 'toasts:timezoneSet')
  const reboot = useServerChange<void>('toasts:failedToReboot', 'toasts:rebootStarted')

  return (
    <div className="space-y-6">
      <Card>
        <Loading isLoading={isLoading} isError={isError} />
        {data && (
          <div className="space-y-6">
            <dl className="grid gap-3 text-sm sm:grid-cols-2">
              <div>
                <dt className="text-gray-500">{t('system.os')}</dt>
                <dd className="text-gray-900 dark:text-white">{data.os || '—'}</dd>
              </div>
              <div>
                <dt className="text-gray-500">{t('system.kernel')}</dt>
                <dd className="font-mono text-gray-900 dark:text-white">{data.kernel || '—'}</dd>
              </div>
              <div>
                <dt className="text-gray-500">{t('system.clock')}</dt>
                <dd className="text-gray-900 dark:text-white">
                  {data.ntp_synchronized ? t('system.synced') : t('system.notSynced')}
                </dd>
              </div>
            </dl>
            <form
              className="flex flex-wrap items-end gap-2"
              onSubmit={(e) => {
                e.preventDefault()
                saveName.mutate(() => step(() => api.setHostname(hostname)), {
                  onSuccess: () => setHostname(''),
                })
              }}
            >
              <div className="min-w-[16rem] flex-1">
                <Input
                  label={t('system.hostname')}
                  placeholder={data.hostname}
                  value={hostname}
                  onChange={(e) => setHostname(e.target.value)}
                />
              </div>
              <Button
                type="submit"
                loading={saveName.isPending}
                disabled={!hostname || hostname === data.hostname}
              >
                {t('system.save')}
              </Button>
            </form>
            <form
              className="flex flex-wrap items-end gap-2"
              onSubmit={(e) => {
                e.preventDefault()
                saveZone.mutate(
                  () => step(() => api.setTimezone(timezone || data.timezone, ntp ?? data.ntp)),
                  {
                    onSuccess: () => {
                      setTimezone('')
                      setNtp(null)
                    },
                  }
                )
              }}
            >
              <div className="min-w-[16rem] flex-1">
                <Input
                  label={t('system.timezone')}
                  placeholder={data.timezone}
                  value={timezone}
                  list="server-timezones"
                  onChange={(e) => setTimezone(e.target.value)}
                />
                <datalist id="server-timezones">
                  {timeZones.map((z) => (
                    <option key={z} value={z} />
                  ))}
                </datalist>
              </div>
              <label className="flex items-center gap-2 pb-2 text-sm text-gray-700 dark:text-gray-300">
                <input
                  type="checkbox"
                  checked={ntp ?? data.ntp}
                  onChange={(e) => setNtp(e.target.checked)}
                />
                {t('system.ntp')}
              </label>
              <Button
                type="submit"
                loading={saveZone.isPending}
                disabled={
                  (!timezone || timezone === data.timezone) && (ntp === null || ntp === data.ntp)
                }
              >
                {t('system.save')}
              </Button>
            </form>
          </div>
        )}
      </Card>
      <PackagesCard step={step} />
      <Card>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="font-medium text-gray-900 dark:text-white">{t('reboot.title')}</h2>
            <p className="text-sm text-gray-500">{t('reboot.hint')}</p>
          </div>
          <Button variant="danger" loading={reboot.isPending} onClick={() => setRebootOpen(true)}>
            <Power className="mr-1 h-4 w-4" aria-hidden="true" />
            {t('reboot.action')}
          </Button>
        </div>
      </Card>
      <ConfirmWordModal
        isOpen={rebootOpen}
        title={t('reboot.title')}
        description={t('reboot.confirmText')}
        word="reboot"
        actionLabel={t('reboot.action')}
        onClose={() => setRebootOpen(false)}
        onConfirm={() => {
          setRebootOpen(false)
          reboot.mutate(() => step(() => api.rebootServer()))
        }}
      />
    </div>
  )
}

// PackagesCard: upgradable packages and the last apt-get upgrade.
const PackagesCard = ({ step }: { step: Step }) => {
  const { t } = useTranslation('server')
  const { data, isLoading, isError, refetch, isFetching } = useUpgradablePackages()
  const { data: job } = useUpgradeJob()
  const [open, setOpen] = useState(false)
  const upgrade = useServerChange<void>('toasts:failedToStartUpgrade', 'toasts:upgradeStarted')
  const running = !!job?.running
  // When an upgrade ends, the list of upgradable packages has changed.
  const [wasRunning, setWasRunning] = useState(false)
  useEffect(() => {
    if (wasRunning && !running) refetch()
    setWasRunning(running)
  }, [running, wasRunning, refetch])
  const security = (data ?? []).filter((p) => p.security).length

  return (
    <Card>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="font-medium text-gray-900 dark:text-white">{t('packages.title')}</h2>
          {data && (
            <p className="text-sm text-gray-500">
              {t('packages.count', { count: data.length, security })}
            </p>
          )}
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="secondary" loading={isFetching} onClick={() => refetch()}>
            <RefreshCw className="mr-1 h-4 w-4" aria-hidden="true" />
            {t('packages.refresh')}
          </Button>
          <Button
            size="sm"
            variant="danger"
            loading={upgrade.isPending}
            disabled={running || !data?.length}
            onClick={() => setOpen(true)}
          >
            {t('packages.upgrade')}
          </Button>
        </div>
      </div>
      <Loading isLoading={isLoading} isError={isError} />
      {data && data.length > 0 && (
        <ul className="max-h-64 divide-y divide-gray-100 overflow-y-auto text-sm dark:divide-gray-700">
          {data.map((p) => (
            <li key={p.name} className="flex items-center justify-between gap-3 py-2">
              <span className="font-mono text-gray-900 dark:text-white">{p.name}</span>
              <span className="flex items-center gap-2 font-mono text-xs text-gray-500">
                {p.from} → {p.version}
                {p.security && <Badge variant="warning">{t('packages.security')}</Badge>}
              </span>
            </li>
          ))}
        </ul>
      )}
      {job?.started_at && (
        <div className="mt-4 space-y-2">
          <div className="flex flex-wrap items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
            <span>{t('packages.lastRun', { when: when(job.started_at) })}</span>
            <Badge variant={running ? 'info' : job.ok ? 'success' : 'danger'}>
              {running ? t('packages.running') : job.ok ? t('packages.ok') : t('packages.failed')}
            </Badge>
          </div>
          <pre className="max-h-72 overflow-auto rounded-lg bg-gray-900 p-3 text-xs text-gray-100">
            {job.output || '…'}
          </pre>
        </div>
      )}
      <ConfirmWordModal
        isOpen={open}
        title={t('packages.upgrade')}
        description={t('packages.confirmText')}
        word="upgrade"
        actionLabel={t('packages.upgrade')}
        onClose={() => setOpen(false)}
        onConfirm={() => {
          setOpen(false)
          upgrade.mutate(() => step(() => api.startUpgrade()))
        }}
      />
    </Card>
  )
}
