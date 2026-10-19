import { Globe } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useSetEndpointHost, useVPNSettings } from '@/api/client'
import { HelpTip } from '@/components/HelpTip'
import { Button, Card } from '@/components/ui'

// EndpointHostCard: the name device configs reach the hub by (server-side
// routing, P2). With a domain, a new server IP changes only a DNS record;
// empty keeps the server's IP address.
export const EndpointHostCard = () => {
  const { t } = useTranslation('settings')
  const { data } = useVPNSettings()
  const save = useSetEndpointHost()
  const [host, setHost] = useState('')
  useEffect(() => {
    if (data) setHost(data.endpoint_host)
  }, [data])
  const changed = !!data && host.trim().toLowerCase() !== data.endpoint_host

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!changed) return
    if (!confirm(t('endpointHost.confirm'))) return
    save.mutate(host.trim())
  }

  return (
    <Card padding="lg" className="lg:col-span-2">
      <div className="mb-4 flex items-start gap-2">
        <Globe className="mt-0.5 h-5 w-5 text-blue-500" />
        <div>
          <h3 className="text-lg font-semibold">{t('endpointHost.title')}</h3>
          <p className="text-sm text-gray-500">{t('endpointHost.description')}</p>
        </div>
      </div>
      <form onSubmit={submit} className="flex flex-wrap items-end gap-3">
        <div className="min-w-[14rem] flex-1">
          <label htmlFor="endpoint-host" className="mb-1 block text-sm font-medium">
            {t('endpointHost.label')}
            <HelpTip k="helpSettings:endpointHost" />
          </label>
          <input
            data-help="helpSettings:endpointHost"
            id="endpoint-host"
            type="text"
            value={host}
            onChange={(e) => setHost(e.target.value)}
            className="w-full rounded-lg border px-3 py-2 font-mono dark:border-gray-600 dark:bg-gray-700"
            placeholder={t('endpointHost.placeholder')}
          />
        </div>
        <Button type="submit" disabled={!changed} loading={save.isPending}>
          {t('endpointHost.save')}
        </Button>
      </form>
      <p className="mt-2 text-xs text-gray-500">
        {data?.endpoint_host
          ? t('endpointHost.using', { host: data.endpoint_host })
          : t('endpointHost.usingIp', { ip: data?.endpoint_default ?? '' })}
      </p>
      <p className="mt-2 text-xs text-amber-700 dark:text-amber-300">{t('endpointHost.warning')}</p>
    </Card>
  )
}
