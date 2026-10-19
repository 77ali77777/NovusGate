import { Route } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useSetVPNSettings, useVPNSettings } from '@/api/client'
import { HelpTip } from '@/components/HelpTip'
import { Button, Card } from '@/components/ui'

// VPNPoolCard: the address pool every device config routes (server-side
// routing, P1). Networks are made inside it, so new networks change no
// config; changing the pool itself means every device downloads once more.
export const VPNPoolCard = () => {
  const { t } = useTranslation('settings')
  const { data } = useVPNSettings()
  const save = useSetVPNSettings()
  const [pool, setPool] = useState('')
  useEffect(() => {
    if (data?.pool) setPool(data.pool)
  }, [data?.pool])
  const changed = !!data && pool.trim() !== data.pool

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!changed) return
    if (!confirm(t('vpnPool.confirm', { pool: pool.trim() }))) return
    save.mutate(pool.trim())
  }

  return (
    <Card padding="lg" className="lg:col-span-2">
      <div className="mb-4 flex items-start gap-2">
        <Route className="mt-0.5 h-5 w-5 text-blue-500" />
        <div>
          <h3 className="text-lg font-semibold">{t('vpnPool.title')}</h3>
          <p className="text-sm text-gray-500">{t('vpnPool.description')}</p>
        </div>
      </div>
      <form onSubmit={submit} className="flex flex-wrap items-end gap-3">
        <div className="min-w-[14rem] flex-1">
          <label htmlFor="vpn-pool" className="mb-1 block text-sm font-medium">
            {t('vpnPool.label')}
            <HelpTip k="helpSettings:vpnPool" />
          </label>
          <input
            data-help="helpSettings:vpnPool"
            id="vpn-pool"
            type="text"
            value={pool}
            onChange={(e) => setPool(e.target.value)}
            className="w-full rounded-lg border px-3 py-2 font-mono dark:border-gray-600 dark:bg-gray-700"
            placeholder="10.0.0.0/8"
          />
        </div>
        <Button type="submit" disabled={!changed} loading={save.isPending}>
          {t('vpnPool.save')}
        </Button>
      </form>
      {data?.next_cidr && (
        <p className="mt-2 text-xs text-gray-500">{t('vpnPool.next', { next: data.next_cidr })}</p>
      )}
      <p className="mt-2 text-xs text-amber-700 dark:text-amber-300">{t('vpnPool.warning')}</p>
    </Card>
  )
}
