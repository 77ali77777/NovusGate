import { Activity, RotateCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useCan, useRestartNetworkInterface } from '@/api/client'
import { interfaceState } from '@/lib/networkDisplay'
import type { Network } from '@/types'

// NetworkInterfaceStatus: whether the network's hub interface runs on the
// server, as the server reports it. When it is down it says why and offers
// a restart (operators and admins); the server also retries every 30 s.
export const NetworkInterfaceStatus = ({ network }: { network: Network }) => {
  const { t } = useTranslation('networks')
  const canEdit = useCan('operator')
  const restart = useRestartNetworkInterface()
  const { state, reason } = interfaceState(network)
  const tone = {
    up: 'text-green-600 dark:text-green-400',
    down: 'text-red-600 dark:text-red-400',
    unknown: 'text-gray-500 dark:text-gray-400',
  }[state]
  return (
    <div className="space-y-2 text-sm">
      <div className="flex items-center justify-between gap-2">
        <span className="flex items-center gap-2 text-gray-500 dark:text-gray-400">
          <Activity className="h-4 w-4" aria-hidden="true" />
          {t('common:fields.status')}
        </span>
        <span className={`font-medium ${tone}`}>{t(`status.${state}`)}</span>
      </div>
      {state === 'down' && (
        <div className="rounded-lg bg-red-50 p-2 text-xs text-red-800 dark:bg-red-900/20 dark:text-red-200">
          <p>{t('status.downHint')}</p>
          {reason && (
            <p className="mt-1 line-clamp-3 break-words font-mono" title={reason}>
              {reason}
            </p>
          )}
          {canEdit && (
            <button
              type="button"
              onClick={() => restart.mutate(network.id)}
              disabled={restart.isPending}
              className="mt-2 inline-flex items-center gap-1 rounded-md bg-red-600 px-2 py-1 font-medium text-white hover:bg-red-700 disabled:opacity-50"
            >
              <RotateCw
                className={`h-3 w-3 ${restart.isPending ? 'animate-spin' : ''}`}
                aria-hidden="true"
              />
              {restart.isPending ? t('status.restarting') : t('status.restart')}
            </button>
          )}
        </div>
      )}
    </div>
  )
}
