import { AlertTriangle, CheckCircle, Info, X, XCircle } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useAppStore, useNotifications } from '@/store'

const styles = {
  success: { box: 'border-green-200 bg-green-50 text-green-800', Icon: CheckCircle },
  error: { box: 'border-red-200 bg-red-50 text-red-800', Icon: XCircle },
  warning: { box: 'border-amber-200 bg-amber-50 text-amber-800', Icon: AlertTriangle },
  info: { box: 'border-blue-200 bg-blue-50 text-blue-800', Icon: Info },
}

// Toaster shows the store's notifications (mutation results). Errors stay
// until closed; the store removes the others after 5 seconds.
export const Toaster = () => {
  const { t } = useTranslation('layout')
  const notifications = useNotifications()
  const remove = useAppStore((s) => s.removeNotification)
  if (notifications.length === 0) return null
  return (
    <div className="fixed bottom-4 right-4 z-[60] flex w-full max-w-sm flex-col gap-2 px-4 sm:px-0">
      {notifications.map((n) => {
        const { box, Icon } = styles[n.type]
        return (
          <div
            key={n.id}
            role={n.type === 'error' ? 'alert' : 'status'}
            className={`flex items-start gap-3 rounded-xl border p-3 shadow-lg ${box}`}
          >
            <Icon className="mt-0.5 h-5 w-5 flex-shrink-0" />
            <div className="min-w-0 flex-1">
              <p className="text-sm font-semibold">{n.title}</p>
              {n.message && <p className="mt-0.5 break-words text-sm">{n.message}</p>}
            </div>
            <button
              type="button"
              aria-label={t('dismiss')}
              onClick={() => remove(n.id)}
              className="rounded p-1 opacity-70 hover:opacity-100"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        )
      })}
    </div>
  )
}
