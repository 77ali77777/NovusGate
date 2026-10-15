import { Bell } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  useNotificationSettings,
  useTestNotification,
  useUpdateNotificationSettings,
} from '@/api/client'
import { Button, Card, Input } from '@/components/ui'
import {
  type NotificationEvents,
  type NotificationForm,
  notificationUpdate,
} from '@/lib/notifications'

// Each event's label is settings:notifications.events.<key>.
const EVENTS: (keyof NotificationEvents)[] = [
  'node_offline',
  'node_expired',
  'fail2ban_ban',
  'firewall_change',
  'quota_exceeded',
]

const EMPTY: NotificationForm = {
  enabled: false,
  chat_id: '',
  bot_token: '',
  node_offline: true,
  node_expired: true,
  fail2ban_ban: true,
  firewall_change: true,
  quota_exceeded: true,
}

// NotificationsCard: Telegram notifications (P8). The bot token is write-only:
// the server never returns it, and an empty field keeps the stored one.
export const NotificationsCard = () => {
  const { t } = useTranslation('settings')
  const { data, isLoading } = useNotificationSettings()
  const save = useUpdateNotificationSettings()
  const test = useTestNotification()
  const [form, setForm] = useState<NotificationForm>(EMPTY)
  // error holds a settings locale key from notificationUpdate.
  const [error, setError] = useState('')

  useEffect(() => {
    if (data) setForm({ ...data, bot_token: '' })
  }, [data])

  const tokenStored = data?.token_set ?? false

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const { request, error: invalid } = notificationUpdate(form, tokenStored)
    setError(invalid ?? '')
    if (invalid) return
    save.mutate(request)
  }

  return (
    <Card padding="lg" className="lg:col-span-2">
      <div className="mb-4 flex items-center gap-2">
        <Bell className="h-5 w-5 text-blue-500" />
        <div>
          <h3 className="text-lg font-semibold">{t('notifications.title')}</h3>
          <p className="text-sm text-gray-500">{t('notifications.description')}</p>
        </div>
      </div>
      {isLoading ? (
        <p className="text-sm text-gray-500">{t('common:state.loading')}</p>
      ) : (
        <form onSubmit={submit} className="space-y-4">
          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="notify-enabled"
              checked={form.enabled}
              onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
              className="rounded"
            />
            <label htmlFor="notify-enabled" className="text-sm font-medium">
              {t('notifications.enabled')}
            </label>
          </div>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <Input
              label={t('notifications.chatId')}
              placeholder={t('notifications.chatIdPlaceholder')}
              value={form.chat_id}
              onChange={(e) => setForm({ ...form, chat_id: e.target.value })}
            />
            <Input
              label={t('notifications.botToken')}
              type="password"
              autoComplete="off"
              placeholder={tokenStored ? t('notifications.tokenStored') : '123456789:ABC…'}
              value={form.bot_token}
              onChange={(e) => setForm({ ...form, bot_token: e.target.value })}
            />
          </div>
          <fieldset className="space-y-2">
            <legend className="mb-1 text-sm font-medium">{t('notifications.notifyWhen')}</legend>
            {EVENTS.map((ev) => (
              <div key={ev} className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id={`notify-${ev}`}
                  checked={form[ev]}
                  onChange={(e) => setForm({ ...form, [ev]: e.target.checked })}
                  className="rounded"
                />
                <label htmlFor={`notify-${ev}`} className="text-sm">
                  {t(`notifications.events.${ev}`)}
                </label>
              </div>
            ))}
          </fieldset>
          {error && <p className="text-sm text-red-600">{t(error)}</p>}
          <div className="flex flex-wrap gap-2">
            <Button type="submit" loading={save.isPending}>
              {t('common:actions.save')}
            </Button>
            <Button
              type="button"
              variant="secondary"
              loading={test.isPending}
              disabled={!tokenStored || !data?.chat_id}
              onClick={() => test.mutate()}
            >
              {t('notifications.sendTest')}
            </Button>
          </div>
        </form>
      )}
    </Card>
  )
}
