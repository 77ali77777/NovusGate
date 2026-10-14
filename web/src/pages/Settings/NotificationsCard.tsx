import { Bell } from 'lucide-react'
import { useEffect, useState } from 'react'
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

const EVENTS: { key: keyof NotificationEvents; label: string }[] = [
  { key: 'node_offline', label: 'A node goes offline or comes back' },
  { key: 'node_expired', label: "A node's access expires" },
  { key: 'fail2ban_ban', label: 'Fail2Ban bans an address' },
  { key: 'firewall_change', label: 'The firewall is changed' },
]

const EMPTY: NotificationForm = {
  enabled: false,
  chat_id: '',
  bot_token: '',
  node_offline: true,
  node_expired: true,
  fail2ban_ban: true,
  firewall_change: true,
}

// NotificationsCard: Telegram notifications (P8). The bot token is write-only:
// the server never returns it, and an empty field keeps the stored one.
export const NotificationsCard = () => {
  const { data, isLoading } = useNotificationSettings()
  const save = useUpdateNotificationSettings()
  const test = useTestNotification()
  const [form, setForm] = useState<NotificationForm>(EMPTY)
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
          <h3 className="text-lg font-semibold">Telegram notifications</h3>
          <p className="text-sm text-gray-500">
            Create a bot with @BotFather, add it to your chat, then enter the bot token and the chat
            ID.
          </p>
        </div>
      </div>
      {isLoading ? (
        <p className="text-sm text-gray-500">Loading…</p>
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
              Send notifications
            </label>
          </div>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <Input
              label="Chat ID"
              placeholder="-1001234567890 or @channel"
              value={form.chat_id}
              onChange={(e) => setForm({ ...form, chat_id: e.target.value })}
            />
            <Input
              label="Bot token"
              type="password"
              autoComplete="off"
              placeholder={tokenStored ? 'Stored — leave empty to keep it' : '123456789:ABC…'}
              value={form.bot_token}
              onChange={(e) => setForm({ ...form, bot_token: e.target.value })}
            />
          </div>
          <fieldset className="space-y-2">
            <legend className="mb-1 text-sm font-medium">Notify when</legend>
            {EVENTS.map((ev) => (
              <div key={ev.key} className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id={`notify-${ev.key}`}
                  checked={form[ev.key]}
                  onChange={(e) => setForm({ ...form, [ev.key]: e.target.checked })}
                  className="rounded"
                />
                <label htmlFor={`notify-${ev.key}`} className="text-sm">
                  {ev.label}
                </label>
              </div>
            ))}
          </fieldset>
          {error && <p className="text-sm text-red-600">{error}</p>}
          <div className="flex flex-wrap gap-2">
            <Button type="submit" loading={save.isPending}>
              Save
            </Button>
            <Button
              type="button"
              variant="secondary"
              loading={test.isPending}
              disabled={!tokenStored || !data?.chat_id}
              onClick={() => test.mutate()}
            >
              Send test message
            </Button>
          </div>
        </form>
      )}
    </Card>
  )
}
