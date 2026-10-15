import { KeyRound } from 'lucide-react'
import { useDeleteSession, useSessions } from '@/api/client'
import { Badge, Button, Card } from '@/components/ui'

const when = (iso: string) => new Date(iso).toLocaleString('az-AZ')

// SessionsCard: the login sessions that are still valid; any of them can be
// ended. Ending your own logs you out.
export const SessionsCard = () => {
  const { data, isLoading } = useSessions()
  const end = useDeleteSession()
  const sessions = data?.sessions ?? []
  return (
    <Card padding="lg" className="lg:col-span-2">
      <div className="mb-4 flex items-center gap-2">
        <KeyRound className="h-5 w-5 text-blue-500" />
        <div>
          <h3 className="text-lg font-semibold">Active sessions</h3>
          <p className="text-sm text-gray-500">
            Logins that are still valid. End one to sign that browser out.
          </p>
        </div>
      </div>
      {isLoading ? (
        <p className="text-sm text-gray-500">Loading…</p>
      ) : sessions.length === 0 ? (
        <p className="text-sm text-gray-500">No active sessions.</p>
      ) : (
        <div className="divide-y divide-gray-100 dark:divide-gray-700">
          {sessions.map((s) => (
            <div key={s.id} className="flex flex-wrap items-center justify-between gap-2 py-2">
              <div>
                <p className="text-sm font-medium">
                  {s.username} {s.current && <Badge variant="success">this browser</Badge>}
                </p>
                <p className="text-xs text-gray-500">
                  Signed in {when(s.created_at)} · last used {when(s.last_used_at)} · expires{' '}
                  {when(s.expires_at)}
                </p>
              </div>
              <Button
                variant="ghost"
                size="sm"
                loading={end.isPending && end.variables === s.id}
                onClick={() => {
                  const msg = s.current
                    ? 'End your own session? You will be signed out.'
                    : `End this session of ${s.username}?`
                  if (confirm(msg)) end.mutate(s.id)
                }}
              >
                End
              </Button>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}
