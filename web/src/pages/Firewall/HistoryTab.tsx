import { History, RotateCcw } from 'lucide-react'
import { useFirewallV2History, useFirewallV2State, useRestoreFirewallV2History } from '@/api/client'
import { Badge, Button, Card } from '@/components/ui'
import { PendingBanner } from './AdvancedTab'

// HistoryTab: every applied nftables change with what it added and removed.
// Restore is a normal change: it must be confirmed or it rolls back.
export const HistoryTab = () => {
  const { data, isLoading } = useFirewallV2History()
  const { data: state } = useFirewallV2State()
  const restore = useRestoreFirewallV2History()
  const enforcing = state?.mode === 'nft'
  const entries = data?.entries ?? []

  if (isLoading) return <p className="text-sm text-gray-500">Loading…</p>
  if (!data)
    return (
      <p className="text-sm text-gray-500">
        History needs the nftables engine (FIREWALL_ENGINE=nft).
      </p>
    )

  return (
    <div className="space-y-4">
      {state?.pending && <PendingBanner pending={state.pending} />}
      <Card>
        <div className="mb-4 flex items-center gap-2">
          <History className="h-5 w-5 text-blue-500" />
          <div>
            <h3 className="text-lg font-semibold">Change history</h3>
            <p className="text-sm text-gray-500">
              The newest 200 applied changes. Restoring brings back the rules as they were after
              that change.
            </p>
          </div>
        </div>
        {entries.length === 0 ? (
          <p className="text-sm text-gray-500">No changes recorded yet.</p>
        ) : (
          <div className="divide-y divide-gray-100 dark:divide-gray-700">
            {entries.map((e, i) => (
              <div key={e.id} className="py-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm text-gray-500">
                      {new Date(e.created_at).toLocaleString('az-AZ')}
                    </span>
                    <span className="font-mono text-xs">{e.action}</span>
                    {e.username && <Badge>{e.username}</Badge>}
                    {i === 0 && <Badge variant="success">current</Badge>}
                  </div>
                  {i > 0 && (
                    <Button
                      variant="secondary"
                      size="sm"
                      disabled={!enforcing || !!state?.pending}
                      loading={restore.isPending && restore.variables === e.id}
                      onClick={() => {
                        if (confirm('Restore the firewall rules as they were after this change?'))
                          restore.mutate(e.id)
                      }}
                    >
                      <RotateCcw className="mr-1 h-4 w-4" />
                      Restore
                    </Button>
                  )}
                </div>
                {e.added.length === 0 && e.removed.length === 0 ? (
                  <p className="mt-1 text-xs text-gray-500">No rule changes.</p>
                ) : (
                  <ul className="mt-1 space-y-0.5 font-mono text-xs">
                    {e.added.map((l) => (
                      <li key={`+${l}`} className="text-green-700 dark:text-green-400">
                        + {l}
                      </li>
                    ))}
                    {e.removed.map((l) => (
                      <li key={`-${l}`} className="text-red-700 dark:text-red-400">
                        − {l}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}
