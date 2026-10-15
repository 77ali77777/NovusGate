import { useAuditLog } from '@/api/client'
import { PageHeader } from '@/components/Layout'
import { Badge, Button, Card } from '@/components/ui'
import { parseAction } from '@/lib/audit'

const methodVariant: Record<string, 'success' | 'info' | 'warning' | 'danger' | 'default'> = {
  POST: 'success',
  PUT: 'info',
  PATCH: 'info',
  DELETE: 'danger',
}

// AuditPage: who changed what through the panel or the API, and every login
// attempt. Entries are kept in the database (firewall_audit_log).
export const AuditPage = () => {
  const { data, isLoading, isError, fetchNextPage, hasNextPage, isFetchingNextPage } = useAuditLog()
  const entries = data?.pages.flatMap((p) => p.entries) ?? []
  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit log"
        description="Changes made through the panel or the API, and login attempts."
      />
      <Card padding="none">
        {isLoading ? (
          <p className="p-6 text-sm text-gray-500">Loading…</p>
        ) : isError ? (
          <p className="p-6 text-sm text-red-600">The audit log could not be loaded.</p>
        ) : entries.length === 0 ? (
          <p className="p-6 text-sm text-gray-500">Nothing recorded yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500 dark:bg-gray-800">
                <tr>
                  <th className="px-4 py-3">Time</th>
                  <th className="px-4 py-3">User</th>
                  <th className="px-4 py-3">Action</th>
                  <th className="px-4 py-3">Result</th>
                  <th className="px-4 py-3">Address</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                {entries.map((e) => {
                  const { method, target } = parseAction(e.action)
                  const status = typeof e.details.status === 'number' ? e.details.status : undefined
                  return (
                    <tr key={e.id}>
                      <td className="whitespace-nowrap px-4 py-2 text-gray-500">
                        {new Date(e.created_at).toLocaleString('az-AZ')}
                      </td>
                      <td className="px-4 py-2">{e.username || '—'}</td>
                      <td className="px-4 py-2">
                        {method && (
                          <Badge variant={methodVariant[method] ?? 'default'}>{method}</Badge>
                        )}{' '}
                        <span className="font-mono text-xs">{target}</span>
                      </td>
                      <td className="px-4 py-2">
                        {status !== undefined && (
                          <Badge variant={status < 300 ? 'success' : 'danger'}>{status}</Badge>
                        )}
                      </td>
                      <td className="px-4 py-2 font-mono text-xs">{e.user_ip || '—'}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {hasNextPage && (
        <div className="flex justify-center">
          <Button variant="secondary" onClick={() => fetchNextPage()} loading={isFetchingNextPage}>
            Load older entries
          </Button>
        </div>
      )}
    </div>
  )
}
