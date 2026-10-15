import { useTranslation } from 'react-i18next'
import { useAuditLog } from '@/api/client'
import { PageHeader } from '@/components/Layout'
import { Badge, Button, Card } from '@/components/ui'
import { formatDateTime } from '@/i18n'
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
  const { t } = useTranslation('audit')
  const { data, isLoading, isError, fetchNextPage, hasNextPage, isFetchingNextPage } = useAuditLog()
  const entries = data?.pages.flatMap((p) => p.entries) ?? []
  return (
    <div className="space-y-6">
      <PageHeader title={t('title')} description={t('description')} />
      <Card padding="none">
        {isLoading ? (
          <p className="p-6 text-sm text-gray-500">{t('common:state.loading')}</p>
        ) : isError ? (
          <p className="p-6 text-sm text-red-600">{t('loadError')}</p>
        ) : entries.length === 0 ? (
          <p className="p-6 text-sm text-gray-500">{t('empty')}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500 dark:bg-gray-800">
                <tr>
                  <th className="px-4 py-3">{t('common:fields.time')}</th>
                  <th className="px-4 py-3">{t('common:fields.user')}</th>
                  <th className="px-4 py-3">{t('common:fields.action')}</th>
                  <th className="px-4 py-3">{t('columns.result')}</th>
                  <th className="px-4 py-3">{t('columns.address')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                {entries.map((e) => {
                  const { method, target } = parseAction(e.action)
                  const status = typeof e.details.status === 'number' ? e.details.status : undefined
                  return (
                    <tr key={e.id}>
                      <td className="whitespace-nowrap px-4 py-2 text-gray-500">
                        {formatDateTime(e.created_at)}
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
            {t('loadOlder')}
          </Button>
        </div>
      )}
    </div>
  )
}
