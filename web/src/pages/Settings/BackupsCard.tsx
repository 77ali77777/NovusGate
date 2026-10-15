import { Archive, Download, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { api, useBackups, useCreateBackup, useDeleteBackup } from '@/api/client'
import { apiErrorMessage } from '@/api/errors'
import { Button, Card } from '@/components/ui'
import { formatDateTime } from '@/i18n'
import { useAppStore } from '@/store'

const formatSize = (bytes: number) => {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

// BackupsCard: manual backups (P8). A backup is the database dump and the
// WireGuard configs; it holds private keys. Restore is manual (docs).
export const BackupsCard = () => {
  const { t } = useTranslation('settings')
  const { data, isLoading } = useBackups()
  const create = useCreateBackup()
  const remove = useDeleteBackup()
  const backups = data?.backups ?? []

  const download = async (name: string) => {
    try {
      const blob = await api.downloadBackup(name)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = name
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
    } catch (err) {
      useAppStore.getState().addNotification({
        type: 'error',
        title: t('backups.downloadFailed'),
        message: apiErrorMessage(err, t('backups.serverError')),
      })
    }
  }

  return (
    <Card padding="lg" className="lg:col-span-2">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Archive className="h-5 w-5 text-blue-500" />
          <div>
            <h3 className="text-lg font-semibold">{t('backups.title')}</h3>
            <p className="text-sm text-gray-500">{t('backups.description')}</p>
          </div>
        </div>
        <Button onClick={() => create.mutate()} loading={create.isPending}>
          {t('backups.now')}
        </Button>
      </div>
      {isLoading ? (
        <p className="text-sm text-gray-500">{t('common:state.loading')}</p>
      ) : backups.length === 0 ? (
        <p className="text-sm text-gray-500">{t('backups.empty')}</p>
      ) : (
        <div className="divide-y divide-gray-100 dark:divide-gray-700">
          {backups.map((b) => (
            <div key={b.name} className="flex flex-wrap items-center justify-between gap-2 py-2">
              <div>
                <p className="font-mono text-sm">{b.name}</p>
                <p className="text-xs text-gray-500">
                  {formatDateTime(b.created_at)} · {formatSize(b.size)}
                </p>
              </div>
              <div className="flex gap-2">
                <Button variant="secondary" size="sm" onClick={() => download(b.name)}>
                  <Download className="mr-1 h-4 w-4" />
                  {t('common:actions.download')}
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  aria-label={t('backups.deleteLabel', { name: b.name })}
                  onClick={() => {
                    if (confirm(t('backups.deleteConfirm', { name: b.name }))) remove.mutate(b.name)
                  }}
                >
                  <Trash2 className="h-4 w-4 text-red-600" />
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}
