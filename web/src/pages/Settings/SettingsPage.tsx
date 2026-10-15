import { useTranslation } from 'react-i18next'
import { PageHeader } from '@/components/Layout'
import { BackupsCard } from './BackupsCard'
import { ChangePasswordCard } from './ChangePasswordCard'
import { NotificationsCard } from './NotificationsCard'
import { SessionsCard } from './SessionsCard'
import { UserManagementCard } from './UserManagementCard'

export const SettingsPage: React.FC = () => {
  const { t } = useTranslation('settings')
  return (
    <div className="space-y-8">
      <PageHeader title={t('title')} description={t('description')} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <ChangePasswordCard />
        <UserManagementCard />
        <BackupsCard />
        <NotificationsCard />
        <SessionsCard />
      </div>
    </div>
  )
}
