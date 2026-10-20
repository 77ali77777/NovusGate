import { useTranslation } from 'react-i18next'
import { useCan } from '@/api/client'
import { PageHeader } from '@/components/Layout'
import { BackupsCard } from './BackupsCard'
import { ChangePasswordCard } from './ChangePasswordCard'
import { EndpointHostCard } from './EndpointHostCard'
import { NotificationsCard } from './NotificationsCard'
import { RolesCard } from './RolesCard'
import { SessionsCard } from './SessionsCard'
import { UserManagementCard } from './UserManagementCard'
import { VPNPoolCard } from './VPNPoolCard'

export const SettingsPage: React.FC = () => {
  const { t } = useTranslation('settings')
  // Users, backups and notifications are admin-only (P9a); every role sees
  // its own sessions (an admin sees everyone's).
  const isAdmin = useCan('admin')
  return (
    <div className="space-y-8">
      <PageHeader title={t('title')} description={t('description')} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <ChangePasswordCard />
        {isAdmin && (
          <>
            <UserManagementCard />
            <RolesCard />
            <BackupsCard />
            <NotificationsCard />
            <VPNPoolCard />
            <EndpointHostCard />
          </>
        )}
        <SessionsCard />
      </div>
    </div>
  )
}
