import { Shield, Trash2, User, UserPlus } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useCreateUser, useDeleteUser, useSetUserRole, useUsers } from '@/api/client'
import { apiErrorMessage } from '@/api/errors'
import { locale } from '@/i18n'
import type { UserRole } from '@/types'

const roles: UserRole[] = ['admin', 'operator', 'viewer']

export const UserManagementCard: React.FC = () => {
  const { t } = useTranslation('settings')
  const { data: users, isLoading } = useUsers()
  const createUser = useCreateUser()
  const deleteUser = useDeleteUser()
  const setRole = useSetUserRole()

  const [isAdding, setIsAdding] = useState(false)
  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newRole, setNewRole] = useState<UserRole>('viewer')
  const [error, setError] = useState('')

  const handleAddUser = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    try {
      await createUser.mutateAsync({ username: newUsername, password: newPassword, role: newRole })
      setNewUsername('')
      setNewPassword('')
      setNewRole('viewer')
      setIsAdding(false)
    } catch (err) {
      setError(apiErrorMessage(err, t('users.failed')))
    }
  }

  const handleDelete = async (id: string, username: string) => {
    if (username === 'admin') {
      alert(t('users.cannotDeleteAdmin')) // Simple protection
      return
    }
    if (confirm(t('users.deleteConfirm', { username }))) {
      await deleteUser.mutateAsync(id)
    }
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 overflow-hidden">
      <div className="p-6 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-purple-100 dark:bg-purple-900/50 rounded-lg text-purple-600 dark:text-purple-400">
            <Shield className="w-5 h-5" />
          </div>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            {t('users.title')}
          </h2>
        </div>
        <button
          type="button"
          onClick={() => setIsAdding(!isAdding)}
          className="flex items-center gap-2 px-3 py-1.5 text-sm font-medium text-blue-600 hover:bg-blue-50 dark:text-blue-400 dark:hover:bg-blue-900/20 rounded-lg transition-colors"
        >
          <UserPlus className="w-4 h-4" />
          {t('users.add')}
        </button>
      </div>

      <div className="p-6">
        {isAdding && (
          <form
            onSubmit={handleAddUser}
            className="mb-6 p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg space-y-4"
          >
            <h3 className="text-sm font-medium text-gray-900 dark:text-white">
              {t('users.newDetails')}
            </h3>
            {error && <div className="text-sm text-red-600 dark:text-red-400">{error}</div>}
            <div className="grid grid-cols-2 gap-4">
              <input
                type="text"
                placeholder={t('users.usernamePlaceholder')}
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                className="px-3 py-2 text-sm border rounded-lg dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                required
              />
              <input
                type="password"
                placeholder={t('users.passwordPlaceholder')}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="px-3 py-2 text-sm border rounded-lg dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                required
              />
            </div>
            <label className="block text-sm text-gray-700 dark:text-gray-300">
              {t('users.role')}
              <select
                value={newRole}
                onChange={(e) => setNewRole(e.target.value as UserRole)}
                className="mt-1 w-full px-3 py-2 text-sm border rounded-lg dark:bg-gray-700 dark:border-gray-600 dark:text-white"
              >
                {roles.map((r) => (
                  <option key={r} value={r}>
                    {t(`users.roles.${r}`)}
                  </option>
                ))}
              </select>
              <span className="block mt-1 text-xs text-gray-500 dark:text-gray-400">
                {t(`users.roleHints.${newRole}`)}
              </span>
            </label>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setIsAdding(false)}
                className="px-3 py-1.5 text-sm text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white"
              >
                {t('common:actions.cancel')}
              </button>
              <button
                type="submit"
                disabled={createUser.isPending}
                className="px-3 py-1.5 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                {t('common:actions.create')}
              </button>
            </div>
          </form>
        )}

        {isLoading ? (
          <div className="text-center py-4 text-gray-500">{t('users.loading')}</div>
        ) : (
          <div className="space-y-2">
            {users?.map((user) => (
              <div
                key={user.id}
                className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/30 rounded-lg group"
              >
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-full bg-gray-200 dark:bg-gray-600 flex items-center justify-center text-gray-500 dark:text-gray-300">
                    <User className="w-4 h-4" />
                  </div>
                  <div>
                    <p className="text-sm font-medium text-gray-900 dark:text-white">
                      {user.username}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      {t('users.created', {
                        date: new Date(user.created_at).toLocaleDateString(locale()),
                      })}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <select
                    aria-label={t('users.roleFor', { username: user.username })}
                    value={user.role}
                    disabled={setRole.isPending}
                    onChange={(e) =>
                      setRole.mutate({ id: user.id, role: e.target.value as UserRole })
                    }
                    className="px-2 py-1 text-xs border rounded-lg dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                  >
                    {roles.map((r) => (
                      <option key={r} value={r}>
                        {t(`users.roles.${r}`)}
                      </option>
                    ))}
                  </select>
                  {user.username !== 'admin' && ( // Hide delete for admin
                    <button
                      type="button"
                      onClick={() => handleDelete(user.id, user.username)}
                      className="p-2 text-gray-400 hover:text-red-600 dark:hover:text-red-400 opacity-0 group-hover:opacity-100 transition-opacity"
                      title={t('users.delete')}
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </div>
              </div>
            ))}
            {users?.length === 0 && (
              <p className="text-center text-gray-500 py-4">{t('users.empty')}</p>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
