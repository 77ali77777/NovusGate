import { KeyRound, Pencil, Plus, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useCreateRole, useDeleteRole, useNetworks, useRoles, useUpdateRole } from '@/api/client'
import { HelpTip } from '@/components/HelpTip'
import { Button, Card, Modal } from '@/components/ui'
import { networkLabel } from '@/lib/networkDisplay'
import type { Role, RoleRequest } from '@/types'

type Level = 'none' | 'view' | 'edit'
const LEVELS: Level[] = ['none', 'view', 'edit']

const fieldClass = 'w-full rounded-lg border px-3 py-2 dark:border-gray-600 dark:bg-gray-700'

interface Section {
  key: string
  editable: boolean
  inside_scope: boolean
}

// template fills the levels the way a built-in role has them.
function template(sections: Section[], kind: 'operator' | 'viewer'): Record<string, Level> {
  const out: Record<string, Level> = {}
  for (const s of sections) {
    if (kind === 'viewer') out[s.key] = s.key === 'configs' ? 'none' : 'view'
    else out[s.key] = s.editable ? 'edit' : 'view'
  }
  return out
}

// RoleEditor: name, description, one level per section and the networks.
const RoleEditor = ({
  role,
  sections,
  onClose,
}: {
  role: Role | null
  sections: Section[]
  onClose: () => void
}) => {
  const { t } = useTranslation('settings')
  const { data: networks = [] } = useNetworks()
  const create = useCreateRole()
  const update = useUpdateRole()
  const [name, setName] = useState(role?.name ?? '')
  const [description, setDescription] = useState(role?.description ?? '')
  const [perms, setPerms] = useState<Record<string, Level>>(
    () => (role?.permissions as Record<string, Level>) ?? template(sections, 'viewer')
  )
  const [nets, setNets] = useState<string[]>(role?.network_ids ?? [])
  const scoped = nets.length > 0

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    // A role limited to networks keeps only the sections inside them: the
    // others are stored as hidden, so removing the limit later opens nothing.
    const permissions = Object.fromEntries(
      sections.map((s) => [s.key, scoped && !s.inside_scope ? 'none' : (perms[s.key] ?? 'none')])
    )
    const body: RoleRequest = { name, description, permissions, network_ids: nets }
    const done = { onSuccess: onClose }
    if (role) update.mutate({ id: role.id, body }, done)
    else create.mutate(body, done)
  }

  return (
    <Modal isOpen onClose={onClose} title={role ? t('roles.edit') : t('roles.new')} size="lg">
      <form onSubmit={submit} className="space-y-4">
        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <label htmlFor="role-name" className="mb-1 block text-sm font-medium">
              {t('roles.name')}
              <HelpTip k="helpSettings:roles.name" />
            </label>
            <input
              data-help="helpSettings:roles.name"
              id="role-name"
              type="text"
              required
              maxLength={100}
              value={name}
              onChange={(e) => setName(e.target.value)}
              className={fieldClass}
              placeholder={t('roles.namePlaceholder')}
            />
          </div>
          <div>
            <label htmlFor="role-description" className="mb-1 block text-sm font-medium">
              {t('roles.description')}
              <HelpTip k="helpSettings:roles.description" />
            </label>
            <input
              data-help="helpSettings:roles.description"
              id="role-description"
              type="text"
              maxLength={500}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className={fieldClass}
            />
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="text-gray-500">{t('roles.startFrom')}</span>
          <Button
            type="button"
            size="sm"
            variant="secondary"
            onClick={() => setPerms(template(sections, 'viewer'))}
          >
            {t('roles.likeViewer')}
          </Button>
          <Button
            type="button"
            size="sm"
            variant="secondary"
            onClick={() => setPerms(template(sections, 'operator'))}
          >
            {t('roles.likeOperator')}
          </Button>
        </div>

        <div className="overflow-x-auto rounded-lg border border-gray-200 dark:border-gray-700">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500 dark:bg-gray-800">
              <tr>
                <th className="px-3 py-2">
                  {t('roles.section')}
                  <HelpTip k="helpSettings:roles.level" />
                </th>
                {LEVELS.map((l) => (
                  <th key={l} className="px-3 py-2 text-center">
                    {t(`roles.levels.${l}`)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
              {sections.map((s) => {
                const off = scoped && !s.inside_scope
                return (
                  <tr key={s.key} className={off ? 'opacity-50' : ''}>
                    <td className="px-3 py-2">
                      <p className="font-medium">{t(`roles.sections.${s.key}`)}</p>
                      <p className="text-xs text-gray-500">{t(`roles.sectionHints.${s.key}`)}</p>
                    </td>
                    {LEVELS.map((l) => (
                      <td key={l} className="px-3 py-2 text-center">
                        <input
                          data-help="helpSettings:roles.level"
                          type="radio"
                          name={`level-${s.key}`}
                          aria-label={`${t(`roles.sections.${s.key}`)}: ${t(`roles.levels.${l}`)}`}
                          checked={(perms[s.key] ?? 'none') === l}
                          disabled={off || (l === 'edit' && !s.editable)}
                          onChange={() => setPerms((p) => ({ ...p, [s.key]: l }))}
                        />
                      </td>
                    ))}
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
        <p className="text-xs text-gray-500">{t('roles.adminOnlyNote')}</p>

        <fieldset className="space-y-2">
          <legend className="text-sm font-medium">
            {t('roles.networks')}
            <HelpTip k="helpSettings:roles.networks" />
          </legend>
          <p className="text-xs text-gray-500">
            {scoped ? t('roles.scopedNote') : t('roles.allNetworks')}
          </p>
          <div className="flex flex-wrap gap-3">
            {networks.map((n) => (
              <label key={n.id} className="flex items-center gap-2 text-sm">
                <input
                  data-help="helpSettings:roles.networks"
                  type="checkbox"
                  checked={nets.includes(n.id)}
                  onChange={(e) =>
                    setNets((cur) =>
                      e.target.checked ? [...cur, n.id] : cur.filter((x) => x !== n.id)
                    )
                  }
                />
                {networkLabel(n, t).name}
              </label>
            ))}
            {/* A network deleted since stays in the role (the role does not turn
                into "every network"); unticking it is the admin's choice. */}
            {nets
              .filter((id) => !networks.some((n) => n.id === id))
              .map((id) => (
                <label key={id} className="flex items-center gap-2 text-sm text-gray-500">
                  <input
                    data-help="helpSettings:roles.networks"
                    type="checkbox"
                    checked
                    onChange={() => setNets((cur) => cur.filter((x) => x !== id))}
                  />
                  {t('roles.deletedNetwork')}
                </label>
              ))}
          </div>
        </fieldset>

        <div className="flex justify-end gap-2 border-t pt-4 dark:border-gray-700">
          <Button type="button" variant="secondary" onClick={onClose}>
            {t('common:actions.cancel')}
          </Button>
          <Button type="submit" loading={create.isPending || update.isPending}>
            {t('common:actions.save')}
          </Button>
        </div>
      </form>
    </Modal>
  )
}

// RolesCard: the custom roles (admin). A role says per section whether its
// users see it, change it or not, and optionally the networks it is
// limited to; users get one under Users.
export const RolesCard = () => {
  const { t } = useTranslation('settings')
  const { data } = useRoles()
  const remove = useDeleteRole()
  const { data: networks = [] } = useNetworks()
  const [editing, setEditing] = useState<Role | null | 'new'>(null)
  const roles = (data?.roles ?? []).filter((r) => r !== null)
  const sections = (data?.sections ?? []).filter((s) => s !== null) as Section[]
  const netName = (id: string) => {
    const n = networks.find((x) => x.id === id)
    return n ? networkLabel(n, t).name : id
  }

  return (
    <Card padding="lg" className="lg:col-span-2">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-start gap-2">
          <KeyRound className="mt-0.5 h-5 w-5 text-blue-500" />
          <div>
            <h3 className="text-lg font-semibold">{t('roles.title')}</h3>
            <p className="text-sm text-gray-500">{t('roles.description_text')}</p>
          </div>
        </div>
        <Button onClick={() => setEditing('new')}>
          <Plus className="mr-1 h-4 w-4" /> {t('roles.new')}
        </Button>
      </div>
      {roles.length === 0 ? (
        <p className="text-sm text-gray-500">{t('roles.empty')}</p>
      ) : (
        <ul className="divide-y divide-gray-100 dark:divide-gray-700">
          {roles.map((r) => (
            <li key={r.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
              <div>
                <p className="font-medium">{r.name}</p>
                {r.description && <p className="text-xs text-gray-500">{r.description}</p>}
                <p className="text-xs text-gray-500">
                  {t('roles.summary', { count: r.users })} ·{' '}
                  {(r.network_ids ?? []).length > 0
                    ? t('roles.onlyNetworks', {
                        names: (r.network_ids ?? []).map(netName).join(', '),
                      })
                    : t('roles.allNetworks')}
                </p>
              </div>
              <div className="flex gap-1">
                <Button
                  variant="ghost"
                  size="sm"
                  title={t('roles.edit')}
                  onClick={() => setEditing(r)}
                >
                  <Pencil className="h-4 w-4" />
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  title={t('roles.delete')}
                  disabled={r.users > 0}
                  onClick={() => {
                    if (confirm(t('roles.deleteConfirm', { name: r.name }))) remove.mutate(r.id)
                  }}
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </div>
            </li>
          ))}
        </ul>
      )}
      {editing && (
        <RoleEditor
          role={editing === 'new' ? null : editing}
          sections={sections}
          onClose={() => setEditing(null)}
        />
      )}
    </Card>
  )
}
