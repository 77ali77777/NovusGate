import { Pencil, Plus, Trash2, Users } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  useCan,
  useCreateGroup,
  useDeleteGroup,
  useGroups,
  useNetworks,
  useNodes,
  useSetGroupMembers,
  useUpdateGroup,
} from '@/api/client'
import { PageHeader } from '@/components/Layout'
import { Badge, Button, Card, EmptyState, Input, Modal } from '@/components/ui'
import type { NodeGroup } from '@/types'

// GroupsPage: named sets of nodes, from any network, that VPN rules can use
// as a source or destination (P9a). Changing members re-applies those rules.
export const GroupsPage = () => {
  const { t } = useTranslation('groups')
  const { data, isLoading, isError } = useGroups()
  const canEdit = useCan('operator')
  const deleteGroup = useDeleteGroup()
  const [editing, setEditing] = useState<NodeGroup | 'new' | null>(null)
  const [membersOf, setMembersOf] = useState<NodeGroup | null>(null)
  const groups = (data?.groups ?? []).filter((g): g is NodeGroup => g !== null)

  const handleDelete = (g: NodeGroup) => {
    if (confirm(t('deleteConfirm', { name: g.name }))) deleteGroup.mutate(g.id)
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('title')}
        description={t('description')}
        actions={
          canEdit && (
            <Button size="sm" onClick={() => setEditing('new')}>
              <Plus className="w-4 h-4 mr-1" /> {t('add')}
            </Button>
          )
        }
      />
      <Card padding="none">
        {isLoading ? (
          <p className="p-6 text-sm text-gray-500">{t('common:state.loading')}</p>
        ) : isError ? (
          <p className="p-6 text-sm text-red-600">{t('loadError')}</p>
        ) : groups.length === 0 ? (
          <EmptyState
            icon={<Users className="w-10 h-10" />}
            title={t('empty')}
            description={t('emptyHint')}
          />
        ) : (
          <ul className="divide-y divide-gray-100 dark:divide-gray-700">
            {groups.map((g) => (
              <li key={g.id} className="flex items-start justify-between gap-4 p-4">
                <div className="min-w-0">
                  <p className="font-medium text-gray-900 dark:text-white">{g.name}</p>
                  {g.description && <p className="text-sm text-gray-500">{g.description}</p>}
                  <div className="mt-2 flex flex-wrap gap-1">
                    {(g.members ?? []).length === 0 ? (
                      <span className="text-xs text-gray-400">{t('noMembers')}</span>
                    ) : (
                      (g.members ?? []).map((m) => (
                        <Badge key={m.node_id}>
                          {m.name} <span className="font-mono">{m.virtual_ip}</span>
                        </Badge>
                      ))
                    )}
                  </div>
                </div>
                {canEdit && (
                  <div className="flex shrink-0 items-center gap-1">
                    <Button variant="secondary" size="sm" onClick={() => setMembersOf(g)}>
                      <Users className="w-4 h-4 mr-1" /> {t('members')}
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setEditing(g)}
                      title={t('common:actions.edit')}
                    >
                      <Pencil className="w-4 h-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleDelete(g)}
                      loading={deleteGroup.isPending}
                      title={t('common:actions.delete')}
                    >
                      <Trash2 className="w-4 h-4 text-red-500" />
                    </Button>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>
      {editing && (
        <GroupModal group={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />
      )}
      {membersOf && <MembersModal group={membersOf} onClose={() => setMembersOf(null)} />}
    </div>
  )
}

const GroupModal = ({ group, onClose }: { group: NodeGroup | null; onClose: () => void }) => {
  const { t } = useTranslation('groups')
  const create = useCreateGroup()
  const update = useUpdateGroup()
  const [name, setName] = useState(group?.name ?? '')
  const [description, setDescription] = useState(group?.description ?? '')
  const pending = create.isPending || update.isPending

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (group) await update.mutateAsync({ id: group.id, name, description })
    else await create.mutateAsync({ name, description })
    onClose()
  }

  return (
    <Modal isOpen onClose={onClose} title={group ? t('editTitle') : t('addTitle')}>
      <form onSubmit={submit} className="space-y-4">
        <Input label={t('name')} value={name} onChange={(e) => setName(e.target.value)} required />
        <Input
          label={t('descriptionLabel')}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" onClick={onClose}>
            {t('common:actions.cancel')}
          </Button>
          <Button type="submit" loading={pending}>
            {t('common:actions.save')}
          </Button>
        </div>
      </form>
    </Modal>
  )
}

// MembersModal picks nodes one network at a time; the selection is kept
// across networks, so a group can span them.
const MembersModal = ({ group, onClose }: { group: NodeGroup; onClose: () => void }) => {
  const { t } = useTranslation('groups')
  const setMembers = useSetGroupMembers()
  const { data: networks = [] } = useNetworks()
  const [networkId, setNetworkId] = useState(group.members?.[0]?.network_id ?? '')
  const { data: nodes = [], isLoading } = useNodes(networkId)
  // node id -> label, for every selected node (also ones in other networks)
  const [selected, setSelected] = useState<Map<string, string>>(
    () => new Map((group.members ?? []).map((m) => [m.node_id, `${m.name} (${m.virtual_ip})`]))
  )

  const toggle = (id: string, label: string) => {
    const next = new Map(selected)
    if (next.has(id)) next.delete(id)
    else next.set(id, label)
    setSelected(next)
  }

  const save = async () => {
    await setMembers.mutateAsync({ id: group.id, nodeIds: [...selected.keys()] })
    onClose()
  }

  return (
    <Modal isOpen onClose={onClose} title={t('membersTitle', { name: group.name })} size="lg">
      <div className="space-y-4">
        <label className="block text-sm font-medium">
          {t('common:fields.network')}
          <select
            value={networkId}
            onChange={(e) => setNetworkId(e.target.value)}
            className="mt-1 w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
          >
            <option value="">{t('selectNetwork')}</option>
            {networks.map((n) => (
              <option key={n.id} value={n.id}>
                {n.name} ({n.cidr})
              </option>
            ))}
          </select>
        </label>
        {networkId && (
          <div className="max-h-64 overflow-y-auto rounded-lg border dark:border-gray-600">
            {isLoading ? (
              <p className="p-3 text-sm text-gray-500">{t('common:state.loading')}</p>
            ) : nodes.length === 0 ? (
              <p className="p-3 text-sm text-gray-500">{t('noNodes')}</p>
            ) : (
              nodes.map((n) => {
                const label = `${n.name} (${n.virtual_ip})`
                return (
                  <label key={n.id} className="flex items-center gap-2 px-3 py-2 text-sm">
                    <input
                      type="checkbox"
                      checked={selected.has(n.id)}
                      onChange={() => toggle(n.id, label)}
                    />
                    {label}
                  </label>
                )
              })
            )}
          </div>
        )}
        <div>
          <p className="text-sm font-medium">{t('selected', { count: selected.size })}</p>
          <div className="mt-1 flex flex-wrap gap-1">
            {[...selected.values()].map((label) => (
              <Badge key={label}>{label}</Badge>
            ))}
          </div>
        </div>
        <p className="text-xs text-gray-500">{t('membersHint')}</p>
        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" onClick={onClose}>
            {t('common:actions.cancel')}
          </Button>
          <Button onClick={save} loading={setMembers.isPending}>
            {t('common:actions.save')}
          </Button>
        </div>
      </div>
    </Modal>
  )
}
