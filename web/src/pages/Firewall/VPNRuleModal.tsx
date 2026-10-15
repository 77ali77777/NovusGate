import { Globe, Server } from 'lucide-react'
import React, { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, useGroups } from '@/api/client'
import { Button, Modal } from '@/components/ui'
import type {
  Network as NetworkType,
  Node,
  VPNEndpointType,
  VPNFirewallAction,
  VPNFirewallProtocol,
  VPNFirewallRuleRequest,
} from '@/types'

interface VPNRuleModalProps {
  isOpen: boolean
  onClose: () => void
  form: VPNFirewallRuleRequest
  setForm: React.Dispatch<React.SetStateAction<VPNFirewallRuleRequest>>
  onSubmit: (e: React.FormEvent) => void
  isEditing: boolean
  loading: boolean
  networks: NetworkType[]
}

export const VPNRuleModal = ({
  isOpen,
  onClose,
  form,
  setForm,
  onSubmit,
  isEditing,
  loading,
  networks,
}: VPNRuleModalProps) => {
  const { t } = useTranslation('firewall')
  const [sourceNodes, setSourceNodes] = useState<Node[]>([])
  const [destNodes, setDestNodes] = useState<Node[]>([])
  const groups = (useGroups().data?.groups ?? []).filter((g) => g !== null)

  // Fetch nodes when network changes
  React.useEffect(() => {
    if (form.source_type === 'node' && form.source_network_id) {
      api
        .getNodes(form.source_network_id)
        .then(setSourceNodes)
        .catch(() => setSourceNodes([]))
    } else {
      setSourceNodes([])
    }
  }, [form.source_network_id, form.source_type])

  React.useEffect(() => {
    if (form.dest_type === 'node' && form.dest_network_id) {
      api
        .getNodes(form.dest_network_id)
        .then(setDestNodes)
        .catch(() => setDestNodes([]))
    } else {
      setDestNodes([])
    }
  }, [form.dest_network_id, form.dest_type])

  const endpointTypes: { value: VPNEndpointType; label: string }[] = [
    { value: 'any', label: t('common:state.any') },
    { value: 'network', label: t('common:fields.network') },
    { value: 'node', label: t('common:fields.node') },
    { value: 'group', label: t('ruleModal.group') },
    { value: 'custom', label: t('ruleModal.customIp') },
  ]

  const protocols: { value: VPNFirewallProtocol; label: string }[] = [
    { value: 'all', label: t('ruleModal.protocolAll') },
    { value: 'tcp', label: 'TCP' },
    { value: 'udp', label: 'UDP' },
    { value: 'icmp', label: 'ICMP' },
  ]

  const actions: { value: VPNFirewallAction; label: string }[] = [
    { value: 'accept', label: t('ruleModal.actionAccept') },
    { value: 'drop', label: t('ruleModal.actionDrop') },
    { value: 'reject', label: t('ruleModal.actionReject') },
  ]

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={isEditing ? t('ruleModal.titleEdit') : t('ruleModal.titleAdd')}
      size="lg"
    >
      <form onSubmit={onSubmit} className="space-y-4">
        {/* Basic Info */}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label htmlFor="vpn-rule-1" className="block text-sm font-medium mb-1">
              {t('ruleModal.ruleName')}
            </label>
            <input
              id="vpn-rule-1"
              type="text"
              required
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
              placeholder={t('ruleModal.namePlaceholder')}
            />
          </div>
          <div>
            <label htmlFor="vpn-rule-2" className="block text-sm font-medium mb-1">
              {t('common:fields.priority')}
            </label>
            <input
              id="vpn-rule-2"
              type="number"
              required
              min="1"
              max="1000"
              value={form.priority}
              onChange={(e) => setForm({ ...form, priority: parseInt(e.target.value, 10) || 100 })}
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
            />
          </div>
        </div>

        <div>
          <label htmlFor="vpn-rule-3" className="block text-sm font-medium mb-1">
            {t('ruleModal.descriptionOptional')}
          </label>
          <input
            id="vpn-rule-3"
            type="text"
            value={form.description || ''}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
            className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
            placeholder={t('ruleModal.descriptionPlaceholder')}
          />
        </div>

        {/* Source */}
        <div className="p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg space-y-3">
          <h4 className="font-medium flex items-center gap-2">
            <Globe className="w-4 h-4" /> {t('common:fields.source')}
          </h4>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label htmlFor="vpn-rule-4" className="block text-sm font-medium mb-1">
                {t('common:fields.type')}
              </label>
              <select
                id="vpn-rule-4"
                value={form.source_type}
                onChange={(e) =>
                  setForm({
                    ...form,
                    source_type: e.target.value as VPNEndpointType,
                    source_network_id: undefined,
                    source_node_id: undefined,
                    source_group_id: undefined,
                    source_ip: undefined,
                  })
                }
                className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
              >
                {endpointTypes.map((t) => (
                  <option key={t.value} value={t.value}>
                    {t.label}
                  </option>
                ))}
              </select>
            </div>
            {form.source_type === 'network' && (
              <div>
                <label htmlFor="vpn-rule-5" className="block text-sm font-medium mb-1">
                  {t('common:fields.network')}
                </label>
                <select
                  id="vpn-rule-5"
                  value={form.source_network_id || ''}
                  onChange={(e) =>
                    setForm({ ...form, source_network_id: e.target.value || undefined })
                  }
                  className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                >
                  <option value="">{t('ruleModal.selectNetwork')}</option>
                  {networks.map((n) => (
                    <option key={n.id} value={n.id}>
                      {n.name} ({n.cidr})
                    </option>
                  ))}
                </select>
              </div>
            )}
            {form.source_type === 'node' && (
              <>
                <div>
                  <label htmlFor="vpn-rule-6" className="block text-sm font-medium mb-1">
                    {t('common:fields.network')}
                  </label>
                  <select
                    id="vpn-rule-6"
                    value={form.source_network_id || ''}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        source_network_id: e.target.value || undefined,
                        source_node_id: undefined,
                      })
                    }
                    className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                  >
                    <option value="">{t('ruleModal.selectNetwork')}</option>
                    {networks.map((n) => (
                      <option key={n.id} value={n.id}>
                        {n.name}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="col-span-2">
                  <label htmlFor="vpn-rule-7" className="block text-sm font-medium mb-1">
                    {t('common:fields.node')}
                  </label>
                  <select
                    id="vpn-rule-7"
                    value={form.source_node_id || ''}
                    onChange={(e) =>
                      setForm({ ...form, source_node_id: e.target.value || undefined })
                    }
                    className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                    disabled={!form.source_network_id}
                  >
                    <option value="">{t('ruleModal.selectNode')}</option>
                    {sourceNodes.map((n) => (
                      <option key={n.id} value={n.id}>
                        {n.name} ({n.virtual_ip})
                      </option>
                    ))}
                  </select>
                </div>
              </>
            )}
            {form.source_type === 'group' && (
              <div>
                <label htmlFor="source-group" className="block text-sm font-medium mb-1">
                  {t('ruleModal.group')}
                </label>
                <select
                  id="source-group"
                  value={form.source_group_id || ''}
                  onChange={(e) =>
                    setForm({ ...form, source_group_id: e.target.value || undefined })
                  }
                  className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                >
                  <option value="">{t('ruleModal.selectGroup')}</option>
                  {groups.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name} ({t('ruleModal.groupMembers', { count: g.members?.length ?? 0 })})
                    </option>
                  ))}
                </select>
              </div>
            )}
            {form.source_type === 'custom' && (
              <div>
                <label htmlFor="vpn-rule-8" className="block text-sm font-medium mb-1">
                  IP/CIDR
                </label>
                <input
                  id="vpn-rule-8"
                  type="text"
                  value={form.source_ip || ''}
                  onChange={(e) => setForm({ ...form, source_ip: e.target.value })}
                  className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                  placeholder={t('ruleModal.cidrPlaceholder')}
                />
              </div>
            )}
          </div>
        </div>

        {/* Destination */}
        <div className="p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg space-y-3">
          <h4 className="font-medium flex items-center gap-2">
            <Server className="w-4 h-4" /> {t('common:fields.destination')}
          </h4>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label htmlFor="vpn-rule-9" className="block text-sm font-medium mb-1">
                {t('common:fields.type')}
              </label>
              <select
                id="vpn-rule-9"
                value={form.dest_type}
                onChange={(e) =>
                  setForm({
                    ...form,
                    dest_type: e.target.value as VPNEndpointType,
                    dest_network_id: undefined,
                    dest_node_id: undefined,
                    dest_group_id: undefined,
                    dest_ip: undefined,
                  })
                }
                className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
              >
                {endpointTypes.map((t) => (
                  <option key={t.value} value={t.value}>
                    {t.label}
                  </option>
                ))}
              </select>
            </div>
            {form.dest_type === 'network' && (
              <div>
                <label htmlFor="vpn-rule-10" className="block text-sm font-medium mb-1">
                  {t('common:fields.network')}
                </label>
                <select
                  id="vpn-rule-10"
                  value={form.dest_network_id || ''}
                  onChange={(e) =>
                    setForm({ ...form, dest_network_id: e.target.value || undefined })
                  }
                  className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                >
                  <option value="">{t('ruleModal.selectNetwork')}</option>
                  {networks.map((n) => (
                    <option key={n.id} value={n.id}>
                      {n.name} ({n.cidr})
                    </option>
                  ))}
                </select>
              </div>
            )}
            {form.dest_type === 'node' && (
              <>
                <div>
                  <label htmlFor="vpn-rule-11" className="block text-sm font-medium mb-1">
                    {t('common:fields.network')}
                  </label>
                  <select
                    id="vpn-rule-11"
                    value={form.dest_network_id || ''}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        dest_network_id: e.target.value || undefined,
                        dest_node_id: undefined,
                      })
                    }
                    className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                  >
                    <option value="">{t('ruleModal.selectNetwork')}</option>
                    {networks.map((n) => (
                      <option key={n.id} value={n.id}>
                        {n.name}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="col-span-2">
                  <label htmlFor="vpn-rule-12" className="block text-sm font-medium mb-1">
                    {t('common:fields.node')}
                  </label>
                  <select
                    id="vpn-rule-12"
                    value={form.dest_node_id || ''}
                    onChange={(e) =>
                      setForm({ ...form, dest_node_id: e.target.value || undefined })
                    }
                    className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                    disabled={!form.dest_network_id}
                  >
                    <option value="">{t('ruleModal.selectNode')}</option>
                    {destNodes.map((n) => (
                      <option key={n.id} value={n.id}>
                        {n.name} ({n.virtual_ip})
                      </option>
                    ))}
                  </select>
                </div>
              </>
            )}
            {form.dest_type === 'group' && (
              <div>
                <label htmlFor="dest-group" className="block text-sm font-medium mb-1">
                  {t('ruleModal.group')}
                </label>
                <select
                  id="dest-group"
                  value={form.dest_group_id || ''}
                  onChange={(e) => setForm({ ...form, dest_group_id: e.target.value || undefined })}
                  className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                >
                  <option value="">{t('ruleModal.selectGroup')}</option>
                  {groups.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name} ({t('ruleModal.groupMembers', { count: g.members?.length ?? 0 })})
                    </option>
                  ))}
                </select>
              </div>
            )}
            {form.dest_type === 'custom' && (
              <div>
                <label htmlFor="vpn-rule-13" className="block text-sm font-medium mb-1">
                  IP/CIDR
                </label>
                <input
                  id="vpn-rule-13"
                  type="text"
                  value={form.dest_ip || ''}
                  onChange={(e) => setForm({ ...form, dest_ip: e.target.value })}
                  className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                  placeholder={t('ruleModal.cidrPlaceholder')}
                />
              </div>
            )}
          </div>
        </div>

        {/* Protocol, Port, Action */}
        <div className="grid grid-cols-3 gap-4">
          <div>
            <label htmlFor="vpn-rule-14" className="block text-sm font-medium mb-1">
              {t('common:fields.protocol')}
            </label>
            <select
              id="vpn-rule-14"
              value={form.protocol}
              onChange={(e) =>
                setForm({ ...form, protocol: e.target.value as VPNFirewallProtocol })
              }
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
            >
              {protocols.map((p) => (
                <option key={p.value} value={p.value}>
                  {p.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="vpn-rule-15" className="block text-sm font-medium mb-1">
              {t('ruleModal.portOptional')}
            </label>
            <input
              id="vpn-rule-15"
              type="text"
              value={form.port || ''}
              onChange={(e) => setForm({ ...form, port: e.target.value })}
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
              placeholder={t('ruleModal.portPlaceholder')}
              disabled={form.protocol === 'icmp' || form.protocol === 'all'}
            />
          </div>
          <div>
            <label htmlFor="vpn-rule-16" className="block text-sm font-medium mb-1">
              {t('common:fields.action')}
            </label>
            <select
              id="vpn-rule-16"
              value={form.action}
              onChange={(e) => setForm({ ...form, action: e.target.value as VPNFirewallAction })}
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
            >
              {actions.map((a) => (
                <option key={a.value} value={a.value}>
                  {a.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Enabled Toggle */}
        <div className="flex items-center gap-2">
          <input
            type="checkbox"
            id="enabled"
            checked={form.enabled}
            onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
            className="rounded"
          />
          <label htmlFor="enabled" className="text-sm">
            {t('ruleModal.enabled')}
          </label>
        </div>

        {/* Submit */}
        <div className="flex justify-end gap-2 pt-4 border-t dark:border-gray-700">
          <Button variant="secondary" type="button" onClick={onClose}>
            {t('common:actions.cancel')}
          </Button>
          <Button variant="primary" type="submit" loading={loading}>
            {isEditing ? t('actions.updateRule') : t('actions.createRule')}
          </Button>
        </div>
      </form>
    </Modal>
  )
}
