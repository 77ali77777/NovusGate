import {
  ArrowLeftRight,
  ArrowRight,
  Ban,
  CheckCircle2,
  Globe,
  Network,
  Server,
  Users,
} from 'lucide-react'
import React, { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, useGroups } from '@/api/client'
import { HelpTip } from '@/components/HelpTip'
import { Button, Modal } from '@/components/ui'
import {
  autoRuleName,
  missingStep,
  presetOf,
  ruleSummary,
  SERVICE_PRESETS,
  withPreset,
  withProtocol,
} from '@/lib/vpnRule'
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
  onSubmit: (e: React.FormEvent, request: VPNFirewallRuleRequest) => void
  isEditing: boolean
  loading: boolean
  networks: NetworkType[]
}

type Side = 'source' | 'dest'

const fieldClass = 'w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600'

// choiceClass styles one button of a button group (the chosen one stands out).
const choiceClass = (on: boolean) =>
  `px-3 py-2 rounded-lg border text-sm text-left transition-colors ${
    on
      ? 'border-blue-500 bg-blue-50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-200'
      : 'border-gray-200 hover:border-gray-300 dark:border-gray-600 dark:hover:border-gray-500'
  }`

// StepCard is one numbered question of the form.
const StepCard = ({
  n,
  title,
  hint,
  help,
  children,
}: {
  n: number
  title: string
  hint: string
  help: string
  children: React.ReactNode
}) => (
  <section className="p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg space-y-3">
    <div className="flex items-start gap-3">
      <span className="flex-shrink-0 w-6 h-6 rounded-full bg-blue-600 text-white flex items-center justify-center text-xs font-bold">
        {n}
      </span>
      <div>
        <h4 className="font-medium">
          {title}
          <HelpTip k={help} />
        </h4>
        <p className="text-xs text-gray-500 dark:text-gray-400">{hint}</p>
      </div>
    </div>
    {children}
  </section>
)

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

  const endpointTypes: { value: VPNEndpointType; label: string; icon: typeof Globe }[] = [
    { value: 'network', label: t('ruleForm.type.network'), icon: Network },
    { value: 'node', label: t('ruleForm.type.node'), icon: Server },
    { value: 'group', label: t('ruleForm.type.group'), icon: Users },
    { value: 'custom', label: t('ruleForm.type.custom'), icon: Globe },
    { value: 'any', label: t('ruleForm.type.any'), icon: Globe },
  ]

  const protocols: { value: VPNFirewallProtocol; label: string }[] = [
    { value: 'tcp', label: 'TCP' },
    { value: 'udp', label: 'UDP' },
    { value: 'icmp', label: t('ruleForm.what.ping') },
  ]

  const decisions: { value: VPNFirewallAction; label: string; hint: string }[] = [
    {
      value: 'accept',
      label: t('ruleForm.decision.accept'),
      hint: t('ruleForm.decision.acceptHint'),
    },
    { value: 'drop', label: t('ruleForm.decision.drop'), hint: t('ruleForm.decision.dropHint') },
    {
      value: 'reject',
      label: t('ruleForm.decision.reject'),
      hint: t('ruleForm.decision.rejectHint'),
    },
  ]

  // sideName is how a side reads: label in the sentences («Office» network),
  // plain in the automatic rule name (Office).
  const sideName = (side: Side): { label: string; plain: string } => {
    const type = side === 'source' ? form.source_type : form.dest_type
    const pick = t('ruleForm.side.pick')
    const named = (key: string, name?: string) =>
      name
        ? { label: t(`ruleForm.side.${key}`, { name }), plain: name }
        : { label: pick, plain: pick }
    switch (type) {
      case 'network': {
        const id = side === 'source' ? form.source_network_id : form.dest_network_id
        return named('network', networks.find((x) => x.id === id)?.name)
      }
      case 'node': {
        const id = side === 'source' ? form.source_node_id : form.dest_node_id
        return named(
          'node',
          (side === 'source' ? sourceNodes : destNodes).find((x) => x.id === id)?.name
        )
      }
      case 'group': {
        const id = side === 'source' ? form.source_group_id : form.dest_group_id
        return named('group', groups.find((x) => x.id === id)?.name)
      }
      case 'custom':
        return named('custom', (side === 'source' ? form.source_ip : form.dest_ip)?.trim())
      default: {
        // "anyone" starts a connection, it goes "anywhere"
        const any = t(side === 'source' ? 'ruleForm.side.anySource' : 'ruleForm.side.anyDest')
        return { label: any, plain: any }
      }
    }
  }

  const source = sideName('source')
  const dest = sideName('dest')
  const from = source.label
  const to = dest.label
  const autoName = autoRuleName(source.plain, dest.plain, !!form.bidirectional)
  const summary = ruleSummary(form)
  const what = t(`ruleForm.what.${summary.what.key}`, summary.what.params)
  const missing = missingStep(form)
  const serviceMode = form.protocol === 'all' ? 'all' : 'some'
  const preset = presetOf(form)

  const submit = (e: React.FormEvent) => {
    const name = (form.name ?? '').trim() || autoName
    onSubmit(e, { ...form, name })
  }

  // sidePicker is the "who" / "to whom" question: a kind, then the one thing.
  const sidePicker = (side: Side) => {
    const s = side === 'source'
    const type = s ? form.source_type : form.dest_type
    const networkId = s ? form.source_network_id : form.dest_network_id
    const nodeId = s ? form.source_node_id : form.dest_node_id
    const groupId = s ? form.source_group_id : form.dest_group_id
    const ip = s ? form.source_ip : form.dest_ip
    const nodes = s ? sourceNodes : destNodes
    const set = (
      patch: Partial<
        Record<'type' | 'network_id' | 'node_id' | 'group_id' | 'ip', string | undefined>
      >
    ) =>
      setForm((f) => {
        const out: Record<string, unknown> = { ...f }
        for (const [k, v] of Object.entries(patch)) out[`${side}_${k}`] = v
        return out as unknown as VPNFirewallRuleRequest
      })
    return (
      <div className="space-y-3">
        <div className="flex flex-wrap gap-2">
          {endpointTypes.map((et) => (
            <button
              key={et.value}
              type="button"
              aria-pressed={type === et.value}
              className={choiceClass(type === et.value)}
              onClick={() =>
                set({
                  type: et.value,
                  network_id: undefined,
                  node_id: undefined,
                  group_id: undefined,
                  ip: undefined,
                })
              }
            >
              <et.icon className="w-4 h-4 inline mr-1" />
              {et.label}
            </button>
          ))}
        </div>
        {(type === 'network' || type === 'node') && (
          <div>
            <label htmlFor={`${side}-network`} className="block text-sm font-medium mb-1">
              {t(type === 'node' ? 'ruleForm.deviceNetwork' : 'ruleForm.whichNetwork')}
              {type === 'node' ? (
                <HelpTip k="helpFirewall:vpnRule.nodeNetwork" />
              ) : (
                <HelpTip k="helpFirewall:vpnRule.network" />
              )}
            </label>
            <select
              data-help="helpFirewall:vpnRule.network"
              id={`${side}-network`}
              value={networkId || ''}
              onChange={(e) => set({ network_id: e.target.value || undefined, node_id: undefined })}
              className={fieldClass}
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
        {type === 'node' && (
          <div>
            <label htmlFor={`${side}-node`} className="block text-sm font-medium mb-1">
              {t('ruleForm.whichDevice')}
              <HelpTip k="helpFirewall:vpnRule.node" />
            </label>
            <select
              data-help="helpFirewall:vpnRule.node"
              id={`${side}-node`}
              value={nodeId || ''}
              onChange={(e) => set({ node_id: e.target.value || undefined })}
              className={fieldClass}
              disabled={!networkId}
            >
              <option value="">
                {networkId ? t('ruleModal.selectNode') : t('ruleForm.networkFirst')}
              </option>
              {nodes.map((n) => (
                <option key={n.id} value={n.id}>
                  {n.name} ({n.virtual_ip})
                </option>
              ))}
            </select>
          </div>
        )}
        {type === 'group' && (
          <div>
            <label htmlFor={`${side}-group`} className="block text-sm font-medium mb-1">
              {t('ruleForm.whichGroup')}
              <HelpTip k="helpFirewall:vpnRule.group" />
            </label>
            <select
              data-help="helpFirewall:vpnRule.group"
              id={`${side}-group`}
              value={groupId || ''}
              onChange={(e) => set({ group_id: e.target.value || undefined })}
              className={fieldClass}
            >
              <option value="">{t('ruleModal.selectGroup')}</option>
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name} ({t('ruleModal.groupMembers', { count: g.members?.length ?? 0 })})
                </option>
              ))}
            </select>
            {groups.length === 0 && (
              <p className="text-xs text-amber-600 mt-1">{t('ruleForm.noGroups')}</p>
            )}
          </div>
        )}
        {type === 'custom' && (
          <div>
            <label htmlFor={`${side}-ip`} className="block text-sm font-medium mb-1">
              {t('ruleForm.whichAddress')}
              <HelpTip k="helpFirewall:vpnRule.customIp" />
            </label>
            <input
              data-help="helpFirewall:vpnRule.customIp"
              id={`${side}-ip`}
              type="text"
              value={ip || ''}
              onChange={(e) => set({ ip: e.target.value })}
              className={fieldClass}
              placeholder={t('ruleModal.cidrPlaceholder')}
            />
          </div>
        )}
      </div>
    )
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={isEditing ? t('ruleModal.titleEdit') : t('ruleModal.titleAdd')}
      size="lg"
    >
      <form onSubmit={submit} className="space-y-4">
        <p className="text-sm text-gray-600 dark:text-gray-300">{t('ruleForm.intro')}</p>

        <StepCard
          n={1}
          title={t('ruleForm.who')}
          hint={t('ruleForm.whoHint')}
          help="helpFirewall:vpnRule.who"
        >
          {sidePicker('source')}
        </StepCard>

        <StepCard
          n={2}
          title={t('ruleForm.toWhom')}
          hint={t('ruleForm.toWhomHint')}
          help="helpFirewall:vpnRule.toWhom"
        >
          {sidePicker('dest')}
        </StepCard>

        <StepCard
          n={3}
          title={t('ruleForm.whatTitle')}
          hint={t('ruleForm.whatHint')}
          help="helpFirewall:vpnRule.what"
        >
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              aria-pressed={serviceMode === 'all'}
              className={choiceClass(serviceMode === 'all')}
              onClick={() => setForm((f) => withProtocol(f, 'all'))}
            >
              {t('ruleForm.everything')}
            </button>
            <button
              type="button"
              aria-pressed={serviceMode === 'some'}
              className={choiceClass(serviceMode === 'some')}
              onClick={() => serviceMode === 'all' && setForm((f) => withPreset(f, 'web'))}
            >
              {t('ruleForm.someServices')}
            </button>
          </div>
          {serviceMode === 'some' && (
            <div className="space-y-3">
              <div className="flex flex-wrap gap-2">
                {SERVICE_PRESETS.map((p) => (
                  <button
                    key={p.id}
                    type="button"
                    aria-pressed={preset === p.id}
                    className={choiceClass(preset === p.id)}
                    onClick={() => setForm((f) => withPreset(f, p.id))}
                  >
                    {t(`ruleForm.preset.${p.id}`)}
                  </button>
                ))}
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label htmlFor="vpn-rule-protocol" className="block text-sm font-medium mb-1">
                    {t('common:fields.protocol')}
                    <HelpTip k="helpFirewall:vpnRule.protocol" />
                  </label>
                  <select
                    data-help="helpFirewall:vpnRule.protocol"
                    id="vpn-rule-protocol"
                    value={form.protocol}
                    onChange={(e) =>
                      setForm((f) => withProtocol(f, e.target.value as VPNFirewallProtocol))
                    }
                    className={fieldClass}
                  >
                    {protocols.map((p) => (
                      <option key={p.value} value={p.value}>
                        {p.label}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label htmlFor="vpn-rule-port" className="block text-sm font-medium mb-1">
                    {t('ruleModal.portOptional')}
                    <HelpTip k="helpFirewall:vpnRule.port" />
                  </label>
                  <input
                    data-help="helpFirewall:vpnRule.port"
                    id="vpn-rule-port"
                    type="text"
                    value={form.port || ''}
                    onChange={(e) => setForm((f) => ({ ...f, port: e.target.value }))}
                    className={fieldClass}
                    placeholder={t('ruleModal.portPlaceholder')}
                    disabled={form.protocol === 'icmp'}
                  />
                </div>
              </div>
            </div>
          )}
        </StepCard>

        <StepCard
          n={4}
          title={t('ruleForm.directionTitle')}
          hint={t('ruleForm.directionHint')}
          help="helpFirewall:vpnRule.direction"
        >
          <div className="grid sm:grid-cols-2 gap-2">
            <button
              type="button"
              aria-pressed={!form.bidirectional}
              className={choiceClass(!form.bidirectional)}
              onClick={() => setForm((f) => ({ ...f, bidirectional: false }))}
            >
              <span className="font-medium flex items-center gap-1">
                <ArrowRight className="w-4 h-4" /> {t('ruleForm.oneWay')}
              </span>
              <span className="block text-xs mt-1 opacity-80">
                {t('ruleForm.oneWayHint', { from, to })}
              </span>
            </button>
            <button
              type="button"
              aria-pressed={!!form.bidirectional}
              className={choiceClass(!!form.bidirectional)}
              onClick={() => setForm((f) => ({ ...f, bidirectional: true }))}
            >
              <span className="font-medium flex items-center gap-1">
                <ArrowLeftRight className="w-4 h-4" /> {t('ruleForm.mutual')}
              </span>
              <span className="block text-xs mt-1 opacity-80">
                {t('ruleForm.mutualHint', { from, to })}
              </span>
            </button>
          </div>
        </StepCard>

        <StepCard
          n={5}
          title={t('ruleForm.decisionTitle')}
          hint={t('ruleForm.decisionHint')}
          help="helpFirewall:vpnRule.action"
        >
          <div className="grid sm:grid-cols-3 gap-2">
            {decisions.map((d) => (
              <button
                key={d.value}
                type="button"
                aria-pressed={form.action === d.value}
                className={choiceClass(form.action === d.value)}
                onClick={() => setForm((f) => ({ ...f, action: d.value }))}
              >
                <span className="font-medium">{d.label}</span>
                <span className="block text-xs mt-1 opacity-80">{d.hint}</span>
              </button>
            ))}
          </div>
        </StepCard>

        {/* The result in one plain sentence */}
        <div
          className={`p-4 rounded-lg border flex gap-3 ${
            form.action === 'accept'
              ? 'bg-green-50 border-green-200 dark:bg-green-900/20 dark:border-green-800'
              : 'bg-red-50 border-red-200 dark:bg-red-900/20 dark:border-red-800'
          }`}
        >
          {form.action === 'accept' ? (
            <CheckCircle2 className="w-5 h-5 text-green-600 flex-shrink-0" />
          ) : (
            <Ban className="w-5 h-5 text-red-600 flex-shrink-0" />
          )}
          <div className="text-sm">
            <p className="font-medium">{t('ruleForm.resultTitle')}</p>
            {/* Until both sides are chosen, say what is missing instead */}
            {missing ? (
              <p className="text-amber-700 dark:text-amber-300">
                {t(`ruleForm.missing.${missing}`)}
              </p>
            ) : (
              <p>{t(`ruleForm.summary.${summary.key}`, { from, to, what })}</p>
            )}
          </div>
        </div>

        {/* Name, order and notes: optional, for people who need them */}
        <details className="rounded-lg border border-gray-200 dark:border-gray-700 p-3">
          <summary className="cursor-pointer text-sm font-medium">{t('ruleForm.more')}</summary>
          <div className="space-y-4 mt-3">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label htmlFor="vpn-rule-name" className="block text-sm font-medium mb-1">
                  {t('ruleForm.nameOptional')}
                  <HelpTip k="helpFirewall:vpnRule.name" />
                </label>
                <input
                  data-help="helpFirewall:vpnRule.name"
                  id="vpn-rule-name"
                  type="text"
                  maxLength={255}
                  value={form.name ?? ''}
                  onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                  className={fieldClass}
                  placeholder={autoName}
                />
              </div>
              <div>
                <label htmlFor="vpn-rule-priority" className="block text-sm font-medium mb-1">
                  {t('common:fields.priority')}
                  <HelpTip k="helpFirewall:vpnRule.priority" />
                </label>
                <input
                  data-help="helpFirewall:vpnRule.priority"
                  id="vpn-rule-priority"
                  type="number"
                  required
                  min="1"
                  max="1000"
                  value={form.priority}
                  onChange={(e) =>
                    setForm((f) => ({ ...f, priority: parseInt(e.target.value, 10) || 100 }))
                  }
                  className={fieldClass}
                />
              </div>
            </div>
            <div>
              <label htmlFor="vpn-rule-description" className="block text-sm font-medium mb-1">
                {t('ruleModal.descriptionOptional')}
                <HelpTip k="helpFirewall:vpnRule.description" />
              </label>
              <input
                data-help="helpFirewall:vpnRule.description"
                id="vpn-rule-description"
                type="text"
                value={form.description || ''}
                onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
                className={fieldClass}
                placeholder={t('ruleModal.descriptionPlaceholder')}
              />
            </div>
            <div className="flex items-center gap-2">
              <input
                data-help="helpFirewall:vpnRule.enabled"
                type="checkbox"
                id="enabled"
                checked={form.enabled}
                onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))}
                className="rounded"
              />
              <label htmlFor="enabled" className="text-sm">
                {t('ruleModal.enabled')}
                <HelpTip k="helpFirewall:vpnRule.enabled" />
              </label>
            </div>
          </div>
        </details>

        {/* Submit */}
        <div className="flex justify-end gap-2 pt-4 border-t dark:border-gray-700">
          <Button variant="secondary" type="button" onClick={onClose}>
            {t('common:actions.cancel')}
          </Button>
          <Button variant="primary" type="submit" loading={loading} disabled={missing !== null}>
            {isEditing ? t('actions.updateRule') : t('actions.createRule')}
          </Button>
        </div>
      </form>
    </Modal>
  )
}
