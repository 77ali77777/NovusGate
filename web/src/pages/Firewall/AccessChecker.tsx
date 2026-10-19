import {
  AlertTriangle,
  ArrowLeftRight,
  CheckCircle2,
  CircleSlash,
  Network,
  Search,
  Server,
  Users,
} from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useAccessCheck, useGroups, useNetworks, useNodes } from '@/api/client'
import { HelpTip } from '@/components/HelpTip'
import { Button, Card } from '@/components/ui'
import { accessHeadline } from '@/lib/accessCheck'
import { matrixReason } from '@/lib/matrixReason'
import { networkLabelById } from '@/lib/networkDisplay'
import type { AccessSide } from '@/types'

// A side as chosen in the form; a device also keeps its network.
export interface CheckSide {
  type: AccessSide['type']
  networkId?: string
  id?: string
}

// sideOf turns a form side into what the API checks (null until complete).
function sideOf(s: CheckSide): AccessSide | null {
  const id = s.type === 'network' ? s.networkId : s.id
  return id ? { type: s.type, id } : null
}

const fieldClass = 'w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600'
const verdictStyle: Record<string, string> = {
  allow: 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300',
  deny: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300',
  partial: 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300',
}

const SidePicker = ({
  label,
  idPrefix,
  side,
  onChange,
}: {
  label: string
  idPrefix: string
  side: CheckSide
  onChange: (s: CheckSide) => void
}) => {
  const { t } = useTranslation('firewall')
  const { data: networks } = useNetworks()
  const groups = (useGroups().data?.groups ?? []).filter((g) => g !== null)
  const { data: nodes } = useNodes(side.type === 'node' ? (side.networkId ?? '') : '')
  const kinds = [
    { value: 'network' as const, icon: Network },
    { value: 'node' as const, icon: Server },
    { value: 'group' as const, icon: Users },
  ]
  return (
    <div className="space-y-2">
      <p className="text-sm font-medium">
        {label}
        <HelpTip k="helpFirewall:accessCheck.side" />
      </p>
      <div className="flex flex-wrap gap-2">
        {kinds.map((k) => (
          <button
            key={k.value}
            type="button"
            aria-pressed={side.type === k.value}
            onClick={() => onChange({ type: k.value })}
            className={`px-3 py-1.5 rounded-lg border text-sm ${
              side.type === k.value
                ? 'border-blue-500 bg-blue-50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-200'
                : 'border-gray-200 dark:border-gray-600'
            }`}
          >
            <k.icon className="w-4 h-4 inline mr-1" />
            {t(`accessCheck.type.${k.value}`)}
          </button>
        ))}
      </div>
      {(side.type === 'network' || side.type === 'node') && (
        <div className="flex items-center gap-1">
          <label htmlFor={`${idPrefix}-network`} className="sr-only">
            {t('accessCheck.network')}
          </label>
          <select
            data-help="helpFirewall:accessCheck.item"
            id={`${idPrefix}-network`}
            value={side.networkId ?? ''}
            onChange={(e) => onChange({ type: side.type, networkId: e.target.value || undefined })}
            className={fieldClass}
          >
            <option value="">{t('accessCheck.pickNetwork')}</option>
            {(networks ?? []).map((n) => (
              <option key={n.id} value={n.id}>
                {networkLabelById(networks, n.id, n.name, t)} ({n.cidr})
              </option>
            ))}
          </select>
          <HelpTip k="helpFirewall:accessCheck.item" />
        </div>
      )}
      {side.type === 'node' && (
        <div className="flex items-center gap-1">
          <label htmlFor={`${idPrefix}-node`} className="sr-only">
            {t('accessCheck.device')}
          </label>
          <select
            data-help="helpFirewall:accessCheck.item"
            id={`${idPrefix}-node`}
            value={side.id ?? ''}
            disabled={!side.networkId}
            onChange={(e) => onChange({ ...side, id: e.target.value || undefined })}
            className={fieldClass}
          >
            <option value="">
              {side.networkId ? t('accessCheck.pickDevice') : t('accessCheck.networkFirst')}
            </option>
            {(nodes ?? []).map((n) => (
              <option key={n.id} value={n.id}>
                {n.name} ({n.virtual_ip})
              </option>
            ))}
          </select>
          <HelpTip k="helpFirewall:accessCheck.item" />
        </div>
      )}
      {side.type === 'group' && (
        <div className="flex items-center gap-1">
          <label htmlFor={`${idPrefix}-group`} className="sr-only">
            {t('accessCheck.group')}
          </label>
          <select
            data-help="helpFirewall:accessCheck.item"
            id={`${idPrefix}-group`}
            value={side.id ?? ''}
            onChange={(e) => onChange({ type: 'group', id: e.target.value || undefined })}
            className={fieldClass}
          >
            <option value="">{t('accessCheck.pickGroup')}</option>
            {groups.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </select>
          <HelpTip k="helpFirewall:accessCheck.item" />
        </div>
      )}
    </div>
  )
}

interface AccessCheckerProps {
  // Opens the rule form for this pair; absent for roles that cannot write rules.
  onCreateRule?: (from: CheckSide, to: CheckSide) => void
}

// AccessChecker answers "who can reach whom" for two networks, devices or
// groups (VLAN plan M3): one plain sentence, then each direction with the
// reason and the deciding rule.
export const AccessChecker = ({ onCreateRule }: AccessCheckerProps) => {
  const { t } = useTranslation('firewall')
  const { data: networks } = useNetworks()
  const [from, setFrom] = useState<CheckSide>({ type: 'network' })
  const [to, setTo] = useState<CheckSide>({ type: 'network' })
  const a = sideOf(from)
  const b = sideOf(to)
  const { data: res, isFetching, isError } = useAccessCheck(a, b)
  // Shown names: a network uses the panel's label (wg0 is "Admin VPN").
  const nameOf = (info: { type: string; id: string; name: string }) =>
    info.type === 'network' ? networkLabelById(networks, info.id, info.name, t) : info.name

  const directions = res
    ? [
        { from: nameOf(res.from), to: nameOf(res.to), v: res.forward },
        { from: nameOf(res.to), to: nameOf(res.from), v: res.reverse },
      ]
    : []
  const headline = res ? accessHeadline(res.forward.verdict, res.reverse.verdict) : null

  return (
    <Card className="mb-4">
      <div className="mb-3 flex items-start gap-2">
        <Search className="mt-0.5 h-5 w-5 shrink-0 text-blue-500" />
        <div className="min-w-0">
          <h3 className="text-lg font-semibold">{t('accessCheck.title')}</h3>
          <p className="text-sm text-gray-500">{t('accessCheck.help')}</p>
        </div>
      </div>
      <div className="grid gap-4 md:grid-cols-[1fr_auto_1fr] md:items-start">
        <SidePicker
          label={t('accessCheck.from')}
          idPrefix="check-from"
          side={from}
          onChange={setFrom}
        />
        <ArrowLeftRight
          className="mx-auto hidden h-5 w-5 text-gray-400 md:mt-9 md:block"
          aria-hidden="true"
        />
        <SidePicker label={t('accessCheck.to')} idPrefix="check-to" side={to} onChange={setTo} />
      </div>

      <div
        className="mt-4 rounded-lg border border-gray-200 p-4 text-sm dark:border-gray-700"
        aria-live="polite"
      >
        {!a || !b ? (
          <p className="text-gray-500">{t('accessCheck.choose')}</p>
        ) : isError ? (
          <p className="text-red-600">{t('accessCheck.error')}</p>
        ) : !res || isFetching ? (
          <p className="text-gray-500">{t('accessCheck.loading')}</p>
        ) : (
          <div className="space-y-3">
            <p className="flex items-start gap-2 font-medium">
              {headline === 'none' ? (
                <CircleSlash className="mt-0.5 h-4 w-4 shrink-0 text-red-600" aria-hidden="true" />
              ) : headline === 'partial' ? (
                <AlertTriangle
                  className="mt-0.5 h-4 w-4 shrink-0 text-amber-600"
                  aria-hidden="true"
                />
              ) : (
                <CheckCircle2
                  className="mt-0.5 h-4 w-4 shrink-0 text-green-600"
                  aria-hidden="true"
                />
              )}
              {t(`accessCheck.headline.${headline}`, { a: nameOf(res.from), b: nameOf(res.to) })}
            </p>
            <ul className="space-y-2">
              {directions.map((d) => (
                <li key={`${d.from}-${d.to}`} className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">
                    {t('accessCheck.direction', { from: d.from, to: d.to })}
                  </span>
                  <span
                    className={`rounded px-2 py-0.5 text-xs font-medium ${verdictStyle[d.v.verdict] ?? ''}`}
                  >
                    {t(`matrix.${d.v.verdict}`, { defaultValue: d.v.verdict })}
                  </span>
                  <span className="text-gray-600 dark:text-gray-300">{matrixReason(t, d.v)}</span>
                </li>
              ))}
            </ul>
            {(res.forward.rules ?? []).length + (res.reverse.rules ?? []).length > 0 && (
              <p className="text-xs text-gray-500">
                {t('accessCheck.rules', {
                  rules: [
                    ...new Set([...(res.forward.rules ?? []), ...(res.reverse.rules ?? [])]),
                  ].join(', '),
                })}
              </p>
            )}
            {onCreateRule && headline !== 'both' && (
              <Button variant="secondary" size="sm" onClick={() => onCreateRule(from, to)}>
                {t('accessCheck.makeRule')}
              </Button>
            )}
          </div>
        )}
      </div>
    </Card>
  )
}
