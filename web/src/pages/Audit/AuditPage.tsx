import { useQueries, useQuery } from '@tanstack/react-query'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { Fragment, useCallback, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, useAuditLog, useCan, useGroups, useLimits, useNetworks } from '@/api/client'
import { PageHeader } from '@/components/Layout'
import { Badge, Button, Card, Input, Select } from '@/components/ui'
import { formatDateTime } from '@/i18n'
import {
  AUDIT_KINDS,
  type AuditNames,
  type AuditResult,
  auditSentence,
  describeAudit,
  matchesAuditQuery,
} from '@/lib/auditText'

const resultVariant: Record<AuditResult, 'success' | 'warning' | 'danger' | 'default'> = {
  ok: 'success',
  denied: 'warning',
  error: 'danger',
  none: 'default',
}

const NO_NETWORKS: { id: string; name: string }[] = []

const byId = (items: ({ id: string; name: string } | null)[] | null | undefined) => {
  const out: Record<string, string> = {}
  for (const i of items ?? []) if (i) out[i.id] = i.name
  return out
}

// AuditPage: who changed what through the panel or the API, and every login
// attempt, as sentences (lib/auditText.ts). Entries are kept in the database
// (firewall_audit_log); the raw record stays one click away.
// flatNodes joins the per-network device lists; module-level, so useQueries
// keeps its result between renders and the name lookup below is memoized.
const flatNodes = (results: { data?: { id: string; name: string }[] }[]) =>
  results.flatMap((r) => r.data ?? [])

export const AuditPage = () => {
  const { t } = useTranslation('audit')
  const { data, isLoading, isError, fetchNextPage, hasNextPage, isFetchingNextPage } = useAuditLog()
  const isAdmin = useCan('admin')
  const networks = useNetworks().data ?? NO_NETWORKS
  const { data: groups } = useGroups()
  const { data: limits } = useLimits()
  // GET /users is admin-only; other roles see short ids for users.
  const { data: users } = useQuery({
    queryKey: ['users'],
    queryFn: () => api.getUsers(),
    enabled: isAdmin,
  })
  const allNodes = useQueries({
    queries: networks.map((n) => ({
      queryKey: ['nodes', n.id],
      queryFn: () => api.getNodes(n.id),
    })),
    combine: flatNodes,
  })

  const names = useMemo<AuditNames>(
    () => ({
      network: byId(networks),
      group: byId(groups?.groups),
      limit: byId(limits?.profiles),
      user: byId(users?.map((u) => ({ id: u.id, name: u.username }))),
      node: byId(allNodes),
    }),
    [networks, groups, limits, users, allNodes]
  )

  const [user, setUser] = useState('')
  const [kind, setKind] = useState('')
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState<Set<string>>(new Set())
  const toggle = (id: string) =>
    setOpen((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })

  const tx = useCallback((key: string, params?: Record<string, string>) => t(key, params), [t])
  const rows = useMemo(
    () =>
      (data?.pages.flatMap((p) => p.entries ?? []) ?? []).flatMap((e) => {
        if (!e) return []
        const entry = { ...e, details: e.details ?? {} }
        return [{ entry, desc: describeAudit(entry, names), text: auditSentence(entry, names, tx) }]
      }),
    [data, names, tx]
  )
  const actors = useMemo(
    () => [...new Set(rows.map((r) => r.desc.actor).filter(Boolean))].sort(),
    [rows]
  )
  const shown = rows.filter(
    (r) =>
      (!user || r.desc.actor === user) &&
      (!kind || r.desc.kind === kind) &&
      matchesAuditQuery(
        [r.text, r.desc.actor, r.entry.user_ip ?? '', r.entry.action, r.desc.path],
        query
      )
  )

  return (
    <div className="space-y-6">
      <PageHeader title={t('title')} description={t('description')} />
      <Card>
        <div className="grid gap-4 sm:grid-cols-3">
          <Select
            label={t('filters.user')}
            help="helpAudit:filters.user"
            value={user}
            onChange={(e) => setUser(e.target.value)}
            options={[
              { value: '', label: t('filters.allUsers') },
              ...actors.map((a) => ({ value: a, label: a })),
            ]}
          />
          <Select
            label={t('filters.kind')}
            help="helpAudit:filters.kind"
            value={kind}
            onChange={(e) => setKind(e.target.value)}
            options={[
              { value: '', label: t('filters.allKinds') },
              ...AUDIT_KINDS.map((k) => ({ value: k, label: t(`kinds.${k}`) })),
            ]}
          />
          <Input
            label={t('filters.search')}
            help="helpAudit:filters.search"
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t('filters.searchPlaceholder')}
          />
        </div>
        {rows.length > 0 && (
          <p className="mt-3 text-xs text-gray-500">
            {t('filters.shown', { shown: shown.length, total: rows.length })}
          </p>
        )}
      </Card>
      <Card padding="none">
        {isLoading ? (
          <p className="p-6 text-sm text-gray-500">{t('common:state.loading')}</p>
        ) : isError ? (
          <p className="p-6 text-sm text-red-600">{t('loadError')}</p>
        ) : rows.length === 0 ? (
          <p className="p-6 text-sm text-gray-500">{t('empty')}</p>
        ) : shown.length === 0 ? (
          <p className="p-6 text-sm text-gray-500">{t('filters.noMatch')}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500 dark:bg-gray-800">
                <tr>
                  <th className="w-8 px-2 py-3" />
                  <th className="px-4 py-3">{t('common:fields.time')}</th>
                  <th className="px-4 py-3">{t('columns.event')}</th>
                  <th className="px-4 py-3">{t('columns.result')}</th>
                  <th className="px-4 py-3">{t('columns.address')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                {shown.map(({ entry: e, desc, text }) => {
                  const expanded = open.has(e.id)
                  const code =
                    desc.status !== undefined ? t('result.code', { code: desc.status }) : undefined
                  return (
                    <Fragment key={e.id}>
                      <tr
                        className="cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800/50"
                        onClick={() => toggle(e.id)}
                      >
                        <td className="px-2 py-2">
                          <button
                            type="button"
                            className="rounded p-1 text-gray-400 hover:text-gray-700 dark:hover:text-gray-200"
                            aria-expanded={expanded}
                            aria-label={expanded ? t('raw.hide') : t('raw.show')}
                            title={expanded ? t('raw.hide') : t('raw.show')}
                            onClick={(ev) => {
                              ev.stopPropagation()
                              toggle(e.id)
                            }}
                          >
                            {expanded ? (
                              <ChevronDown className="h-4 w-4" />
                            ) : (
                              <ChevronRight className="h-4 w-4" />
                            )}
                          </button>
                        </td>
                        <td className="whitespace-nowrap px-4 py-2 text-gray-500">
                          {formatDateTime(e.created_at)}
                        </td>
                        <td className="px-4 py-2">
                          <span className="block">{text}</span>
                          <span className="text-xs text-gray-400">{t(`kinds.${desc.kind}`)}</span>
                        </td>
                        <td className="whitespace-nowrap px-4 py-2">
                          {desc.result === 'none' ? (
                            '—'
                          ) : (
                            <span title={code}>
                              <Badge variant={resultVariant[desc.result]}>
                                {t(`result.${desc.result}`)}
                              </Badge>
                              {desc.result !== 'ok' && code && (
                                <span className="block text-xs text-gray-400">{code}</span>
                              )}
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-2 font-mono text-xs">{e.user_ip || '—'}</td>
                      </tr>
                      {expanded && (
                        <tr className="bg-gray-50 dark:bg-gray-800/40">
                          <td />
                          <td colSpan={4} className="px-4 py-3">
                            <dl className="grid gap-x-6 gap-y-1 text-xs sm:grid-cols-[max-content_1fr]">
                              <dt className="text-gray-500">{t('raw.action')}</dt>
                              <dd className="font-mono">{e.action}</dd>
                              <dt className="text-gray-500">{t('raw.method')}</dt>
                              <dd className="font-mono">{desc.method || '—'}</dd>
                              <dt className="text-gray-500">{t('raw.path')}</dt>
                              <dd className="break-all font-mono">{desc.path || '—'}</dd>
                              <dt className="text-gray-500">{t('raw.status')}</dt>
                              <dd className="font-mono">{desc.status ?? '—'}</dd>
                              <dt className="text-gray-500">{t('raw.ip')}</dt>
                              <dd className="font-mono">{e.user_ip || '—'}</dd>
                              <dt className="text-gray-500">{t('raw.details')}</dt>
                              <dd>
                                <pre className="overflow-x-auto whitespace-pre-wrap break-all font-mono">
                                  {JSON.stringify(e.details, null, 2)}
                                </pre>
                              </dd>
                            </dl>
                          </td>
                        </tr>
                      )}
                    </Fragment>
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
