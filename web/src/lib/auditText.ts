// Human-readable audit entries: the route the backend recorded (method and
// route template, see server/.../rest/audit_handlers.go) becomes a sentence
// key of the audit namespace, the concrete path supplies the ids, and ids
// the panel knows become names. Imports only import-free modules, so it runs
// under `node --experimental-strip-types` in web/tests.
import { parseAction } from './audit.ts'

export const AUDIT_KINDS = [
  'login',
  'network',
  'node',
  'firewall',
  'user',
  'server',
  'other',
] as const
export type AuditKind = (typeof AUDIT_KINDS)[number]

export type AuditResult = 'ok' | 'denied' | 'error' | 'none'

// What an id in a route names; 'raw' values (backup file, systemd unit) are
// shown as they are, 'id' values (sessions) only as a short id.
type TargetType = 'network' | 'group' | 'limit' | 'user' | 'node' | 'raw' | 'id'

interface AuditRoute {
  key: string // under "sentence." in audit.json
  kind: AuditKind
  target?: { param: string; type: TargetType }
}

const net = (param: string) => ({ param, type: 'network' as const })
const id = (type: TargetType) => ({ param: 'id', type })

// AUDIT_ROUTES: every change the audit middleware records, keyed by
// "METHOD /route-template" without the /api/v1 prefix (registerXRoutes in
// server/internal/controlplane/api/rest), plus the legacy VPN rule actions
// firewall_handlers.go writes itself. Node check-ins are not recorded.
export const AUDIT_ROUTES: Record<string, AuditRoute> = {
  'POST /auth/logout': { key: 'auth.logout', kind: 'login' },
  'POST /auth/step-up': { key: 'auth.stepUp', kind: 'login' },
  'PUT /auth/password': { key: 'auth.password', kind: 'user' },
  'DELETE /auth/sessions/{id}': { key: 'auth.sessionEnd', kind: 'user', target: id('id') },

  'POST /networks': { key: 'network.create', kind: 'network' },
  'DELETE /networks/{id}': { key: 'network.delete', kind: 'network', target: id('network') },
  'PUT /networks/{id}/dns': { key: 'network.dns', kind: 'network', target: id('network') },
  'POST /networks/{networkId}/sync': {
    key: 'network.sync',
    kind: 'network',
    target: net('networkId'),
  },
  'POST /networks/{networkId}/servers': {
    key: 'node.create',
    kind: 'node',
    target: net('networkId'),
  },

  'PUT /nodes/{id}': { key: 'node.update', kind: 'node', target: id('node') },
  'PATCH /nodes/{id}': { key: 'node.update', kind: 'node', target: id('node') },
  'DELETE /nodes/{id}': { key: 'node.delete', kind: 'node', target: id('node') },
  'POST /nodes/{id}/quota/reset': { key: 'node.quotaReset', kind: 'node', target: id('node') },

  'POST /groups': { key: 'group.create', kind: 'node' },
  'PUT /groups/{id}': { key: 'group.update', kind: 'node', target: id('group') },
  'DELETE /groups/{id}': { key: 'group.delete', kind: 'node', target: id('group') },
  'PUT /groups/{id}/members': { key: 'group.members', kind: 'node', target: id('group') },

  'POST /limits': { key: 'limit.create', kind: 'other' },
  'PUT /limits/{id}': { key: 'limit.update', kind: 'other', target: id('limit') },
  'DELETE /limits/{id}': { key: 'limit.delete', kind: 'other', target: id('limit') },
  'PUT /limits/{id}/bindings': { key: 'limit.bindings', kind: 'other', target: id('limit') },

  'POST /firewall/host/import': { key: 'firewall.import', kind: 'firewall' },
  'POST /firewall/host/ip/allow': { key: 'firewall.ipAllow', kind: 'firewall' },
  'POST /firewall/host/ip/block': { key: 'firewall.ipBlock', kind: 'firewall' },
  'POST /firewall/host/port/open': { key: 'firewall.portOpen', kind: 'firewall' },
  'POST /firewall/host/port/close': { key: 'firewall.portClose', kind: 'firewall' },
  'POST /firewall/host/reset': { key: 'firewall.reset', kind: 'firewall' },
  'POST /firewall/host/rules/delete': { key: 'firewall.ruleDelete', kind: 'firewall' },
  'POST /firewall/v2/confirm/{id}': { key: 'firewall.confirm', kind: 'firewall' },
  'PUT /firewall/v2/egress/{nodeId}': {
    key: 'firewall.egressOn',
    kind: 'firewall',
    target: { param: 'nodeId', type: 'node' },
  },
  'DELETE /firewall/v2/egress/{nodeId}': {
    key: 'firewall.egressOff',
    kind: 'firewall',
    target: { param: 'nodeId', type: 'node' },
  },
  'POST /firewall/v2/forwards': { key: 'firewall.forwardCreate', kind: 'firewall' },
  'DELETE /firewall/v2/forwards/{id}': { key: 'firewall.forwardDelete', kind: 'firewall' },
  'POST /firewall/v2/history/{id}/restore': { key: 'firewall.restore', kind: 'firewall' },
  'POST /firewall/v2/ip-rules': { key: 'firewall.ipRuleCreate', kind: 'firewall' },
  'DELETE /firewall/v2/ip-rules/{id}': { key: 'firewall.ipRuleDelete', kind: 'firewall' },
  'POST /firewall/v2/services': { key: 'firewall.portOpen', kind: 'firewall' },
  'DELETE /firewall/v2/services/{id}': { key: 'firewall.serviceDelete', kind: 'firewall' },
  vpn_rule_created: { key: 'vpn.created', kind: 'firewall' },
  vpn_rule_updated: { key: 'vpn.updated', kind: 'firewall' },
  vpn_rule_deleted: { key: 'vpn.deleted', kind: 'firewall' },
  vpn_rules_applied: { key: 'vpn.applied', kind: 'firewall' },

  'POST /system/fail2ban/ban': { key: 'fail2ban.ban', kind: 'firewall' },
  'POST /system/fail2ban/unban': { key: 'fail2ban.unban', kind: 'firewall' },
  'POST /system/fail2ban/jail/control': { key: 'fail2ban.jailControl', kind: 'firewall' },
  'PUT /system/fail2ban/jail/settings': { key: 'fail2ban.jailSettings', kind: 'firewall' },
  'POST /system/fail2ban/reload': { key: 'fail2ban.reload', kind: 'firewall' },
  'DELETE /system/fail2ban/permanent-bans': { key: 'fail2ban.permanentRemove', kind: 'firewall' },
  'PUT /system/fail2ban/whitelist': { key: 'fail2ban.whitelist', kind: 'firewall' },

  'POST /users': { key: 'user.create', kind: 'user' },
  'DELETE /users/{id}': { key: 'user.delete', kind: 'user', target: id('user') },
  'PUT /users/{id}/role': { key: 'user.role', kind: 'user', target: id('user') },

  'POST /backups': { key: 'backup.create', kind: 'server' },
  'DELETE /backups/{name}': {
    key: 'backup.delete',
    kind: 'server',
    target: { param: 'name', type: 'raw' },
  },
  'POST /server/packages/upgrade': { key: 'server.upgrade', kind: 'server' },
  'POST /server/reboot': { key: 'server.reboot', kind: 'server' },
  'POST /server/services/{unit}/restart': {
    key: 'server.serviceRestart',
    kind: 'server',
    target: { param: 'unit', type: 'raw' },
  },
  'PUT /server/sysctl': { key: 'server.sysctl', kind: 'server' },
  'POST /server/sysctl/confirm': { key: 'server.sysctlConfirm', kind: 'server' },
  'PUT /server/system/hostname': { key: 'server.hostname', kind: 'server' },
  'PUT /server/system/timezone': { key: 'server.timezone', kind: 'server' },
  'PUT /notifications/settings': { key: 'notify.settings', kind: 'other' },
  'POST /notifications/test': { key: 'notify.test', kind: 'other' },
}

const LOGIN = 'POST /auth/login'

// Names the panel already loaded, by id.
export type AuditNames = Partial<Record<Exclude<TargetType, 'raw' | 'id'>, Record<string, string>>>

export interface AuditEntryLike {
  action: string
  details?: Record<string, unknown> | null
  username?: string
}

export interface AuditDescription {
  key: string // sentence key under "sentence."
  kind: AuditKind
  actor: string // who: the session user, or the username a login tried ('' unknown)
  params: Record<string, string>
  result: AuditResult
  method: string
  path: string // the concrete path when recorded, else the route
  status?: number
}

// auditResult classifies an HTTP status: 2xx done, 4xx refused, 5xx failed.
export function auditResult(status: number | undefined): AuditResult {
  if (status === undefined) return 'none'
  if (status >= 200 && status < 300) return 'ok'
  if (status >= 400 && status < 500) return 'denied'
  if (status >= 500) return 'error'
  return 'none'
}

// shortId keeps the first block of a UUID-like id.
export function shortId(value: string): string {
  return value.length > 12 ? value.slice(0, 8) : value
}

const quote = (s: string) => `«${s}»`

// routeVars reads the {param} segments of a route template from the
// concrete path ("/networks/{id}" + "/api/v1/networks/abc" -> {id: "abc"}).
function routeVars(template: string, path: string): Record<string, string> {
  const t = template.split('/')
  const p = path.replace(/^\/api\/v1/, '').split('/')
  if (t.length !== p.length) return {}
  const out: Record<string, string> = {}
  for (let i = 0; i < t.length; i++) {
    const m = /^\{(\w+)\}$/.exec(t[i])
    if (m) out[m[1]] = decodeURIComponent(p[i])
    else if (t[i] !== p[i]) return {}
  }
  return out
}

const str = (v: unknown) => (typeof v === 'string' ? v : '')

// describeAudit turns one entry into a sentence key, its parameters and the
// result class.
export function describeAudit(entry: AuditEntryLike, names: AuditNames): AuditDescription {
  const d = entry.details ?? {}
  const status = typeof d.status === 'number' ? d.status : undefined
  const { method, target: template } = parseAction(entry.action)
  const path = str(d.path) || template
  const shownPath = path.replace(/^\/api\/v1/, '')
  const routeKey = method ? `${method} ${template}` : template
  const user = entry.username ?? ''

  if (routeKey === LOGIN) {
    const actor = str(d.username) || user
    const ok = auditResult(status) === 'ok'
    return {
      key: ok ? 'login.ok' : 'login.fail',
      kind: 'login',
      actor,
      params: { user: actor || '—' },
      result: auditResult(status),
      method,
      path,
      status,
    }
  }

  const route = AUDIT_ROUTES[routeKey]
  if (!route) {
    return {
      key: method ? 'fallback.http' : 'fallback.action',
      kind: 'other',
      actor: user,
      params: { user, method, path: shownPath, action: entry.action },
      result: auditResult(status),
      method,
      path,
      status,
    }
  }

  const params: Record<string, string> = { user }
  let key = route.key
  if (!method) {
    // Legacy VPN rule entries: written by the handler after it succeeded,
    // with the rule's name (vpn_rules_applied has none).
    const name = str(d.rule_name) || shortId(str(d.rule_id))
    if (name) params.target = quote(name)
    else if (key !== 'vpn.applied') key = `${key}NoName`
  } else if (route.target) {
    const value = routeVars(template, path)[route.target.param]
    if (value) {
      const type = route.target.type
      const known = type === 'raw' || type === 'id' ? undefined : names[type]?.[value]
      params.target = quote(known ?? (type === 'raw' ? value : shortId(value)))
    } else {
      params.target = quote('?')
    }
  }
  return {
    key,
    kind: route.kind,
    actor: user,
    params,
    result: method ? auditResult(status) : 'ok',
    method,
    path,
    status,
  }
}

type T = (key: string, params?: Record<string, string>) => string

// auditSentence renders the entry with t bound to the audit namespace; an
// entry without a user says "unknown user".
export function auditSentence(entry: AuditEntryLike, names: AuditNames, t: T): string {
  const desc = describeAudit(entry, names)
  const params = { ...desc.params }
  if (!desc.key.startsWith('login.')) params.user ||= t('actor.unknown')
  return t(`sentence.${desc.key}`, params)
}

// matchesAuditQuery: every word of q appears in one of the texts (case
// ignored); an empty query matches everything.
export function matchesAuditQuery(texts: string[], q: string): boolean {
  const words = q.toLocaleLowerCase().split(/\s+/).filter(Boolean)
  if (words.length === 0) return true
  const hay = texts.join('\n').toLocaleLowerCase()
  return words.every((w) => hay.includes(w))
}
