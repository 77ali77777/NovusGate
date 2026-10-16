import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import {
  AUDIT_KINDS,
  AUDIT_ROUTES,
  auditResult,
  auditSentence,
  describeAudit,
  matchesAuditQuery,
} from '../src/lib/auditText.ts'

const load = (lang) =>
  JSON.parse(readFileSync(new URL(`../src/i18n/locales/${lang}/audit.json`, import.meta.url), 'utf8'))
const locales = { en: load('en'), az: load('az') }

// t mimics i18next for one namespace: dotted keys and {{param}} interpolation.
const tFor = (lang) => (key, params = {}) => {
  const v = key.split('.').reduce((o, k) => (o && typeof o === 'object' ? o[k] : undefined), locales[lang])
  if (typeof v !== 'string') throw new Error(`missing ${lang} key ${key}`)
  return v.replace(/\{\{(\w+)\}\}/g, (_, p) => (p in params ? params[p] : `{{${p}}}`))
}
const az = tFor('az')
const en = tFor('en')

const NET = '11111111-2222-3333-4444-555555555555'
const names = { network: { [NET]: 'Ofis' }, group: {}, limit: {}, user: {}, node: {} }
const entry = (action, details = {}, username = 'admin') => ({ action, details, username })

test('known routes read as sentences in az and en', () => {
  const create = entry('POST /api/v1/networks/{networkId}/servers', { status: 201, path: `/api/v1/networks/${NET}/servers` })
  assert.equal(auditSentence(create, names, az), 'admin «Ofis» şəbəkəsində cihaz yaratdı')
  assert.equal(auditSentence(create, names, en), 'admin created a device in network «Ofis»')

  const del = entry('DELETE /api/v1/networks/{id}', { status: 204, path: `/api/v1/networks/${NET}` })
  assert.equal(auditSentence(del, names, az), 'admin «Ofis» şəbəkəsini sildi')
  assert.equal(auditSentence(del, names, en), 'admin deleted network «Ofis»')

  const pw = entry('PUT /api/v1/auth/password', { status: 204, path: '/api/v1/auth/password' })
  assert.equal(auditSentence(pw, names, az), 'admin parolunu dəyişdi')
  assert.equal(auditSentence(pw, names, en), 'admin changed their password')

  const port = entry('POST /api/v1/firewall/host/port/open', { status: 200, path: '/api/v1/firewall/host/port/open' })
  assert.equal(auditSentence(port, names, az), 'admin firewall-da port açdı')
  assert.equal(auditSentence(port, names, en), 'admin opened a port in the firewall')
})

test('legacy VPN rule entries name the rule', () => {
  const e = entry('vpn_rule_created', { rule_id: 'r1', rule_name: 'Ofis → Anbar' })
  assert.equal(auditSentence(e, names, az), 'admin «Ofis → Anbar» VPN qaydasını yaratdı')
  assert.equal(auditSentence(e, names, en), 'admin created VPN rule «Ofis → Anbar»')
  assert.equal(describeAudit(e, names).kind, 'firewall')
  assert.equal(describeAudit(e, names).result, 'ok') // written only after success
})

test('login attempts say who tried and whether it worked', () => {
  const ok = entry('POST /api/v1/auth/login', { status: 200, path: '/api/v1/auth/login', username: 'admin' }, '')
  const bad = entry('POST /api/v1/auth/login', { status: 401, path: '/api/v1/auth/login', username: 'root' }, '')
  assert.equal(auditSentence(ok, names, az), 'Giriş cəhdi: admin — uğurlu')
  assert.equal(auditSentence(bad, names, az), 'Giriş cəhdi: root — uğursuz')
  assert.equal(auditSentence(ok, names, en), 'Login attempt: admin — succeeded')
  assert.equal(auditSentence(bad, names, en), 'Login attempt: root — failed')
  assert.equal(describeAudit(bad, names).kind, 'login')
  assert.equal(describeAudit(bad, names).actor, 'root')
})

test('unknown routes and actions fall back to the raw request, nothing hidden', () => {
  const e = entry('POST /api/v1/something/{id}/new', { status: 200, path: '/api/v1/something/42/new' })
  assert.equal(auditSentence(e, names, az), 'admin POST /something/42/new')
  assert.equal(auditSentence(e, names, en), 'admin POST /something/42/new')
  assert.equal(describeAudit(e, names).kind, 'other')
  const odd = entry('mystery_event', {})
  assert.equal(auditSentence(odd, names, en), 'admin: mystery_event')
  // no user on the entry
  const anon = entry('DELETE /api/v1/networks/{id}', { status: 204, path: `/api/v1/networks/${NET}` }, '')
  assert.equal(auditSentence(anon, names, en), 'unknown user deleted network «Ofis»')
})

test('ids resolve to names the panel knows, else a short id', () => {
  const gone = '99999999-8888-7777-6666-555555555555'
  const e = entry('DELETE /api/v1/networks/{id}', { status: 204, path: `/api/v1/networks/${gone}` })
  assert.equal(auditSentence(e, names, az), 'admin «99999999» şəbəkəsini sildi')
  const g = entry('PUT /api/v1/groups/{id}/members', { status: 200, path: '/api/v1/groups/g-1/members' })
  assert.equal(auditSentence(g, { ...names, group: { 'g-1': 'Mühasibat' } }, az), 'admin «Mühasibat» qrupunun üzvlərini dəyişdi')
  const u = entry('PUT /api/v1/users/{id}/role', { status: 200, path: '/api/v1/users/u-7/role' })
  assert.equal(auditSentence(u, { ...names, user: { 'u-7': 'leyla' } }, en), "admin changed the role of user «leyla»")
  const svc = entry('POST /api/v1/server/services/{unit}/restart', { status: 200, path: '/api/v1/server/services/ssh.service/restart' })
  assert.equal(auditSentence(svc, names, az), 'admin «ssh.service» xidmətini yenidən başlatdı')
})

test('results: 2xx ok, 4xx denied, 5xx error, none without a status', () => {
  assert.equal(auditResult(201), 'ok')
  assert.equal(auditResult(204), 'ok')
  assert.equal(auditResult(403), 'denied')
  assert.equal(auditResult(401), 'denied')
  assert.equal(auditResult(500), 'error')
  assert.equal(auditResult(undefined), 'none')
})

test('every route has a sentence and a known kind in both languages', () => {
  for (const [route, r] of Object.entries(AUDIT_ROUTES)) {
    assert.ok(AUDIT_KINDS.includes(r.kind), `${route}: kind ${r.kind}`)
    for (const t of [az, en]) assert.ok(t(`sentence.${r.key}`, {}), route)
  }
  for (const k of AUDIT_KINDS) for (const t of [az, en]) assert.ok(t(`kinds.${k}`))
})

test('the search matches the sentence and the raw fields, ignoring case', () => {
  assert.equal(matchesAuditQuery(['admin «Ofis» şəbəkəsini sildi', '/api/v1/networks/x', '10.0.0.1'], 'ofis'), true)
  assert.equal(matchesAuditQuery(['admin «Ofis» şəbəkəsini sildi'], '  '), true)
  assert.equal(matchesAuditQuery(['admin', '10.0.0.1'], '10.0.0'), true)
  assert.equal(matchesAuditQuery(['admin'], 'anbar'), false)
})
