import assert from 'node:assert/strict'
import { test } from 'node:test'
import { describeAudit } from '../src/lib/auditText.ts'
import { engineMode } from '../src/lib/firewallV2.ts'
import { matrixCellLabel } from '../src/lib/matrixReason.ts'
import { networkMatches } from '../src/lib/networkDisplay.ts'

// Review of 708b2c1 (UX stage 1).

const disabled = { response: { status: 409, data: { error: { code: 'firewall_disabled', message: 'x' } } } }

// A cached nft state must not hide that the server went back to iptables.
test('engineMode trusts the latest error over cached data', () => {
  assert.equal(engineMode({ data: { mode: 'nft' }, error: disabled }), 'iptables')
  assert.equal(engineMode({ data: { mode: 'nft' }, error: null }), 'nft')
  assert.equal(engineMode({ data: undefined, error: disabled }), 'iptables')
})

// A failed login names the account someone TRIED; it is not that user's
// own action, so the user filter must not list it under them.
test('a failed login is nobody\'s action in the user filter', () => {
  const login = (status, username) => ({
    action: 'POST /api/v1/auth/login',
    username: null,
    details: { path: '/api/v1/auth/login', status, username },
  })
  const names = { network: {}, group: {}, limit: {}, user: {}, node: {} }
  assert.equal(describeAudit(login(401, 'admin'), names).filterUser, '')
  assert.equal(describeAudit(login(200, 'admin'), names).filterUser, 'admin')
  const change = { action: 'POST /api/v1/networks', username: 'operator1', details: { path: '/api/v1/networks', status: 201 } }
  assert.equal(describeAudit(change, names).filterUser, 'operator1')
})

// The admin network is shown as "Admin VPN": searching that must find it.
test('network search matches the shown name too', () => {
  const t = (k) => ({ 'networks:admin.name': 'Admin VPN', 'networks:admin.note': 'n' })[k] ?? k
  const admin = { name: 'Admin Management Network', cidr: '10.99.0.0/24', interface_name: 'wg0' }
  const office = { name: 'Ofis', cidr: '10.20.0.0/24', interface_name: 'wg1' }
  assert.ok(networkMatches(admin, 'admin vpn', t))
  assert.ok(networkMatches(admin, 'management', t), 'the stored name still matches')
  assert.ok(networkMatches(office, '10.20', t))
  assert.ok(networkMatches(office, 'wg1', t))
  assert.ok(!networkMatches(office, 'admin', t))
  assert.ok(networkMatches(office, '', t), 'empty search shows all')
})

// Screen readers must hear the verdict, not only the reason.
test('matrixCellLabel says the verdict', () => {
  const t = (k, v) => (k === 'firewall:matrix.reason.rule' ? `rule "${v.rule}"` : k)
  const cell = { verdict: 'deny', reason: 'r', reason_key: 'rule', rule: 'block-db' }
  const label = matrixCellLabel(t, 'Ofis', 'Serverlər', cell, 'Qadağa')
  assert.match(label, /^Ofis → Serverlər: Qadağa/)
  assert.match(label, /block-db/)
})
