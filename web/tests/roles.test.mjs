import assert from 'node:assert/strict'
import { test } from 'node:test'
import { networkScope, roleAtLeast } from '../src/lib/roles.ts'

test('roleAtLeast follows viewer < operator < admin', () => {
  assert.equal(roleAtLeast('admin', 'operator'), true)
  assert.equal(roleAtLeast('operator', 'operator'), true)
  assert.equal(roleAtLeast('operator', 'admin'), false)
  assert.equal(roleAtLeast('viewer', 'operator'), false)
  assert.equal(roleAtLeast('viewer', 'viewer'), true)
})

test('an unknown or missing role can do nothing', () => {
  assert.equal(roleAtLeast(undefined, 'viewer'), false)
  assert.equal(roleAtLeast('root', 'viewer'), false)
})

// Custom roles (2026-10-20): the panel follows /auth/me permissions.
test('allowed reads the section levels', async () => {
  const { allowed } = await import('../src/lib/roles.ts')
  const me = { permissions: { devices: 'edit', networks: 'view', vpn_rules: 'none' } }
  assert.equal(allowed(me, 'devices', 'edit'), true)
  assert.equal(allowed(me, 'devices', 'view'), true)
  assert.equal(allowed(me, 'networks', 'edit'), false)
  assert.equal(allowed(me, 'networks', 'view'), true)
  assert.equal(allowed(me, 'vpn_rules', 'view'), false)
  assert.equal(allowed(me, 'groups', 'view'), false) // missing: none
  assert.equal(allowed(undefined, 'devices', 'view'), false)
})

test('navVisible hides menu entries the role cannot see', async () => {
  const { navVisible } = await import('../src/lib/roles.ts')
  const me = { role: 'custom', permissions: { devices: 'view', limits: 'view' } }
  assert.equal(navVisible(me, '/nodes'), true)
  assert.equal(navVisible(me, '/networks'), false)
  assert.equal(navVisible(me, '/firewall'), true) // limits live under the firewall
  assert.equal(navVisible(me, '/audit'), false)
  assert.equal(navVisible(me, '/settings'), true) // own password, sessions
  assert.equal(navVisible(me, '/server'), false) // admin only
  assert.equal(navVisible({ role: 'admin', permissions: {} }, '/server'), true)
})

// Own networks (2026-10-20): the scope comes from /auth/me; older servers
// say it only by network_ids.
test('networkScope reads the role scope and the own-network limit', () => {
  assert.deepEqual(networkScope({ scope_mode: 'own', owned_networks: 1, max_networks: 3 }), {
    mode: 'own',
    owned: 1,
    max: 3,
    full: false,
  })
  assert.equal(networkScope({ scope_mode: 'own', owned_networks: 3, max_networks: 3 }).full, true)
  assert.equal(networkScope({ network_ids: ['n1'] }).mode, 'listed')
  assert.equal(networkScope({ network_ids: [] }).mode, 'all')
  assert.equal(networkScope({ scope_mode: 'listed', network_ids: ['n1'] }).full, false)
  assert.equal(networkScope(undefined).mode, 'all')
})
