import assert from 'node:assert/strict'
import { test } from 'node:test'

// The Firewall page groups its ten old tabs into five; every old tab has
// exactly one home, so nothing disappears from the page.
test('every old firewall tab lives in exactly one new tab', async () => {
  const { FIREWALL_TABS, ADVANCED_SECTIONS, homeOf } = await import('../src/lib/firewallTabs.ts')
  assert.deepEqual(FIREWALL_TABS, ['overview', 'server', 'networks', 'limits', 'advanced'])
  assert.deepEqual(ADVANCED_SECTIONS, ['nft', 'live', 'history', 'system-rules'])
  const old = ['overview', 'host-rules', 'open-ports', 'vpn-rules', 'limits', 'blocked-ips', 'advanced', 'live', 'history', 'system-rules']
  const want = {
    overview: 'overview',
    'host-rules': 'server',
    'open-ports': 'server',
    'blocked-ips': 'server',
    'vpn-rules': 'networks',
    limits: 'limits',
    advanced: 'advanced',
    live: 'advanced',
    history: 'advanced',
    'system-rules': 'advanced',
  }
  for (const id of old) assert.equal(homeOf(id), want[id], id)
  assert.equal(homeOf('nope'), 'overview')
})

// The page reads the engine from GET /firewall/v2/state: data means nftables,
// 409 firewall_disabled means iptables, firewall_not_ready means starting.
test('engineMode reads the engine from the v2 state query', async () => {
  const { engineMode } = await import('../src/lib/firewallV2.ts')
  const err = (code, status = 409) => ({ response: { status, data: { error: { code, message: 'x' } } } })
  assert.equal(engineMode({ data: { pending: null }, error: null }), 'nft')
  assert.equal(engineMode({ data: undefined, error: err('firewall_disabled') }), 'iptables')
  assert.equal(engineMode({ data: undefined, error: err('firewall_not_ready') }), 'starting')
  assert.equal(engineMode({ data: undefined, error: err('forbidden', 403) }), 'unknown')
  assert.equal(engineMode({ data: undefined, error: null }), 'unknown', 'still loading')
})

test('the Advanced tab is locked only when the engine is known to be iptables', async () => {
  const { advancedLocked } = await import('../src/lib/firewallTabs.ts')
  assert.equal(advancedLocked('iptables'), true)
  assert.equal(advancedLocked('nft'), false)
  assert.equal(advancedLocked('starting'), false)
  assert.equal(advancedLocked('unknown'), false)
})
