import assert from 'node:assert/strict'
import { test } from 'node:test'
import { interfaceState } from '../src/lib/networkDisplay.ts'

// The network card said "Active" whatever the interface did. It now shows
// what the server reports: running, down (with the reason), or unknown for
// an older server that does not send the fields.
test('interfaceState reads the live interface fields', () => {
  assert.deepEqual(interfaceState({ interface_up: true, interface_error: '' }), { state: 'up', reason: '' })
  assert.deepEqual(interfaceState({ interface_up: false, interface_error: 'systemctl start failed' }), {
    state: 'down',
    reason: 'systemctl start failed',
  })
  assert.deepEqual(interfaceState({ interface_up: false, interface_error: '' }), { state: 'down', reason: '' })
  assert.deepEqual(interfaceState({}), { state: 'unknown', reason: '' })
})

// Server-side routing P3: whether the hub answers DNS for the network.
test('dnsState reads the hub DNS fields', async () => {
  const { dnsState } = await import('../src/lib/networkDisplay.ts')
  assert.deepEqual(dnsState({ cidr: '10.10.0.0/24', dns_served: true, dns_error: '' }), {
    state: 'served',
    hub: '10.10.0.1',
    reason: '',
  })
  assert.deepEqual(dnsState({ cidr: '10.20.0.0/24', dns_served: false, dns_error: 'bind: address in use' }), {
    state: 'direct',
    hub: '10.20.0.1',
    reason: 'bind: address in use',
  })
  assert.equal(dnsState({ cidr: '10.20.0.0/24' }).state, 'unknown')
})
