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
