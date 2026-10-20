import assert from 'node:assert/strict'
import { test } from 'node:test'
import { defaultNetworkId, detailActions, rowActions } from '../src/lib/deviceActions.ts'

test('viewers get no row or detail actions', () => {
  assert.deepEqual(rowActions({ has_config: true }, false), [])
  assert.deepEqual(detailActions({ has_config: true }, false), [])
})

test('operators get config, edit and delete in the row', () => {
  assert.deepEqual(rowActions({ has_config: true }, true), ['config', 'edit', 'delete'])
})

test('imported devices (no private key) have no config action', () => {
  assert.deepEqual(rowActions({ has_config: false }, true), ['edit', 'delete'])
  // ... but a new key gives them one (VLAN plan M4)
  assert.deepEqual(detailActions({ has_config: false }, true), ['sync', 'rotate'])
})

test('the detail page offers config, QR, Linux script and reconnect', () => {
  assert.deepEqual(detailActions({ has_config: true }, true), ['download', 'qr', 'script', 'sync', 'rotate'])
})

test('the create form defaults to the current network when it exists', () => {
  const nets = [{ id: 'a' }, { id: 'b' }]
  assert.equal(defaultNetworkId('b', nets), 'b')
  assert.equal(defaultNetworkId('gone', nets), 'a')
  assert.equal(defaultNetworkId(null, nets), 'a')
  assert.equal(defaultNetworkId('b', undefined), 'b')
  assert.equal(defaultNetworkId(null, []), '')
})

// Custom roles: changing devices and downloading configs (private keys)
// are separate permissions.
test('config actions follow the configs permission, edits the devices one', () => {
  assert.deepEqual(rowActions({ has_config: true }, false, true), ['config'])
  assert.deepEqual(rowActions({ has_config: true }, true, false), ['edit', 'delete'])
  assert.deepEqual(detailActions({ has_config: true }, false, true), ['download', 'qr', 'script'])
  assert.deepEqual(detailActions({ has_config: true }, true, false), ['sync', 'rotate'])
})
