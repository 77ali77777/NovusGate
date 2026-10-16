import assert from 'node:assert/strict'
import { test } from 'node:test'
import { restoreAppState } from '../src/lib/appStorage.ts'
import { roleLabelKey } from '../src/lib/userMenu.ts'
import { nodeSetKey, shouldFitView } from '../src/lib/topologyFit.ts'

test('restoreAppState keeps the network and theme, drops the drawer state', () => {
  assert.deepEqual(restoreAppState({ currentNetworkId: 'n1', theme: 'dark', sidebarOpen: true }), {
    currentNetworkId: 'n1',
    theme: 'dark',
  })
  assert.deepEqual(restoreAppState({ currentNetworkId: null }), { currentNetworkId: null })
})

test('restoreAppState ignores broken or foreign storage', () => {
  assert.deepEqual(restoreAppState(undefined), {})
  assert.deepEqual(restoreAppState(null), {})
  assert.deepEqual(restoreAppState('x'), {})
  assert.deepEqual(restoreAppState({ currentNetworkId: 5, theme: 'blue', sidebarOpen: true }), {})
  assert.deepEqual(restoreAppState({ theme: 'system' }), { theme: 'system' })
})

test('roleLabelKey maps the known roles and nothing else', () => {
  assert.equal(roleLabelKey('admin'), 'settings:users.roles.admin')
  assert.equal(roleLabelKey('operator'), 'settings:users.roles.operator')
  assert.equal(roleLabelKey('viewer'), 'settings:users.roles.viewer')
  assert.equal(roleLabelKey('root'), null)
  assert.equal(roleLabelKey(undefined), null)
})

test('nodeSetKey does not depend on order', () => {
  assert.equal(nodeSetKey(['b', 'a']), nodeSetKey(['a', 'b']))
  assert.notEqual(nodeSetKey(['a']), nodeSetKey(['a', 'b']))
  assert.equal(nodeSetKey([]), '')
})

test('shouldFitView fits a new, measured node set unless the user moved nodes', () => {
  const base = { initialized: true, key: 'a,b', fittedKey: '', userMoved: false }
  assert.equal(shouldFitView(base), true)
  assert.equal(shouldFitView({ ...base, fittedKey: 'a,b' }), false) // already fitted
  assert.equal(shouldFitView({ ...base, initialized: false }), false) // not measured yet
  assert.equal(shouldFitView({ ...base, key: '' }), false) // nothing to show
  assert.equal(shouldFitView({ ...base, userMoved: true }), false) // keep the user's layout
  assert.equal(shouldFitView({ ...base, fittedKey: 'a' }), true) // a peer appeared
})
