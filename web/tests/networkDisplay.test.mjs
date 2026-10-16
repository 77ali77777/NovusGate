import assert from 'node:assert/strict'
import { test } from 'node:test'
import { isAdminInterface, networkLabel } from '../src/lib/networkDisplay.ts'

const t = (key) => `<${key}>`

test('only wg0 is the admin network', () => {
  assert.equal(isAdminInterface('wg0'), true)
  assert.equal(isAdminInterface('wg1'), false)
  assert.equal(isAdminInterface(''), false)
  assert.equal(isAdminInterface(undefined), false)
  assert.equal(isAdminInterface(null), false)
})

test('the admin network shows the translated name and note', () => {
  const label = networkLabel({ name: 'Admin Management Network', interface_name: 'wg0' }, t)
  assert.deepEqual(label, {
    name: '<networks:admin.name>',
    note: '<networks:admin.note>',
    admin: true,
  })
})

test('stats rows name the interface "interface"', () => {
  const label = networkLabel({ name: 'Admin Management Network', interface: 'wg0' }, t)
  assert.equal(label.admin, true)
  assert.equal(label.name, '<networks:admin.name>')
})

test('other networks keep their own name and have no note', () => {
  assert.deepEqual(networkLabel({ name: 'Ofis', interface_name: 'wg1' }, t), {
    name: 'Ofis',
    note: null,
    admin: false,
  })
  // The DB name alone does not make a network the admin one.
  assert.equal(networkLabel({ name: 'Admin Management Network', interface_name: 'wg3' }, t).admin, false)
})

// The policy matrix and VPN rules know a network by id and name only; the
// interface comes from the network list.
test('networkLabelById finds the admin network by id', async () => {
  const { networkLabelById } = await import('../src/lib/networkDisplay.ts')
  const t = (k) => ({ 'networks:admin.name': 'Admin VPN', 'networks:admin.note': 'note' })[k] ?? k
  const nets = [{ id: 'a', name: 'Admin Management Network', interface_name: 'wg0' }, { id: 'b', name: 'Ofis', interface_name: 'wg1' }]
  assert.equal(networkLabelById(nets, 'a', 'Admin Management Network', t), 'Admin VPN')
  assert.equal(networkLabelById(nets, 'b', 'Ofis', t), 'Ofis')
  assert.equal(networkLabelById(undefined, 'a', 'Admin Management Network', t), 'Admin Management Network', 'list not loaded yet')
  assert.equal(networkLabelById(nets, 'x', '', t), '', 'unknown id keeps the given name')
})
