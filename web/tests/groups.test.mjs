import assert from 'node:assert/strict'
import { test } from 'node:test'
import { groupsByNode } from '../src/lib/groups.ts'

const member = (node_id) => ({ node_id, name: node_id, virtual_ip: '10.0.0.2', network_id: 'n1' })

test('groupsByNode lists the group names of each node, in group order', () => {
  const byNode = groupsByNode([
    { id: 'g1', name: 'office', members: [member('a'), member('b')] },
    null,
    { id: 'g2', name: 'admins', members: [member('a')] },
    { id: 'g3', name: 'empty', members: null },
  ])
  assert.deepEqual(byNode.get('a'), [
    { id: 'g1', name: 'office' },
    { id: 'g2', name: 'admins' },
  ])
  assert.deepEqual(byNode.get('b'), [{ id: 'g1', name: 'office' }])
  assert.equal(byNode.get('c'), undefined)
})

test('groupsByNode accepts a missing list', () => {
  assert.equal(groupsByNode(undefined).size, 0)
  assert.equal(groupsByNode(null).size, 0)
})
