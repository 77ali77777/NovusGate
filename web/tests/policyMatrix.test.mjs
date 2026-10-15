import assert from 'node:assert/strict'
import { test } from 'node:test'
import { policyMatrix } from '../src/lib/policyMatrix.ts'

const nets = [
  { id: 'a', name: 'Office' },
  { id: 'b', name: 'Branch' },
  { id: 'c', name: 'Guests' },
]

const rule = (over) => ({
  name: 'r',
  enabled: true,
  source_type: 'network',
  dest_type: 'network',
  protocol: 'all',
  port: '',
  action: 'accept',
  ...over,
})

test('defaults: nftables isolates networks, iptables lets everything through', () => {
  const nft = policyMatrix(nets, [], true)
  assert.equal(nft.a.a.verdict, 'allow')
  assert.equal(nft.a.b.verdict, 'deny')
  assert.match(nft.a.b.reason, /default/)
  const ipt = policyMatrix(nets, [], false)
  assert.equal(ipt.a.b.verdict, 'allow')
})

test('the first whole-network rule decides, in list order', () => {
  const rules = [
    rule({ name: 'office to branch', source_network_id: 'a', dest_network_id: 'b' }),
    rule({ name: 'block all', source_type: 'any', dest_type: 'any', action: 'drop' }),
  ]
  const m = policyMatrix(nets, rules, true)
  assert.equal(m.a.b.verdict, 'allow')
  assert.deepEqual(m.a.b.rules, ['office to branch'])
  assert.equal(m.b.a.verdict, 'deny')
  assert.equal(m.a.a.verdict, 'deny') // the any/any drop comes before the same-network default
  assert.deepEqual(m.c.c.rules, ['block all'])
})

test('rules limited to ports, protocols or hosts make a cell partial', () => {
  const rules = [
    rule({ name: 'web only', source_network_id: 'a', dest_network_id: 'b', protocol: 'tcp', port: '443' }),
    rule({ name: 'one node', source_type: 'node', source_node_id: 'n1', dest_network_id: 'c', action: 'accept' }),
    rule({ name: 'disabled', enabled: false, source_network_id: 'b', dest_network_id: 'c' }),
  ]
  const m = policyMatrix(nets, rules, true)
  assert.equal(m.a.b.verdict, 'partial')
  assert.deepEqual(m.a.b.rules, ['web only'])
  // a node rule can match from any network to c
  assert.equal(m.b.c.verdict, 'partial')
  assert.equal(m.a.c.verdict, 'partial')
  // disabled rules are ignored; c->b stays at the default
  assert.equal(m.c.b.verdict, 'deny')
  assert.deepEqual(m.c.b.rules, [])
})

test('a scoped rule that agrees with the final verdict keeps the cell whole', () => {
  const rules = [rule({ name: 'ssh drop', source_network_id: 'a', dest_network_id: 'b', protocol: 'tcp', port: '22', action: 'drop' })]
  const m = policyMatrix(nets, rules, true) // a->b ends at the default drop anyway
  assert.equal(m.a.b.verdict, 'deny')
  assert.deepEqual(m.a.b.rules, ['ssh drop'])
})
