import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  deviceMemberships,
  groupsInNetwork,
  limitsInNetwork,
  networkKpis,
  rulesForNetwork,
  topTraffic,
} from '../src/lib/networkOverview.ts'

// The network page shows everything about one network: KPIs, devices with
// their groups and limits, every rule that touches it, groups, limits.

const now = new Date('2026-10-20T12:00:00Z')
const day = 24 * 3600 * 1000
const nodes = [
  { id: 'a', name: 'pc', status: 'online', transfer_rx: 100, transfer_tx: 50, config_outdated: true },
  { id: 'b', name: 'phone', status: 'offline', transfer_rx: 10, transfer_tx: 5, tunnel_override: 'full', expires_at: new Date(now.getTime() + 2 * day).toISOString() },
  { id: 'c', name: 'old', status: 'expired', transfer_rx: 0, transfer_tx: 0 },
  { id: 'd', name: 'srv', status: 'online', transfer_rx: 1000, transfer_tx: 2000, tunnel_override: 'split' },
]

test('networkKpis counts devices, traffic and what needs attention', () => {
  assert.deepEqual(networkKpis(nodes, 'split', now), {
    total: 4, online: 2, offline: 1, expired: 1, expiringSoon: 1, fullTunnel: 1, outdated: 1, rx: 1110, tx: 2055,
  })
  // A full-tunnel network: every device without its own choice goes full.
  assert.equal(networkKpis(nodes, 'full', now).fullTunnel, 3)
})

const groups = [
  { id: 'g1', name: 'staff', members: [{ node_id: 'a', network_id: 'n1' }, { node_id: 'x', network_id: 'n2' }] },
  { id: 'g2', name: 'elsewhere', members: [{ node_id: 'y', network_id: 'n2' }] },
  { id: 'g3', name: 'servers', members: [{ node_id: 'd', network_id: 'n1' }] },
]

test('rulesForNetwork finds rules by network, device, group or any, with the side', () => {
  const rules = [
    { id: 'r1', source_type: 'network', source_network_id: 'n1', dest_type: 'network', dest_network_id: 'n2' },
    { id: 'r2', source_type: 'node', source_node_id: 'x', dest_type: 'node', dest_node_id: 'd' },
    { id: 'r3', source_type: 'group', source_group_id: 'g1', dest_type: 'custom', dest_ip: '8.8.8.8' },
    { id: 'r4', source_type: 'network', source_network_id: 'n2', dest_type: 'group', dest_group_id: 'g2' },
    { id: 'r5', source_type: 'any', dest_type: 'network', dest_network_id: 'n1' },
  ]
  const got = rulesForNetwork(rules, 'n1', new Set(['a', 'b', 'c', 'd']), groupsInNetwork(groups, 'n1').map((g) => g.id))
  assert.deepEqual(got.map((r) => `${r.rule.id}:${r.side}`), ['r1:from', 'r2:to', 'r3:from', 'r5:both'])
})

test('groupsInNetwork lists groups with members here', () => {
  assert.deepEqual(groupsInNetwork(groups, 'n1'), [
    { id: 'g1', name: 'staff', here: 1, total: 2 },
    { id: 'g3', name: 'servers', here: 1, total: 1 },
  ])
})

test('limitsInNetwork counts the devices here a profile covers, directly or by group', () => {
  const profiles = [
    { id: 'p1', name: 'slow', node_ids: ['b'], group_ids: ['g1'], down_kbps: 1000, up_kbps: 500 },
    { id: 'p2', name: 'other', node_ids: ['z'], group_ids: ['g2'] },
  ]
  assert.deepEqual(
    limitsInNetwork(profiles, new Set(['a', 'b', 'c', 'd']), groups).map((l) => `${l.id}:${l.devices}`),
    ['p1:2']
  )
  assert.deepEqual(deviceMemberships('a', groups, profiles), { groups: ['staff'], limits: ['slow'] })
  assert.deepEqual(deviceMemberships('d', groups, profiles), { groups: ['servers'], limits: [] })
})

test('topTraffic orders devices by traffic', () => {
  assert.deepEqual(topTraffic(nodes, 2).map((n) => `${n.id}:${n.total}`), ['d:3000', 'a:150'])
})
