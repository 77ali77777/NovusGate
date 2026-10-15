import assert from 'node:assert/strict'
import { test } from 'node:test'
import { buildTopology } from '../src/lib/topology.ts'

const networks = [
  { id: 'a', name: 'Office' },
  { id: 'b', name: 'Branch' },
]
const peers = {
  a: [{ id: 'n1', name: 'laptop', status: 'online' }],
  b: [
    { id: 'n2', name: 'cam', status: 'offline' },
    { id: 'n3', name: 'nas', status: 'online' },
  ],
}
const cells = {
  a: { a: { verdict: 'allow' }, b: { verdict: 'allow' } },
  b: { a: { verdict: 'deny' }, b: { verdict: 'partial' } },
}

test('the hub sits in the middle, networks around it, peers around their network', () => {
  const t = buildTopology(networks, peers, cells)
  const hub = t.nodes.find((n) => n.id === 'hub')
  assert.deepEqual(hub.position, { x: 0, y: 0 })
  assert.equal(t.nodes.filter((n) => n.kind === 'network').length, 2)
  assert.equal(t.nodes.filter((n) => n.kind === 'peer').length, 3)
  const pos = t.nodes.map((n) => `${n.position.x},${n.position.y}`)
  assert.equal(new Set(pos).size, pos.length, 'no two nodes share a position')
  const cam = t.nodes.find((n) => n.id === 'peer:n2')
  assert.equal(cam.status, 'offline')
  assert.equal(cam.label, 'cam')
})

test('edges: hub to every network, network to its peers, allowed traffic between networks', () => {
  const t = buildTopology(networks, peers, cells)
  const ids = t.edges.map((e) => e.id).sort()
  assert.deepEqual(ids, [
    'hub->net:a',
    'hub->net:b',
    'net:a->peer:n1',
    'net:b->peer:n2',
    'net:b->peer:n3',
    'policy:a->b',
  ])
  assert.equal(t.edges.find((e) => e.id === 'policy:a->b').verdict, 'allow')
})

test('partial policy edges are kept and marked; no matrix means no policy edges', () => {
  const t = buildTopology(networks, peers, { a: { b: { verdict: 'partial' } }, b: {} })
  assert.equal(t.edges.find((e) => e.id === 'policy:a->b').verdict, 'partial')
  assert.equal(buildTopology(networks, peers, undefined).edges.filter((e) => e.kind === 'policy').length, 0)
})
