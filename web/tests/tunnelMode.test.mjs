import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  affectedByNetworkChange,
  effectiveTunnel,
  fullTunnelBlock,
} from '../src/lib/tunnelMode.ts'

// A node follows its network unless it has its own mode.
test('effectiveTunnel: override wins, else the network', () => {
  assert.equal(effectiveTunnel('', 'full'), 'full')
  assert.equal(effectiveTunnel(undefined, 'split'), 'split')
  assert.equal(effectiveTunnel('split', 'full'), 'split')
  assert.equal(effectiveTunnel('full', 'split'), 'full')
  assert.equal(effectiveTunnel('', undefined), 'split', 'an older server without the field is split')
})

// Only nodes without an override change with their network; each needs its
// config downloaded again.
test('affectedByNetworkChange counts the nodes that follow the network', () => {
  const nodes = [{ tunnel_override: '' }, { tunnel_override: 'split' }, { tunnel_override: '' }]
  assert.equal(affectedByNetworkChange(nodes, 'split', 'full'), 2)
  assert.equal(affectedByNetworkChange(nodes, 'full', 'full'), 0)
  assert.equal(affectedByNetworkChange([], 'split', 'full'), 0)
})

// Full tunnel needs an admin; on the admin VPN (wg0) it also needs nftables
// (the server answers 409 full_tunnel_needs_nft otherwise).
test('fullTunnelBlock says why full tunnel is not available', () => {
  assert.equal(fullTunnelBlock({ isAdmin: false, adminNetwork: false, engine: 'nft' }), 'role')
  assert.equal(fullTunnelBlock({ isAdmin: true, adminNetwork: true, engine: 'iptables' }), 'engine')
  assert.equal(fullTunnelBlock({ isAdmin: true, adminNetwork: true, engine: 'unknown' }), 'engine')
  assert.equal(fullTunnelBlock({ isAdmin: true, adminNetwork: true, engine: 'nft' }), null)
  assert.equal(fullTunnelBlock({ isAdmin: true, adminNetwork: false, engine: 'iptables' }), null)
})
