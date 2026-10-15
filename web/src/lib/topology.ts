// Topology view: the hub (this server) in the middle, VPN networks around
// it, each network's peers around the network, and an arrow between two
// networks when the policy matrix lets traffic through. Kept free of imports
// so it runs under `node --experimental-strip-types` in web/tests.

export interface TopoNetwork {
  id: string
  name: string
}

export interface TopoPeer {
  id: string
  name: string
  status: string
}

export type TopoCells = Record<string, Record<string, { verdict: string }>>

export interface TopoNode {
  id: string
  kind: 'hub' | 'network' | 'peer'
  label: string
  status?: string
  position: { x: number; y: number }
}

export interface TopoEdge {
  id: string
  source: string
  target: string
  kind: 'link' | 'policy'
  verdict?: string
}

const NETWORK_RADIUS = 280
const PEER_RADIUS = 150
const PEER_ARC = Math.PI * 0.9 // peers fan out over this angle, away from the hub

const round = (n: number) => Math.round(n)

export function buildTopology(
  networks: TopoNetwork[],
  peersByNetwork: Record<string, TopoPeer[]>,
  cells: TopoCells | undefined
): { nodes: TopoNode[]; edges: TopoEdge[] } {
  const nodes: TopoNode[] = [
    { id: 'hub', kind: 'hub', label: 'NovusGate', position: { x: 0, y: 0 } },
  ]
  const edges: TopoEdge[] = []
  networks.forEach((net, i) => {
    const angle = (2 * Math.PI * i) / Math.max(networks.length, 1) - Math.PI / 2
    const nx = NETWORK_RADIUS * Math.cos(angle)
    const ny = NETWORK_RADIUS * Math.sin(angle)
    const netId = `net:${net.id}`
    nodes.push({
      id: netId,
      kind: 'network',
      label: net.name,
      position: { x: round(nx), y: round(ny) },
    })
    edges.push({ id: `hub->${netId}`, source: 'hub', target: netId, kind: 'link' })
    const peers = peersByNetwork[net.id] ?? []
    peers.forEach((p, j) => {
      // Spread the peers over an arc centred on the direction away from the hub.
      const offset = peers.length === 1 ? 0 : (j / (peers.length - 1) - 0.5) * PEER_ARC
      const a = angle + offset
      const peerId = `peer:${p.id}`
      nodes.push({
        id: peerId,
        kind: 'peer',
        label: p.name,
        status: p.status,
        position: {
          x: round(nx + PEER_RADIUS * Math.cos(a)),
          y: round(ny + PEER_RADIUS * Math.sin(a)),
        },
      })
      edges.push({ id: `${netId}->${peerId}`, source: netId, target: peerId, kind: 'link' })
    })
  })
  if (cells) {
    for (const from of networks) {
      for (const to of networks) {
        const verdict = cells[from.id]?.[to.id]?.verdict
        if (from.id === to.id || (verdict !== 'allow' && verdict !== 'partial')) continue
        edges.push({
          id: `policy:${from.id}->${to.id}`,
          source: `net:${from.id}`,
          target: `net:${to.id}`,
          kind: 'policy',
          verdict,
        })
      }
    }
  }
  return { nodes, edges }
}
