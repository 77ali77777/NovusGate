// What the network page shows about one network: its KPIs, the rules that
// touch it (by the network, one of its devices, a group with members in it,
// or "any"), its groups, the limits on its devices and who uses the most
// traffic. Kept free of imports so it runs in web/tests.

interface OvNode {
  id: string
  name: string
  status: string
  transfer_rx?: number
  transfer_tx?: number
  expires_at?: string | null
  tunnel_override?: string
  config_outdated?: boolean
}

const SOON = 7 * 24 * 3600 * 1000

export interface NetworkKpis {
  total: number
  online: number
  offline: number
  expired: number
  expiringSoon: number // expires within 7 days, not expired yet
  fullTunnel: number // effective: the device's own choice, else the network's
  outdated: number // config needs downloading once more
  rx: number
  tx: number
}

export function networkKpis(nodes: OvNode[], networkTunnel: string, now: Date): NetworkKpis {
  const k: NetworkKpis = {
    total: 0,
    online: 0,
    offline: 0,
    expired: 0,
    expiringSoon: 0,
    fullTunnel: 0,
    outdated: 0,
    rx: 0,
    tx: 0,
  }
  for (const n of nodes) {
    k.total++
    if (n.status === 'online') k.online++
    else if (n.status === 'expired') k.expired++
    else k.offline++
    if (n.status !== 'expired' && n.expires_at) {
      const left = new Date(n.expires_at).getTime() - now.getTime()
      if (left > 0 && left <= SOON) k.expiringSoon++
    }
    if ((n.tunnel_override || networkTunnel) === 'full') k.fullTunnel++
    if (n.config_outdated) k.outdated++
    k.rx += n.transfer_rx ?? 0
    k.tx += n.transfer_tx ?? 0
  }
  return k
}

interface RuleLike {
  id: string
  source_type: string
  source_network_id?: string | null
  source_node_id?: string | null
  source_group_id?: string | null
  dest_type: string
  dest_network_id?: string | null
  dest_node_id?: string | null
  dest_group_id?: string | null
}

export type RuleSide = 'from' | 'to' | 'both'

// rulesForNetwork keeps the rules with an end in the network: from (the
// network starts), to (it is reached) or both, in the given order.
export function rulesForNetwork<R extends RuleLike>(
  rules: R[],
  networkId: string,
  nodeIds: Set<string>,
  groupIds: string[]
): { rule: R; side: RuleSide }[] {
  const groups = new Set(groupIds)
  const here = (type: string, net?: string | null, node?: string | null, group?: string | null) => {
    switch (type) {
      case 'any':
        return true
      case 'network':
        return net === networkId
      case 'node':
        return !!node && nodeIds.has(node)
      case 'group':
        return !!group && groups.has(group)
      default:
        return false
    }
  }
  const out: { rule: R; side: RuleSide }[] = []
  for (const r of rules) {
    const from = here(r.source_type, r.source_network_id, r.source_node_id, r.source_group_id)
    const to = here(r.dest_type, r.dest_network_id, r.dest_node_id, r.dest_group_id)
    if (from && to) out.push({ rule: r, side: 'both' })
    else if (from) out.push({ rule: r, side: 'from' })
    else if (to) out.push({ rule: r, side: 'to' })
  }
  return out
}

interface GroupLike {
  id: string
  name: string
  members?: { node_id: string; network_id: string }[] | null
}

// groupsInNetwork lists the groups with members in the network.
export function groupsInNetwork(groups: GroupLike[], networkId: string) {
  return groups
    .map((g) => ({
      id: g.id,
      name: g.name,
      here: (g.members ?? []).filter((m) => m.network_id === networkId).length,
      total: (g.members ?? []).length,
    }))
    .filter((g) => g.here > 0)
}

interface ProfileLike {
  id: string
  name: string
  node_ids?: string[] | null
  group_ids?: string[] | null
  down_kbps?: number | null
  up_kbps?: number | null
  quota_mb?: number | null
}

// coveredNodes: the devices a profile covers, directly or through a group.
function coveredNodes(p: ProfileLike, groups: GroupLike[]): Set<string> {
  const out = new Set(p.node_ids ?? [])
  const gids = new Set(p.group_ids ?? [])
  for (const g of groups) {
    if (!gids.has(g.id)) continue
    for (const m of g.members ?? []) out.add(m.node_id)
  }
  return out
}

// limitsInNetwork lists the profiles that cover devices of the network,
// with how many of them.
export function limitsInNetwork<P extends ProfileLike>(
  profiles: P[],
  nodeIds: Set<string>,
  groups: GroupLike[]
) {
  return profiles
    .map((p) => {
      let devices = 0
      for (const id of coveredNodes(p, groups)) if (nodeIds.has(id)) devices++
      return { ...p, devices }
    })
    .filter((p) => p.devices > 0)
}

// deviceMemberships: the groups and limit profiles of one device.
export function deviceMemberships(nodeId: string, groups: GroupLike[], profiles: ProfileLike[]) {
  return {
    groups: groups
      .filter((g) => (g.members ?? []).some((m) => m.node_id === nodeId))
      .map((g) => g.name),
    limits: profiles.filter((p) => coveredNodes(p, groups).has(nodeId)).map((p) => p.name),
  }
}

// topTraffic: the n devices with the most traffic (received + sent).
export function topTraffic<N extends OvNode>(nodes: N[], n: number) {
  return nodes
    .map((d) => ({ ...d, total: (d.transfer_rx ?? 0) + (d.transfer_tx ?? 0) }))
    .filter((d) => d.total > 0)
    .sort((a, b) => b.total - a.total)
    .slice(0, n)
}
