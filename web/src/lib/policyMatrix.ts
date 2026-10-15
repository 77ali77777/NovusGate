// Network Policies matrix: what traffic from one VPN network to another gets,
// derived from the VPN rules the same way the firewall evaluates them (in
// list order, first match wins). Kept free of imports so it runs under
// `node --experimental-strip-types` in web/tests.

export interface MatrixNetwork {
  id: string
  name: string
}

// The VPN rule fields the matrix needs (VPNFirewallRule has them all).
export interface MatrixRule {
  name: string
  enabled: boolean
  source_type: string
  source_network_id?: string
  dest_type: string
  dest_network_id?: string
  protocol: string
  port?: string
  action: string
}

export type CellVerdict = 'allow' | 'deny' | 'partial'

export interface MatrixCell {
  verdict: CellVerdict
  reason: string
  rules: string[] // names of the rules that touch this pair, in order
}

type Scope = 'none' | 'whole' | 'some'

// scope says how much of network netId an endpoint covers: a node or a
// custom address may be inside it, so it covers "some".
function scope(type: string, networkId: string | undefined, netId: string): Scope {
  if (type === 'any') return 'whole'
  if (type === 'network') return networkId === netId ? 'whole' : 'none'
  return 'some'
}

const verdictOf = (action: string): CellVerdict => (action === 'accept' ? 'allow' : 'deny')

// policyMatrix returns matrix[from][to]. rules must be in the order the API
// lists them (priority, then creation). nftEnforcing: the nftables engine
// drops traffic between different networks unless a rule allows it; in
// iptables mode traffic between VPN interfaces is accepted.
export function policyMatrix(
  networks: MatrixNetwork[],
  rules: MatrixRule[],
  nftEnforcing: boolean
): Record<string, Record<string, MatrixCell>> {
  const out: Record<string, Record<string, MatrixCell>> = {}
  for (const from of networks) {
    out[from.id] = {}
    for (const to of networks) {
      out[from.id][to.id] = cell(from.id, to.id, rules, nftEnforcing)
    }
  }
  return out
}

function cell(from: string, to: string, rules: MatrixRule[], nftEnforcing: boolean): MatrixCell {
  const touched: string[] = []
  const scoped: CellVerdict[] = []
  let final: CellVerdict | null = null
  let reason = ''
  for (const r of rules) {
    if (!r.enabled) continue
    const s = scope(r.source_type, r.source_network_id, from)
    const d = scope(r.dest_type, r.dest_network_id, to)
    if (s === 'none' || d === 'none') continue
    touched.push(r.name)
    const allTraffic = (r.protocol === 'all' || r.protocol === '') && !r.port
    if (s === 'whole' && d === 'whole' && allTraffic) {
      final = verdictOf(r.action)
      reason = `rule "${r.name}"`
      break
    }
    scoped.push(verdictOf(r.action))
  }
  if (final === null) {
    if (!nftEnforcing) {
      final = 'allow'
      reason = 'default (iptables mode accepts VPN traffic)'
    } else if (from === to) {
      final = 'allow'
      reason = 'default (same network)'
    } else {
      final = 'deny'
      reason = 'default (networks are isolated)'
    }
  }
  if (scoped.some((v) => v !== final)) {
    return { verdict: 'partial', reason: `some traffic differs from ${reason}`, rules: touched }
  }
  return { verdict: final, reason, rules: touched }
}
