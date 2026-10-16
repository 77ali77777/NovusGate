// What a node routes through the hub: split (the VPN networks) or full (all
// IPv4, the hub is its internet exit). A network has a mode; a node may
// override it. Pure, so tests/tunnelMode.test.mjs runs it in Node.

export type TunnelMode = 'split' | 'full'

// The engine modes of lib/firewallV2 (kept as plain strings here).
type Engine = 'nft' | 'iptables' | 'starting' | 'unknown'

const isMode = (m: string | null | undefined): m is TunnelMode => m === 'split' || m === 'full'

// effectiveTunnel is a node's mode: its override, or else its network's.
export function effectiveTunnel(
  override: string | null | undefined,
  networkMode: string | null | undefined
): TunnelMode {
  if (isMode(override)) return override
  return networkMode === 'full' ? 'full' : 'split'
}

// affectedByNetworkChange counts the nodes that change when their network
// goes from one mode to another: those without an override. Each needs its
// config downloaded again (WireGuard routes come from the config file).
export function affectedByNetworkChange(
  nodes: readonly { tunnel_override?: string | null }[],
  from: TunnelMode,
  to: TunnelMode
): number {
  if (from === to) return 0
  return nodes.filter((n) => !isMode(n.tunnel_override)).length
}

// fullTunnelBlock says why full tunnel cannot be chosen, or null when it
// can: it needs an admin, and the admin VPN (wg0) needs the nftables engine
// (iptables mode has no NAT for it; the server answers 409).
export function fullTunnelBlock(p: {
  isAdmin: boolean
  adminNetwork: boolean
  engine: Engine
}): 'role' | 'engine' | null {
  if (!p.isAdmin) return 'role'
  if (p.adminNetwork && p.engine !== 'nft') return 'engine'
  return null
}

export type TunnelResult = 'saved' | 'pending' | 'confirmed' | 'rolledBack'

// tunnelResultState is where a tunnel change stands after Apply: saved at
// once (no firewall confirmation), waiting for confirmation, confirmed (the
// stored mode is the requested one) or rolled back (the deadline passed
// without it). Right after Confirm the list may not be refreshed yet: that
// is still "pending", never "rolled back". An empty stored value (no
// override) matches "".
export function tunnelResultState(p: {
  hadPending: boolean
  stillPending: boolean
  stored: string | null | undefined
  requested: string
  deadlinePassed: boolean
}): TunnelResult {
  if (!p.hadPending) return 'saved'
  if (p.stillPending) return 'pending'
  if ((p.stored ?? '') === p.requested) return 'confirmed'
  return p.deadlinePassed ? 'rolledBack' : 'pending'
}
