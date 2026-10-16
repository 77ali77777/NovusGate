// Tab layout of the Firewall page: five top-level tabs, the nftables pages
// grouped under Advanced. Kept free of runtime imports so it runs in web/tests.
import type { EngineMode } from './firewallV2.ts'

export const FIREWALL_TABS = ['overview', 'server', 'networks', 'limits', 'advanced'] as const
export type FirewallTab = (typeof FIREWALL_TABS)[number]

export const ADVANCED_SECTIONS = ['nft', 'live', 'history', 'system-rules'] as const
export type AdvancedSection = (typeof ADVANCED_SECTIONS)[number]

// Where each of the old ten tabs lives now.
const HOME: Record<string, FirewallTab> = {
  overview: 'overview',
  'host-rules': 'server',
  'open-ports': 'server',
  'blocked-ips': 'server',
  'vpn-rules': 'networks',
  limits: 'limits',
  advanced: 'advanced',
  live: 'advanced',
  history: 'advanced',
  'system-rules': 'advanced',
}

// homeOf maps an old tab id to its new top-level tab (unknown: overview).
export function homeOf(oldTab: string): FirewallTab {
  return HOME[oldTab] ?? 'overview'
}

// advancedLocked: the Advanced tab carries a lock badge when the server is
// known to run iptables (its pages need nftables). Loading shows no lock.
export function advancedLocked(mode: EngineMode): boolean {
  return mode === 'iptables'
}
