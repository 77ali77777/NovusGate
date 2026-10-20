// Panel roles (P9a), lowest first; mirrors roleRank in the backend.
const rank: Record<string, number> = { viewer: 1, operator: 2, admin: 3 }

// roleAtLeast reports whether role may do what need allows. The UI uses it
// only to hide controls; the backend refuses the request anyway.
export function roleAtLeast(
  role: string | undefined,
  need: 'viewer' | 'operator' | 'admin'
): boolean {
  return (rank[role ?? ''] ?? 0) >= rank[need]
}

// Sections of a role (custom roles, 2026-10-20); /auth/me reports a level
// for each, for built-in roles too.
export type Section =
  | 'dashboard'
  | 'networks'
  | 'devices'
  | 'configs'
  | 'groups'
  | 'vpn_rules'
  | 'limits'
  | 'host_firewall'
  | 'fail2ban'
  | 'audit'

const levels: Record<string, number> = { none: 0, view: 1, edit: 2 }

// allowed reports whether the signed-in user may view or edit a section.
export function allowed(
  me: { permissions?: Record<string, string> | null } | undefined,
  section: Section,
  level: 'view' | 'edit'
): boolean {
  return (levels[me?.permissions?.[section] ?? 'none'] ?? 0) >= levels[level]
}

// The sections behind each menu entry: shown when any of them is visible.
const navSections: Record<string, Section[]> = {
  '/dashboard': ['dashboard'],
  '/networks': ['networks'],
  '/nodes': ['devices'],
  '/topology': ['networks'],
  '/groups': ['groups'],
  '/firewall': ['vpn_rules', 'limits', 'host_firewall'],
  '/fail2ban': ['fail2ban'],
  '/audit': ['audit'],
}

// navVisible: whether a menu entry is shown. Settings (own password and
// sessions) is everyone's; the server page is an admin's.
export function navVisible(
  me: { role?: string; permissions?: Record<string, string> | null } | undefined,
  href: string
): boolean {
  if (href === '/settings') return true
  if (href === '/server') return me?.role === 'admin'
  const sections = navSections[href]
  return !sections || sections.some((s) => allowed(me, s, 'view'))
}

export interface NetworkScope {
  mode: 'all' | 'listed' | 'own'
  owned: number
  max: number
  full: boolean // own networks: the limit is reached
}

// networkScope reads which networks the signed-in role covers. Answers from
// servers before scope modes say it by network_ids.
export function networkScope(
  me?: {
    scope_mode?: string
    network_ids?: string[] | null
    owned_networks?: number
    max_networks?: number
  } | null
): NetworkScope {
  const mode =
    me?.scope_mode === 'own' || me?.scope_mode === 'listed' || me?.scope_mode === 'all'
      ? me.scope_mode
      : (me?.network_ids?.length ?? 0) > 0
        ? 'listed'
        : 'all'
  const owned = me?.owned_networks ?? 0
  const max = me?.max_networks ?? 0
  return { mode, owned, max, full: mode === 'own' && owned >= max }
}
