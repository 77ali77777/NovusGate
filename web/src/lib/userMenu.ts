// The top bar's user menu. Pure, so tests/layoutState.test.mjs runs it in Node.

const ROLES = new Set(['admin', 'operator', 'viewer'])

// roleLabelKey returns the i18n key of a role's name, or null for a role the
// panel does not know (shown as is).
export function roleLabelKey(role: string | undefined): string | null {
  return role && ROLES.has(role) ? `settings:users.roles.${role}` : null
}
