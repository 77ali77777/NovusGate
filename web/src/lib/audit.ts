// Helpers for the Audit page. Kept free of imports so they run under
// `node --experimental-strip-types` in web/tests.

// parseAction splits "METHOD /api/v1/route" into its method and the route
// without the API prefix; older entries (e.g. "vpn_rule_created") stay as
// they are.
export function parseAction(action: string): { method: string; target: string } {
  const m = /^(GET|POST|PUT|PATCH|DELETE) (\S+)$/.exec(action)
  if (!m) return { method: '', target: action }
  return { method: m[1], target: m[2].replace(/^\/api\/v1/, '') }
}

export interface AuditCursor {
  before: string
  beforeId: string
}

// nextBefore is the paging cursor for the next (older) page: the time and id
// of the oldest entry shown (the id keeps entries with the same time), or
// undefined when the last page was not full.
export function nextBefore(
  page: { id: string; created_at: string }[],
  limit: number
): AuditCursor | undefined {
  if (page.length === 0 || page.length < limit) return undefined
  const last = page[page.length - 1]
  return { before: last.created_at, beforeId: last.id }
}
