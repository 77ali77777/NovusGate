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
