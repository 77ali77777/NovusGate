// Helpers for the Network Policies matrix (the matrix itself is computed by
// the backend: GET /firewall/policy-matrix). Kept free of imports so they run
// under `node --experimental-strip-types` in web/tests.

// pairRulePriority is the priority for a rule made from a matrix cell: just
// before every existing rule (lower runs first), so an older catch-all rule
// does not shadow it. 1 is the floor (the rule form turns 0 into 100).
export function pairRulePriority(priorities: number[]): number {
  if (priorities.length === 0) return 100
  return Math.max(1, Math.min(...priorities) - 1)
}
