// What the panel restores from its browser storage ('novusgate-storage').
// The mobile drawer state is not restored: an old copy saved it, and a
// phone then opened with the menu over the page. Pure, so
// tests/layoutState.test.mjs runs it in Node.

export type Theme = 'light' | 'dark' | 'system'

export interface RestoredAppState {
  currentNetworkId?: string | null
  theme?: Theme
}

const THEMES = new Set(['light', 'dark', 'system'])

// restoreAppState picks the valid saved fields and drops everything else.
export function restoreAppState(persisted: unknown): RestoredAppState {
  if (!persisted || typeof persisted !== 'object') return {}
  const p = persisted as Record<string, unknown>
  const out: RestoredAppState = {}
  if (p.currentNetworkId === null || typeof p.currentNetworkId === 'string') {
    out.currentNetworkId = p.currentNetworkId
  }
  if (typeof p.theme === 'string' && THEMES.has(p.theme)) out.theme = p.theme as Theme
  return out
}
