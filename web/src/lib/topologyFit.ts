// When the topology map fits itself to the screen. The networks and each
// network's peers load separately, so the first fit can happen with only
// part of the map; it fits again when the set of nodes changes, but not
// after the user has dragged nodes into their own layout. Pure, so
// tests/layoutState.test.mjs runs it in Node.

// nodeSetKey names a set of node ids independent of their order.
export function nodeSetKey(ids: string[]): string {
  return [...ids].sort().join(',')
}

export interface FitState {
  initialized: boolean // every node has been measured
  key: string // nodeSetKey of the nodes shown now
  fittedKey: string // nodeSetKey of the last fit
  userMoved: boolean // the user dragged a node
}

export function shouldFitView(s: FitState): boolean {
  return s.initialized && s.key !== '' && s.key !== s.fittedKey && !s.userMoved
}
