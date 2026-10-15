// present: a generated API list as a plain array. Go encodes a nil slice as
// null, and the generated types allow null items; both are dropped. Kept
// free of imports so it runs under `node --experimental-strip-types`.
export function present<T>(list: readonly (T | null | undefined)[] | null | undefined): T[] {
  return (list ?? []).filter((x): x is T => x !== null && x !== undefined)
}
