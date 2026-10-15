// Node groups (P9a) as the Nodes page shows them.
interface GroupLike {
  id: string
  name: string
  members: { node_id: string }[] | null
}

export interface GroupRef {
  id: string
  name: string
}

// groupsByNode maps each node id to the groups it is in, in list order.
export function groupsByNode(
  groups: (GroupLike | null)[] | null | undefined
): Map<string, GroupRef[]> {
  const out = new Map<string, GroupRef[]>()
  for (const g of groups ?? []) {
    if (!g) continue
    for (const m of g.members ?? []) {
      const list = out.get(m.node_id) ?? []
      list.push({ id: g.id, name: g.name })
      out.set(m.node_id, list)
    }
  }
  return out
}
