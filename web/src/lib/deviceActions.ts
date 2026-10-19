// Which actions a device (node) offers in the list row and on its detail
// page (B6, C3), and the network the create form starts with (C2). Pure, so
// tests/deviceActions.test.mjs runs it in Node.

export type RowAction = 'config' | 'edit' | 'delete'
// rotate: a new key pair (VLAN plan M4) — for a leaked config, or a device
// whose private key the server never held.
export type DetailAction = 'download' | 'qr' | 'script' | 'sync' | 'rotate'

// Config downloads and changes need an operator; viewers only look. Imported
// devices have no private key on the server, so they have no config.
export function rowActions(device: { has_config: boolean }, canEdit: boolean): RowAction[] {
  if (!canEdit) return []
  return device.has_config ? ['config', 'edit', 'delete'] : ['edit', 'delete']
}

export function detailActions(device: { has_config: boolean }, canEdit: boolean): DetailAction[] {
  if (!canEdit) return []
  return device.has_config ? ['download', 'qr', 'script', 'sync', 'rotate'] : ['sync', 'rotate']
}

// defaultNetworkId: the network chosen in the sidebar if it still exists,
// else the first one. While the list loads, the current choice is kept.
export function defaultNetworkId(
  current: string | null | undefined,
  networks: { id: string }[] | undefined
): string {
  if (!networks) return current ?? ''
  if (current && networks.some((n) => n.id === current)) return current
  return networks[0]?.id ?? ''
}
