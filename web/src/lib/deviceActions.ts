// Which actions a device (node) offers in the list row and on its detail
// page (B6, C3), and the network the create form starts with (C2). Pure, so
// tests/deviceActions.test.mjs runs it in Node.

export type RowAction = 'config' | 'edit' | 'delete'
// rotate: a new key pair (VLAN plan M4) — for a leaked config, or a device
// whose private key the server never held.
export type DetailAction = 'download' | 'qr' | 'script' | 'sync' | 'rotate'

// Changes need the devices permission (edit), config downloads the configs
// one (private keys; built-in roles: operators and admins). Imported devices
// have no private key on the server, so they have no config.
export function rowActions(
  device: { has_config: boolean },
  canEdit: boolean,
  canConfig = canEdit
): RowAction[] {
  const out: RowAction[] = []
  if (canConfig && device.has_config) out.push('config')
  if (canEdit) out.push('edit', 'delete')
  return out
}

export function detailActions(
  device: { has_config: boolean },
  canEdit: boolean,
  canConfig = canEdit
): DetailAction[] {
  const out: DetailAction[] = []
  if (canConfig && device.has_config) out.push('download', 'qr', 'script')
  if (canEdit) out.push('sync', 'rotate')
  return out
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
