// How a network is shown in the panel (C9). The hub's own network (wg0) is
// called "Admin Management Network" in the DB; the panel shows it as
// "Admin VPN" with a one-line note, without renaming it in the DB. Pure, so
// tests/networkDisplay.test.mjs runs it in Node.

// Translate is the part of i18next's t this file needs; keys carry their
// namespace, so any t works.
export type Translate = (key: string) => string

// The admin network is the one on the hub's first interface.
export const ADMIN_INTERFACE = 'wg0'

export function isAdminInterface(iface: string | null | undefined): boolean {
  return iface === ADMIN_INTERFACE
}

export interface NetworkLabel {
  name: string
  note: string | null // a one-line explanation, only for the admin network
  admin: boolean
}

// networkLabel accepts a network (interface_name) or a stats row (interface).
export function networkLabel(
  network: { name: string; interface_name?: string | null; interface?: string | null },
  t: Translate
): NetworkLabel {
  const admin = isAdminInterface(network.interface_name ?? network.interface)
  if (!admin) return { name: network.name, note: null, admin }
  return { name: t('networks:admin.name'), note: t('networks:admin.note'), admin }
}

// networkLabelById: the shown name of a network known only by id and name
// (policy matrix, VPN rules); the interface comes from the network list,
// which may not be loaded yet.
export function networkLabelById(
  networks: readonly { id: string; name: string; interface_name?: string | null }[] | undefined,
  id: string | null | undefined,
  name: string,
  t: Translate
): string {
  const net = networks?.find((n) => n.id === id)
  return net ? networkLabel({ name, interface_name: net.interface_name }, t).name : name
}
