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

// networkMatches: does a search find this network? It looks at the stored
// name, the shown name ("Admin VPN"), the CIDR and the interface.
export function networkMatches(
  network: { name: string; cidr: string; interface_name?: string | null },
  query: string,
  t: Translate
): boolean {
  const q = query.trim().toLowerCase()
  if (!q) return true
  return [
    network.name,
    networkLabel(network, t).name,
    network.cidr,
    network.interface_name ?? '',
  ].some((s) => s.toLowerCase().includes(q))
}

export interface InterfaceState {
  state: 'up' | 'down' | 'unknown'
  reason: string // why it did not come up, when the server knows
}

// interfaceState is the hub interface of a network as the server reports it
// (interface_up, interface_error); an older server without them is unknown.
export function interfaceState(network: {
  interface_up?: boolean
  interface_error?: string
}): InterfaceState {
  if (network.interface_up === undefined) return { state: 'unknown', reason: '' }
  return {
    state: network.interface_up ? 'up' : 'down',
    reason: network.interface_up ? '' : (network.interface_error ?? ''),
  }
}

export interface DNSState {
  state: 'served' | 'direct' | 'unknown'
  hub: string // the address configs name as DNS when served
  reason: string // why the hub does not answer ("" when unknown or for viewers)
}

// dnsState reads whether the hub answers DNS for a network (server-side
// routing P3): served, configs name the hub; direct, configs name the DNS
// servers themselves until the hub can listen.
export function dnsState(network: {
  cidr?: string
  dns_served?: boolean
  dns_error?: string
}): DNSState {
  const hub = hubAddress(network.cidr ?? '')
  if (network.dns_served === undefined) return { state: 'unknown', hub, reason: '' }
  return network.dns_served
    ? { state: 'served', hub, reason: '' }
    : { state: 'direct', hub, reason: network.dns_error ?? '' }
}

// hubAddress is the first address of an IPv4 CIDR ("" when it is not one).
function hubAddress(cidr: string): string {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/\d+$/.exec(cidr)
  if (!m) return ''
  const n = ((+m[1] << 24) >>> 0) + (+m[2] << 16) + (+m[3] << 8) + +m[4] + 1
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.')
}
