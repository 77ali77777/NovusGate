// Server administration (P10a): the step-up retry and the views of the
// host's `ip -j` lists. Pure, so tests/serverAdmin.test.mjs runs it in Node.
import { errorBodyCode } from '../api/errors.ts'

// StepUpCancelled: the person closed the password prompt.
export class StepUpCancelled extends Error {
  constructor() {
    super('step-up cancelled')
    this.name = 'StepUpCancelled'
  }
}

// Step runs a server change; a step-up password prompt appears when the
// server asks for one, and the change is retried after it.
export type Step = <T>(run: () => Promise<T>) => Promise<T>

// withStepUp runs a server change; when the server asks for the password
// again (403 step_up_required) it waits for askPassword, which confirms it
// with the server or throws StepUpCancelled, and runs the change once more.
export async function withStepUp<T>(
  run: () => Promise<T>,
  askPassword: () => Promise<void>
): Promise<T> {
  try {
    return await run()
  } catch (err) {
    if (errorBodyCode(err) !== 'step_up_required') throw err
    await askPassword()
    return run()
  }
}

// PasswordGate holds the changes waiting for the step-up password: one
// prompt for all of them, and every one settles when it closes (two saves
// started together must not leave the first one waiting forever).
export interface PasswordGate {
  ask: () => Promise<void>
  resolveAll: () => void
  rejectAll: (err: Error) => void
  isOpen: () => boolean
  onChange?: (open: boolean) => void
}

export function createPasswordGate(): PasswordGate {
  let waiting: { resolve: () => void; reject: (e: Error) => void }[] = []
  const settle = (fn: (w: (typeof waiting)[number]) => void) => {
    const all = waiting
    waiting = []
    for (const w of all) fn(w)
    gate.onChange?.(false)
  }
  const gate: PasswordGate = {
    ask: () =>
      new Promise((resolve, reject) => {
        waiting.push({ resolve, reject })
        if (waiting.length === 1) gate.onChange?.(true)
      }),
    resolveAll: () => settle((w) => w.resolve()),
    rejectAll: (err) => settle((w) => w.reject(err)),
    isOpen: () => waiting.length > 0,
  }
  return gate
}

export interface AddressRow {
  name: string
  state: string
  addresses: string[]
}

export interface RouteRow {
  dst: string
  gateway: string
  dev: string
}

type JSONObject = { [key: string]: unknown }

function objects(list: readonly unknown[] | null | undefined): JSONObject[] {
  return (list ?? []).filter(
    (x): x is JSONObject => !!x && typeof x === 'object' && !Array.isArray(x)
  )
}

function str(v: unknown): string {
  return typeof v === 'string' || typeof v === 'number' ? String(v) : ''
}

// addressRows turns `ip -j addr` into one row per interface.
export function addressRows(list: readonly unknown[] | null | undefined): AddressRow[] {
  return objects(list).map((link) => ({
    name: str(link.ifname),
    state: str(link.operstate),
    addresses: objects(Array.isArray(link.addr_info) ? link.addr_info : []).map(
      (a) => `${str(a.local)}/${str(a.prefixlen)}`
    ),
  }))
}

// routeRows turns `ip -j route` into destination, gateway and device.
export function routeRows(list: readonly unknown[] | null | undefined): RouteRow[] {
  return objects(list).map((r) => ({
    dst: str(r.dst),
    gateway: str(r.gateway),
    dev: str(r.dev),
  }))
}

export type SysctlField =
  | { kind: 'select'; options: string[] }
  | { kind: 'number'; min: number; max: number }

// The kernel settings the server accepts (hostadmin.sysctlRules); the
// server checks them again.
const sysctlFields: Record<string, SysctlField> = {
  'net.ipv4.ip_forward': { kind: 'select', options: ['0', '1'] },
  'net.ipv4.conf.all.rp_filter': { kind: 'select', options: ['0', '1', '2'] },
  'net.netfilter.nf_conntrack_max': { kind: 'number', min: 1024, max: 16777216 },
  'net.ipv4.tcp_congestion_control': { kind: 'select', options: ['bbr', 'cubic'] },
  'net.core.default_qdisc': { kind: 'select', options: ['fq', 'fq_codel', 'pfifo_fast', 'cake'] },
}

export function sysctlField(key: string): SysctlField | undefined {
  return sysctlFields[key]
}
