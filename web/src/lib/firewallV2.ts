// Helpers for the nftables (firewall v2) tab. They import only modules that
// have no imports themselves, so they run under `node --experimental-strip-types`
// in web/tests.
import { errorBodyCode } from '../api/errors.ts'

// parseList splits a user-typed list of addresses on commas and whitespace.
export function parseList(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter((s) => s !== '')
}

// secondsLeft is the whole seconds until deadline, rounded up and never
// negative, so a pending change never shows 0 while it can still be confirmed.
export function secondsLeft(deadline: string, now: Date): number {
  const t = new Date(deadline).getTime()
  if (Number.isNaN(t)) return 0
  return Math.max(0, Math.ceil((t - now.getTime()) / 1000))
}

export function formatPorts(from: number, to: number): string {
  return from === to ? String(from) : `${from}-${to}`
}

// toRFC3339 converts a datetime-local input value (local time) to UTC.
export function toRFC3339(local: string): string | undefined {
  if (!local) return undefined
  const d = new Date(local)
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString()
}

// AgoText is a translation key (firewallv2 namespace) with its count.
export interface AgoText {
  key: 'ago.justNow' | 'ago.seconds' | 'ago.minutes'
  count: number
}

// formatAgo says how long ago a dropped source was last seen, as a
// translation key and count the view resolves.
export function formatAgo(seconds: number): AgoText {
  if (seconds <= 0) return { key: 'ago.justNow', count: 0 }
  if (seconds < 60) return { key: 'ago.seconds', count: seconds }
  return { key: 'ago.minutes', count: Math.floor(seconds / 60) }
}

const byteUnits = ['B', 'KB', 'MB', 'GB', 'TB']

// formatBytes renders a byte count with binary units (1 KB = 1024 B).
export function formatBytes(bytes: number): string {
  let i = 0
  let v = bytes
  while (v >= 1024 && i < byteUnits.length - 1) {
    v /= 1024
    i++
  }
  return i === 0 ? `${v} B` : `${v.toFixed(1)} ${byteUnits[i]}`
}

// usagePercent is count/max as a whole percent, capped at 100; 0 without max.
export function usagePercent(count: number, max: number): number {
  if (max <= 0) return 0
  return Math.min(100, Math.floor((count / max) * 100))
}

export type EngineState = 'disabled' | 'not_ready' | 'error'

// engineState reads why a /firewall/v2 request failed: the server runs the
// iptables engine (disabled, the default after an install), the engine is
// still starting (not_ready, iptables import pending), or something else failed.
export function engineState(err: unknown): EngineState {
  const code = errorBodyCode(err)
  if (code === 'firewall_disabled') return 'disabled'
  if (code === 'firewall_not_ready') return 'not_ready'
  return 'error'
}

// retryFirewallV2 is the retry rule of the /firewall/v2 queries: an engine
// that is off stays off, so it is not retried; a starting engine and real
// failures are (twice).
export function retryFirewallV2(failures: number, err: unknown): boolean {
  return engineState(err) !== 'disabled' && failures < 2
}

export type EngineMode = 'nft' | 'iptables' | 'starting' | 'unknown'

// engineMode is the firewall engine as the GET /firewall/v2/state query sees
// it: an answer means nftables runs; an off engine means iptables; a starting
// engine is nftables on its way. Loading or any other failure is unknown.
export function engineMode(q: { data: unknown; error: unknown }): EngineMode {
  if (q.data) return 'nft'
  if (!q.error) return 'unknown'
  const s = engineState(q.error)
  if (s === 'disabled') return 'iptables'
  if (s === 'not_ready') return 'starting'
  return 'unknown'
}
