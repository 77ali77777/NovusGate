// Helpers for the nftables (firewall v2) tab. Kept free of imports so they
// run under `node --experimental-strip-types` in web/tests.

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

// formatAgo says how long ago a dropped source was last seen.
export function formatAgo(seconds: number): string {
  if (seconds <= 0) return 'just now'
  if (seconds < 60) return `${seconds} s ago`
  return `${Math.floor(seconds / 60)} min ago`
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
