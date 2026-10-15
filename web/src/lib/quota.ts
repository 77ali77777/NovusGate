// Traffic quotas (P9c) in the panel: the API stores MB (10^6 bytes), the
// form takes GB. Kept free of imports so it runs under
// `node --experimental-strip-types`.

const maxMB = 1_000_000_000 // 1 PB, as the backend allows

interface LimitsLike {
  profiles: { id: string; quota_mb: number | null; quota_action: string }[] | null
  node_limits: { node_id: string; profile_id: string }[] | null
  quota_states: { node_id: string; used_bytes: number; exceeded_at: string | null }[] | null
}

export interface QuotaUsage {
  usedBytes: number
  quotaBytes: number
  percent: number // 0-100, for the bar
  exceeded: boolean
  action: string // block or throttle
}

// quotaFor is the node's use of its profile's quota, or null without one.
export function quotaFor(nodeId: string, limits: LimitsLike | undefined): QuotaUsage | null {
  const nl = limits?.node_limits?.find((l) => l.node_id === nodeId)
  const profile = limits?.profiles?.find((p) => p.id === nl?.profile_id)
  if (!profile || profile.quota_mb == null) return null
  const st = limits?.quota_states?.find((s) => s.node_id === nodeId)
  const usedBytes = st?.used_bytes ?? 0
  const quotaBytes = profile.quota_mb * 1e6
  return {
    usedBytes,
    quotaBytes,
    percent: Math.min(100, Math.round((usedBytes / quotaBytes) * 100)),
    exceeded: st?.exceeded_at != null,
    action: profile.quota_action,
  }
}

// gbToMb reads a GB field: empty is no quota (null), a positive number
// becomes MB, anything else is 'invalid'.
export function gbToMb(text: string): number | null | 'invalid' {
  const s = text.trim().replace(',', '.')
  if (s === '') return null
  if (!/^\d+(\.\d+)?$/.test(s)) return 'invalid'
  const mb = Math.round(Number(s) * 1000)
  return mb < 1 || mb > maxMB ? 'invalid' : mb
}

export function mbToGb(mb: number | null | undefined): string {
  return mb == null ? '' : String(mb / 1000)
}

export function formatBytes(bytes: number): string {
  return bytes >= 1e9 ? `${(bytes / 1e9).toFixed(1)} GB` : `${Math.round(bytes / 1e6)} MB`
}
