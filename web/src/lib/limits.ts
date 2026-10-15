// Limit profiles (P9b) in the panel: the API stores speeds in kbit/s, the
// form takes Mbit/s. Kept free of imports so it runs under
// `node --experimental-strip-types`.

const maxKbps = 100_000_000 // 100 Gbit/s, as the backend allows

// mbpsToKbps reads a Mbit/s field: empty is unlimited (null), a positive
// number becomes kbit/s (at least 1), anything else is 'invalid'.
export function mbpsToKbps(text: string): number | null | 'invalid' {
  const s = text.trim().replace(',', '.')
  if (s === '') return null
  if (!/^\d+(\.\d+)?$/.test(s)) return 'invalid'
  const mbps = Number(s)
  if (!(mbps > 0)) return 'invalid'
  const kbps = Math.max(1, Math.round(mbps * 1000))
  return kbps > maxKbps ? 'invalid' : kbps
}

// kbpsToMbps fills the Mbit/s field from a stored value.
export function kbpsToMbps(kbps: number | null | undefined): string {
  if (kbps == null) return ''
  return String(kbps / 1000)
}

export function formatRate(kbps: number): string {
  return kbps >= 1000 ? `${kbps / 1000} Mbit/s` : `${kbps} kbit/s`
}

interface WindowLike {
  days: number[] | null
  from: string
  to: string
}

// scheduleSummary: "Mon, Tue, Fri 08:00–18:00; Sat 22:00–02:00" with the
// given day names (index 0 = Sunday).
export function scheduleSummary(
  windows: WindowLike[] | null | undefined,
  dayNames: string[]
): string {
  return (windows ?? [])
    .map((w) => {
      const days = [...(w.days ?? [])].sort((a, b) => ((a + 6) % 7) - ((b + 6) % 7))
      return `${days.map((d) => dayNames[d]).join(', ')} ${w.from}–${w.to}`
    })
    .join('; ')
}
