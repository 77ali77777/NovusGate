// BantimeUnit is the unit a fail2ban duration is shown in; the component
// translates it (fail2ban:duration.<unit>) with the count.
export type BantimeUnit = 'permanent' | 'days' | 'hours' | 'min' | 'sec'

export const formatBantime = (s: string): { unit: BantimeUnit; count: number } => {
  const n = parseInt(s, 10)
  if (n === -1) return { unit: 'permanent', count: n }
  if (n >= 86400) return { unit: 'days', count: Math.floor(n / 86400) }
  if (n >= 3600) return { unit: 'hours', count: Math.floor(n / 3600) }
  if (n >= 60) return { unit: 'min', count: Math.floor(n / 60) }
  return { unit: 'sec', count: n }
}
