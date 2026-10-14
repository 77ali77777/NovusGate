// Helpers for the node traffic history chart. Kept free of imports so they
// run under `node --experimental-strip-types` in web/tests.

export type TrafficRange = '24h' | '7d' | '30d'

export interface TrafficPoint {
  t: string // start of the interval (RFC 3339)
  rx: number // bytes in the interval, as the hub counts them
  tx: number
}

const pad = (n: number) => String(n).padStart(2, '0')

// bucketLabel is the x-axis label of a point in local time: the time of day
// for 24h, day and hour for 7d, the day for 30d.
export function bucketLabel(t: string, range: TrafficRange): string {
  const d = new Date(t)
  const day = `${pad(d.getDate())}.${pad(d.getMonth() + 1)}`
  const time = `${pad(d.getHours())}:${pad(d.getMinutes())}`
  if (range === '24h') return time
  if (range === '7d') return `${day} ${pad(d.getHours())}:00`
  return day
}

export function totals(points: TrafficPoint[]): { rx: number; tx: number } {
  return points.reduce((sum, p) => ({ rx: sum.rx + p.rx, tx: sum.tx + p.tx }), { rx: 0, tx: 0 })
}
