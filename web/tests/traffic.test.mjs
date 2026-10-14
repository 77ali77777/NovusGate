// Run: npm test (node --experimental-strip-types)
import assert from 'node:assert/strict'
import test from 'node:test'
import { bucketLabel, totals } from '../src/lib/traffic.ts'

test('bucketLabel shows the time for a day and the date for longer ranges', () => {
  const t = '2026-10-15T09:05:00Z'
  assert.match(bucketLabel(t, '24h'), /^\d\d:05$/) // local hour
  assert.match(bucketLabel(t, '7d'), /^\d\d\.\d\d \d\d:00$/)
  assert.match(bucketLabel(t, '30d'), /^\d\d\.\d\d$/)
})

test('totals sums the interval bytes of a range', () => {
  assert.deepEqual(totals([{ t: 'a', rx: 5, tx: 1 }, { t: 'b', rx: 7, tx: 0 }]), { rx: 12, tx: 1 })
  assert.deepEqual(totals([]), { rx: 0, tx: 0 })
})
