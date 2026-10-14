// Run: npm test (node --experimental-strip-types)
import assert from 'node:assert/strict'
import test from 'node:test'
import { formatPorts, parseList, secondsLeft, toRFC3339 } from '../src/lib/firewallV2.ts'

test('parseList splits on commas and whitespace and drops empties', () => {
  assert.deepEqual(parseList(' 203.0.113.0/24, 198.51.100.7\n2001:db8::/32 ,,'), ['203.0.113.0/24', '198.51.100.7', '2001:db8::/32'])
  assert.deepEqual(parseList(''), [])
  assert.deepEqual(parseList('   '), [])
})

test('secondsLeft counts down to the deadline and never goes negative', () => {
  const now = new Date('2026-10-14T12:00:00Z')
  assert.equal(secondsLeft('2026-10-14T12:00:45Z', now), 45)
  assert.equal(secondsLeft('2026-10-14T12:00:45.400Z', now), 46) // rounds up: never shows 0 while still pending
  assert.equal(secondsLeft('2026-10-14T11:59:00Z', now), 0)
  assert.equal(secondsLeft('not a date', now), 0)
})

test('formatPorts shows a single port or a range', () => {
  assert.equal(formatPorts(443, 443), '443')
  assert.equal(formatPorts(8000, 8100), '8000-8100')
})

test('toRFC3339 turns a datetime-local value into UTC, empty stays undefined', () => {
  assert.equal(toRFC3339(''), undefined)
  const v = toRFC3339('2026-10-20T10:30')
  assert.match(v, /^2026-10-2\dT\d\d:30:00\.000Z$/) // local time zone of the test runner
})
