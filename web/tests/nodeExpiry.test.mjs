// Run: node --experimental-strip-types --test web/tests/
import assert from 'node:assert/strict'
import test from 'node:test'
import { computeExpiry, initialExpiryChoice } from '../src/lib/nodeExpiry.ts'

const now = new Date('2026-10-14T12:00:00Z')
const past = '2026-10-01T12:00:00Z'
const future = '2026-12-31T18:00:00Z'

// B13: a node whose expiry is already set must open on "keep", so saving a
// name or status change never trips the date field's validation.
test('an existing expiry opens as keep', () => {
  assert.equal(initialExpiryChoice(past), 'keep')
  assert.equal(initialExpiryChoice(future), 'keep')
  assert.equal(initialExpiryChoice(null), 'keep')
})

test('keep sends no expiry change, even when the expiry is in the past', () => {
  assert.deepEqual(computeExpiry({ choice: 'keep', current: past, now }), { ok: true, expiresAt: undefined })
})

test('forever removes the limit', () => {
  assert.deepEqual(computeExpiry({ choice: 'forever', current: future, now }), { ok: true, expiresAt: null })
})

test('extensions start from the later of now and the current expiry', () => {
  assert.equal(computeExpiry({ choice: '1h', current: past, now }).expiresAt, '2026-10-14T13:00:00.000Z')
  assert.equal(computeExpiry({ choice: '1d', current: future, now }).expiresAt, '2027-01-01T18:00:00.000Z')
  assert.equal(computeExpiry({ choice: '1w', current: null, now }).expiresAt, '2026-10-21T12:00:00.000Z')
})

test('a custom date must be in the future', () => {
  const r = computeExpiry({ choice: 'custom', current: null, customDate: '2026-10-13T10:00:00Z', now })
  assert.equal(r.ok, false)
  assert.equal(r.error, 'nodes:edit.errors.mustBeFuture')
})

test('a custom date may not shorten a future expiry', () => {
  const r = computeExpiry({ choice: 'custom', current: future, customDate: '2026-11-01T10:00:00Z', now })
  assert.equal(r.ok, false)
  assert.equal(r.error, 'nodes:edit.errors.onlyExtend')
})

test('a custom date after an expired limit is accepted', () => {
  const r = computeExpiry({ choice: 'custom', current: past, customDate: '2026-10-20T10:00:00Z', now })
  assert.deepEqual(r, { ok: true, expiresAt: '2026-10-20T10:00:00.000Z' })
})

test('custom without a date is an error, not a silent no-op', () => {
  const r = computeExpiry({ choice: 'custom', current: null, customDate: '', now })
  assert.equal(r.ok, false)
  assert.equal(r.error, 'nodes:edit.errors.dateRequired')
})

test('an unparsable custom date is an error', () => {
  const r = computeExpiry({ choice: 'custom', current: null, customDate: 'not a date', now })
  assert.deepEqual(r, { ok: false, error: 'nodes:edit.errors.dateInvalid' })
})
