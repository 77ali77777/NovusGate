import assert from 'node:assert/strict'
import { test } from 'node:test'
import { formatBytes, gbToMb, mbToGb, quotaFor } from '../src/lib/quota.ts'

const limits = {
  profiles: [
    { id: 'p', quota_mb: 50000, quota_action: 'block' },
    { id: 'free', quota_mb: null, quota_action: 'block' },
  ],
  node_limits: [
    { node_id: 'n1', profile_id: 'p' },
    { node_id: 'n2', profile_id: 'free' },
    { node_id: 'n3', profile_id: 'p' },
  ],
  quota_states: [{ node_id: 'n1', used_bytes: 32e9, exceeded_at: null }],
}

test('quotaFor gives the used share of the node profile quota', () => {
  assert.deepEqual(quotaFor('n1', limits), {
    usedBytes: 32e9,
    quotaBytes: 50e9,
    percent: 64,
    exceeded: false,
    action: 'block',
  })
  // counted yet: nothing used
  assert.equal(quotaFor('n3', limits)?.usedBytes, 0)
  assert.equal(quotaFor('n2', limits), null) // profile without a quota
  assert.equal(quotaFor('n9', limits), null) // no profile
  assert.equal(quotaFor('n1', undefined), null)
})

test('quotaFor caps the bar at 100% and reports exceeded', () => {
  const over = { ...limits, quota_states: [{ node_id: 'n1', used_bytes: 60e9, exceeded_at: '2026-10-15T00:00:00Z' }] }
  const q = quotaFor('n1', over)
  assert.equal(q?.percent, 100)
  assert.equal(q?.exceeded, true)
})

test('gbToMb reads the GB field; mbToGb fills it back', () => {
  assert.equal(gbToMb(''), null)
  assert.equal(gbToMb('50'), 50000)
  assert.equal(gbToMb('0,5'), 500)
  assert.equal(gbToMb('0'), 'invalid')
  assert.equal(gbToMb('x'), 'invalid')
  assert.equal(gbToMb('1000001'), 'invalid') // above 1 PB
  assert.equal(mbToGb(null), '')
  assert.equal(mbToGb(50000), '50')
  assert.equal(mbToGb(1500), '1.5')
})

test('formatBytes picks GB or MB', () => {
  assert.equal(formatBytes(32e9), '32.0 GB')
  assert.equal(formatBytes(512e6), '512 MB')
  assert.equal(formatBytes(0), '0 MB')
})
