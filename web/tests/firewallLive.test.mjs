import assert from 'node:assert/strict'
import { test } from 'node:test'
import { formatAgo, formatBytes, usagePercent } from '../src/lib/firewallV2.ts'

test('formatAgo says how long ago a source was dropped', () => {
  assert.equal(formatAgo(0), 'just now')
  assert.equal(formatAgo(42), '42 s ago')
  assert.equal(formatAgo(125), '2 min ago')
  assert.equal(formatAgo(3599), '59 min ago')
})

test('formatBytes uses binary units', () => {
  assert.equal(formatBytes(0), '0 B')
  assert.equal(formatBytes(1023), '1023 B')
  assert.equal(formatBytes(1536), '1.5 KB')
  assert.equal(formatBytes(5 * 1024 * 1024), '5.0 MB')
  assert.equal(formatBytes(3 * 1024 ** 3), '3.0 GB')
})

test('usagePercent is whole percent and safe without a limit', () => {
  assert.equal(usagePercent(3, 65536), 0)
  assert.equal(usagePercent(32768, 65536), 50)
  assert.equal(usagePercent(10, 0), 0)
  assert.equal(usagePercent(70000, 65536), 100)
})
