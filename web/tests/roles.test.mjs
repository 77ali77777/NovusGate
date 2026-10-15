import assert from 'node:assert/strict'
import { test } from 'node:test'
import { roleAtLeast } from '../src/lib/roles.ts'

test('roleAtLeast follows viewer < operator < admin', () => {
  assert.equal(roleAtLeast('admin', 'operator'), true)
  assert.equal(roleAtLeast('operator', 'operator'), true)
  assert.equal(roleAtLeast('operator', 'admin'), false)
  assert.equal(roleAtLeast('viewer', 'operator'), false)
  assert.equal(roleAtLeast('viewer', 'viewer'), true)
})

test('an unknown or missing role can do nothing', () => {
  assert.equal(roleAtLeast(undefined, 'viewer'), false)
  assert.equal(roleAtLeast('root', 'viewer'), false)
})
