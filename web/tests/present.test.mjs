import assert from 'node:assert/strict'
import { test } from 'node:test'
import { present } from '../src/lib/present.ts'

// Go encodes nil slices as null and the generated types allow null items.
test('present drops a missing list and null items', () => {
  assert.deepEqual(present(null), [])
  assert.deepEqual(present(undefined), [])
  assert.deepEqual(present([1, null, 2, undefined]), [1, 2])
  assert.deepEqual(present([0, '']), [0, ''])
})
