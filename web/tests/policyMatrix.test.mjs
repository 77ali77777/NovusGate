import assert from 'node:assert/strict'
import { test } from 'node:test'
import { pairRulePriority } from '../src/lib/policyMatrix.ts'

test('a rule made from the matrix runs before every existing rule', () => {
  assert.equal(pairRulePriority([]), 100)
  assert.equal(pairRulePriority([100, 200]), 99)
  assert.equal(pairRulePriority([50, 10, 300]), 9)
  assert.equal(pairRulePriority([1]), 1)
})
