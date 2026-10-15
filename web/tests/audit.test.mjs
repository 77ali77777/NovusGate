import assert from 'node:assert/strict'
import { test } from 'node:test'
import { nextBefore, parseAction } from '../src/lib/audit.ts'

test('parseAction splits method and route; old entries keep their name', () => {
  assert.deepEqual(parseAction('DELETE /api/v1/nodes/{id}'), { method: 'DELETE', target: '/nodes/{id}' })
  assert.deepEqual(parseAction('POST /api/v1/auth/login'), { method: 'POST', target: '/auth/login' })
  assert.deepEqual(parseAction('vpn_rule_created'), { method: '', target: 'vpn_rule_created' })
})

test('nextBefore pages from the oldest shown entry (time and id); none when the page was short', () => {
  const page = [
    { id: 'a', created_at: '2026-10-15T10:00:00Z' },
    { id: 'b', created_at: '2026-10-15T09:00:00Z' },
  ]
  assert.deepEqual(nextBefore(page, 2), { before: '2026-10-15T09:00:00Z', beforeId: 'b' })
  assert.equal(nextBefore(page, 100), undefined)
  assert.equal(nextBefore([], 100), undefined)
})
