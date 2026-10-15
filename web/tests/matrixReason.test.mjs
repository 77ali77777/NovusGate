import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { matrixReason } from '../src/lib/matrixReason.ts'

// A tiny t() over the real English firewall namespace.
const en = JSON.parse(readFileSync('src/i18n/locales/en/firewall.json', 'utf8'))
const t = (key, vars = {}) => {
  const [, path] = key.split(':')
  const s = path.split('.').reduce((o, k) => o?.[k], en)
  return String(s ?? key).replace(/\{\{(\w+)\}\}/g, (_, v) => vars[v])
}

test('matrix reasons are built from the key and the rule name', () => {
  assert.equal(matrixReason(t, { verdict: 'allow', reason_key: 'rule', rule: 'a to b', reason: 'x' }), 'rule "a to b"')
  assert.equal(matrixReason(t, { verdict: 'deny', reason_key: 'isolated', reason: 'x' }), 'default (networks are isolated)')
  assert.equal(
    matrixReason(t, { verdict: 'partial', reason_key: 'isolated', reason: 'x' }),
    'some traffic differs from default (networks are isolated)'
  )
})

test('an unknown key falls back to the server text', () => {
  assert.equal(matrixReason(t, { verdict: 'allow', reason_key: 'new_kind', reason: 'server text' }), 'server text')
})
