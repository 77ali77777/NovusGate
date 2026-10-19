import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { accessHeadline } from '../src/lib/accessCheck.ts'
import { matrixReason } from '../src/lib/matrixReason.ts'

// VLAN plan M3: "who can reach whom" in one line, then each direction.

test('accessHeadline reads both directions as one answer', () => {
  assert.equal(accessHeadline('allow', 'allow'), 'both')
  assert.equal(accessHeadline('allow', 'deny'), 'fromOnly')
  assert.equal(accessHeadline('deny', 'allow'), 'toOnly')
  assert.equal(accessHeadline('deny', 'deny'), 'none')
  assert.equal(accessHeadline('partial', 'deny'), 'partial')
  assert.equal(accessHeadline('allow', 'partial'), 'partial')
})

const en = JSON.parse(readFileSync('src/i18n/locales/en/firewall.json', 'utf8'))
const t = (key, vars = {}) => {
  const [, path] = key.split(':')
  const s = path.split('.').reduce((o, k) => o?.[k], en)
  return String(s ?? key).replace(/\{\{(\w+)\}\}/g, (_, v) => vars[v])
}

test('the check reasons mixed and empty are translated', () => {
  assert.equal(
    matrixReason(t, { verdict: 'partial', reason_key: 'mixed', reason: 'x' }),
    'the devices on this side get different answers'
  )
  assert.equal(matrixReason(t, { verdict: 'deny', reason_key: 'empty', reason: 'x' }), 'the group has no devices')
})

test('every headline has a sentence in both languages', () => {
  const az = JSON.parse(readFileSync('src/i18n/locales/az/firewall.json', 'utf8'))
  for (const tree of [en, az]) {
    for (const k of ['both', 'fromOnly', 'toOnly', 'none', 'partial']) {
      assert.ok(tree.accessCheck?.headline?.[k], `accessCheck.headline.${k}`)
    }
  }
})
