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

// The cell shows a short reason under the verdict (a hover title is invisible
// on touch screens); every reason_key has one in both languages.
const az = JSON.parse(readFileSync('src/i18n/locales/az/firewall.json', 'utf8'))
const tFor = (tree) => (key, vars = {}) => {
  const [, path] = key.split(':')
  const s = path.split('.').reduce((o, k) => o?.[k], tree)
  return String(s ?? key).replace(/\{\{(\w+)\}\}/g, (_, v) => vars[v])
}

test('every reason key has a short visible text in en and az', async () => {
  const { matrixShortReason } = await import('../src/lib/matrixReason.ts')
  for (const [lang, tree] of [['en', en], ['az', az]]) {
    const tt = tFor(tree)
    for (const reason_key of ['same_network', 'isolated', 'iptables_default']) {
      const s = matrixShortReason(tt, { verdict: 'deny', reason_key, reason: 'server text' })
      assert.ok(s && !s.includes('matrix.short'), `${lang} ${reason_key}: ${s}`)
      assert.ok(s.length <= 24, `${lang} ${reason_key} is short: ${s}`)
    }
  }
  const tt = tFor(en)
  assert.equal(matrixShortReason(tt, { verdict: 'allow', reason_key: 'same_network', reason: 'x' }), 'same network')
  assert.equal(matrixShortReason(tt, { verdict: 'deny', reason_key: 'isolated', reason: 'x' }), 'isolated')
  assert.equal(matrixShortReason(tt, { verdict: 'allow', reason_key: 'iptables_default', reason: 'x' }), 'iptables default')
})

test('a rule reason shows the rule name, clipped when long', async () => {
  const { matrixShortReason } = await import('../src/lib/matrixReason.ts')
  const tt = tFor(en)
  assert.equal(matrixShortReason(tt, { verdict: 'allow', reason_key: 'rule', rule: 'office to db', reason: 'x' }), 'office to db')
  const long = 'a very long rule name that does not fit a cell'
  const s = matrixShortReason(tt, { verdict: 'allow', reason_key: 'rule', rule: long, reason: 'x' })
  assert.equal(s.length, 24)
  assert.ok(s.endsWith('…'))
  // A rule key without a rule name says "rule".
  assert.equal(matrixShortReason(tt, { verdict: 'deny', reason_key: 'rule', reason: 'x' }), 'rule')
})

test('an unknown key shows the server text, clipped', async () => {
  const { matrixShortReason } = await import('../src/lib/matrixReason.ts')
  const tt = tFor(en)
  assert.equal(matrixShortReason(tt, { verdict: 'allow', reason_key: 'new_kind', reason: 'short' }), 'short')
  assert.equal(matrixShortReason(tt, { verdict: 'allow', reason: 'x'.repeat(40) }).length, 24)
})
