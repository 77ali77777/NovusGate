import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { formatAgo, formatBytes, usagePercent } from '../src/lib/firewallV2.ts'

// english resolves a formatAgo result the way i18next does for the English
// locale: key_one / key_other by plural rule, then {{count}}.
const en = JSON.parse(readFileSync(new URL('../src/i18n/locales/en/firewallv2.json', import.meta.url), 'utf8'))
const plural = new Intl.PluralRules('en')
function english({ key, count }) {
  const [group, name] = key.split('.')
  const texts = en[group]
  const text = texts[name] ?? texts[`${name}_${plural.select(count)}`]
  return text.replaceAll('{{count}}', String(count))
}

test('formatAgo says how long ago a source was dropped', () => {
  assert.deepEqual(formatAgo(0), { key: 'ago.justNow', count: 0 })
  assert.deepEqual(formatAgo(42), { key: 'ago.seconds', count: 42 })
  assert.deepEqual(formatAgo(125), { key: 'ago.minutes', count: 2 })
  assert.deepEqual(formatAgo(3599), { key: 'ago.minutes', count: 59 })
  assert.equal(english(formatAgo(0)), 'just now')
  assert.equal(english(formatAgo(1)), '1 s ago')
  assert.equal(english(formatAgo(42)), '42 s ago')
  assert.equal(english(formatAgo(125)), '2 min ago')
  assert.equal(english(formatAgo(3599)), '59 min ago')
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
