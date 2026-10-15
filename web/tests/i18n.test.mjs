import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { test } from 'node:test'
import { flatKeys, LOCALES, listFiles, loadLocale, scanHardcoded, scanKeys } from './i18nScan.mjs'

const en = loadLocale('en')
const az = loadLocale('az')

test('every namespace exists in English and Azerbaijani with the same keys', () => {
  assert.deepEqual(Object.keys(az).sort(), Object.keys(en).sort())
  for (const ns of Object.keys(en)) {
    assert.deepEqual(flatKeys(az[ns]).sort(), flatKeys(en[ns]).sort(), `namespace ${ns}`)
  }
})

test('no translation is empty', () => {
  for (const [lang, tree] of [
    ['en', en],
    ['az', az],
  ]) {
    for (const [ns, data] of Object.entries(tree)) {
      for (const key of flatKeys(data)) {
        const v = key.split('.').reduce((o, k) => o[k], data)
        assert.ok(typeof v === 'string' && v.trim() !== '', `${lang}/${ns}.json: ${key} is empty`)
      }
    }
  }
})

test('the Azerbaijani texts use Azerbaijani letters, not ASCII stand-ins', () => {
  // A few words that are always written with diacritics.
  const wrong = /\b(Sebeke|sebeke|Parametrler|Yuklenir|Legv|Tesdiq|Istifadeci|Xeta)\b/
  for (const f of listFiles(join(LOCALES, 'az'), '.json')) {
    assert.doesNotMatch(readFileSync(f, 'utf8'), wrong, f)
  }
})

test('every t() key exists in the English locale', () => {
  const missing = listFiles('src', '.tsx').flatMap((f) => scanKeys(f, en))
  assert.deepEqual(missing.map((m) => `${m.file}:${m.line} ${m.key}`), [])
})

// Keys passed around as strings (toast titles in mutation meta, labels kept in
// data) must exist too: every 'namespace:key' literal of a known namespace.
test('every namespaced key literal exists in the English locale', () => {
  const missing = []
  const has = (ns, key) =>
    ['', '_one', '_other'].some((s) => typeof (key + s).split('.').reduce((o, k) => o?.[k], en[ns]) === 'string')
  for (const f of [...listFiles('src', '.ts'), ...listFiles('src', '.tsx')]) {
    if (f.endsWith('.d.ts')) continue
    const src = readFileSync(f, 'utf8')
    for (const m of src.matchAll(/['"`]([a-z0-9]+):([A-Za-z][A-Za-z0-9_.]*)['"`]/g)) {
      if (en[m[1]] && !has(m[1], m[2])) missing.push(`${f}: ${m[1]}:${m[2]}`)
    }
  }
  assert.deepEqual(missing, [])
})

test('no hard-coded UI text is left in the components', () => {
  const found = listFiles('src', '.tsx').flatMap((f) => scanHardcoded(f))
  assert.deepEqual(found.map((h) => `${h.file}:${h.line} [${h.kind}] ${h.text}`), [])
})
