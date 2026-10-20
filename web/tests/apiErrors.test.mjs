import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { apiErrorMessage, setErrorTranslator } from '../src/api/errors.ts'

// The panel shows a translated sentence for a known error code; the
// server's English message stays the fallback for codes without one.

const axiosError = (code, message) => ({ response: { data: { error: { code, message } } } })

test('a known error code is shown in the panel language', () => {
  setErrorTranslator((code) => (code === 'dns_is_hub' ? 'hub ünvanı olmaz' : undefined))
  assert.equal(apiErrorMessage(axiosError('dns_is_hub', '10.10.0.1 is the hub'), 'x'), 'hub ünvanı olmaz')
  assert.equal(apiErrorMessage(axiosError('other_code', 'server text'), 'x'), 'server text')
  setErrorTranslator(undefined)
  assert.equal(apiErrorMessage(axiosError('dns_is_hub', 'server text'), 'x'), 'server text')
})

// Every code the routing work added has a sentence in both languages.
const CODES = [
  'dns_is_hub',
  'cidr_outside_pool',
  'pool_full',
  'invalid_pool',
  'endpoint_inside_pool',
  'invalid_endpoint_host',
  'rotate_own_device',
  'rotate_peer_not_added',
  'cidr_overlap',
  'invalid_cidr',
  'invalid_dns',
]

test('routing error codes are translated in en and az', () => {
  for (const lang of ['en', 'az']) {
    const tree = JSON.parse(readFileSync(`src/i18n/locales/${lang}/apiErrors.json`, 'utf8'))
    for (const code of CODES) {
      assert.ok(typeof tree[code] === 'string' && tree[code].length > 10, `${lang}: ${code}`)
    }
  }
})
