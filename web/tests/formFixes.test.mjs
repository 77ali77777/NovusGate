import assert from 'node:assert/strict'
import { test } from 'node:test'
import { jailSaveResult } from '../src/lib/fail2ban.ts'
import { withProtocol } from '../src/lib/vpnRule.ts'

// Help-text review 2026-10-15: two form bugs the tips would have papered over.

// Fail2Ban refuses a bad value with 206 {status:"partial", errors}; the
// panel showed "Settings saved" anyway.
test('jailSaveResult reports a partial save with the refused fields', () => {
  assert.deepEqual(jailSaveResult({ status: 'success', updated: ['bantime'] }), { ok: true, errors: [] })
  assert.deepEqual(jailSaveResult({ status: 'partial', updated: ['bantime'], errors: ['maxretry: bad'] }), {
    ok: false,
    errors: ['maxretry: bad'],
  })
  assert.deepEqual(jailSaveResult({ status: 'partial', errors: null }), { ok: false, errors: [] })
})

// Switching to All or ICMP disabled the port field but kept its value, and
// the server refused the rule ("port can only be specified for tcp or udp").
test('withProtocol clears the port for protocols without ports', () => {
  const form = { name: 'x', protocol: 'tcp', port: '443' }
  assert.deepEqual(withProtocol(form, 'udp'), { name: 'x', protocol: 'udp', port: '443' })
  assert.deepEqual(withProtocol(form, 'all'), { name: 'x', protocol: 'all', port: '' })
  assert.deepEqual(withProtocol(form, 'icmp'), { name: 'x', protocol: 'icmp', port: '' })
})
