import assert from 'node:assert/strict'
import { test } from 'node:test'
import { notificationUpdate } from '../src/lib/notifications.ts'

const base = {
  enabled: true,
  chat_id: ' -1001234 ',
  bot_token: '',
  node_offline: true,
  node_expired: false,
  fail2ban_ban: true,
  firewall_change: false,
}

test('an empty token is left out so the stored one is kept', () => {
  const { request, error } = notificationUpdate(base, true)
  assert.equal(error, undefined)
  assert.equal(request.chat_id, '-1001234')
  assert.equal('bot_token' in request, false)
  assert.equal(request.node_expired, false)
})

test('a new token is trimmed and sent', () => {
  const { request } = notificationUpdate({ ...base, bot_token: ' 123:abc ' }, false)
  assert.equal(request.bot_token, '123:abc')
})

test('enabling needs a chat and a token (new or stored)', () => {
  assert.match(notificationUpdate({ ...base, chat_id: ' ' }, true).error, /chat/i)
  assert.match(notificationUpdate(base, false).error, /token/i)
  assert.equal(notificationUpdate({ ...base, enabled: false }, false).error, undefined)
})
