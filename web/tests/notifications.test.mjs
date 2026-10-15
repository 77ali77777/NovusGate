import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
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

// The error is a key of the "settings" namespace; it must exist in every language.
const locale = (lang) =>
  JSON.parse(readFileSync(new URL(`../src/i18n/locales/${lang}/settings.json`, import.meta.url), 'utf8'))
const lookup = (tree, key) => key.split('.').reduce((o, k) => o?.[k], tree)

test('enabling needs a chat and a token (new or stored)', () => {
  const noChat = notificationUpdate({ ...base, chat_id: ' ' }, true).error
  const noToken = notificationUpdate(base, false).error
  assert.equal(noChat, 'notifications.errors.chatIdRequired')
  assert.equal(noToken, 'notifications.errors.botTokenRequired')
  for (const lang of ['en', 'az']) {
    assert.equal(typeof lookup(locale(lang), noChat), 'string', `${lang}: ${noChat}`)
    assert.equal(typeof lookup(locale(lang), noToken), 'string', `${lang}: ${noToken}`)
  }
  assert.match(lookup(locale('en'), noChat), /chat/i)
  assert.match(lookup(locale('en'), noToken), /token/i)
  assert.equal(notificationUpdate({ ...base, enabled: false }, false).error, undefined)
})

test('the quota switch (P9c) is sent', () => {
  const { request } = notificationUpdate({ ...base, quota_exceeded: false }, true)
  assert.equal(request.quota_exceeded, false)
  assert.equal(notificationUpdate({ ...base, quota_exceeded: true }, true).request.quota_exceeded, true)
})
