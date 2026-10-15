// Telegram notification form (P8): what the panel sends to
// PUT /api/v1/notifications/settings.

export interface NotificationEvents {
  node_offline: boolean
  node_expired: boolean
  fail2ban_ban: boolean
  firewall_change: boolean
}

export interface NotificationForm extends NotificationEvents {
  enabled: boolean
  chat_id: string
  bot_token: string
}

export interface NotificationSettingsRequest extends NotificationEvents {
  enabled: boolean
  chat_id: string
  bot_token?: string
}

export interface NotificationUpdate {
  request: NotificationSettingsRequest
  // error is a key in the "settings" locale namespace; the caller translates it.
  error?: string
}

// notificationUpdate trims the form and leaves an empty token out, so the
// server keeps the stored one. Enabling needs a chat and a token. Kept free
// of imports so it runs under `node --experimental-strip-types` in web/tests.
export function notificationUpdate(
  form: NotificationForm,
  tokenStored: boolean
): NotificationUpdate {
  const chatId = form.chat_id.trim()
  const token = form.bot_token.trim()
  const request: NotificationSettingsRequest = {
    enabled: form.enabled,
    chat_id: chatId,
    node_offline: form.node_offline,
    node_expired: form.node_expired,
    fail2ban_ban: form.fail2ban_ban,
    firewall_change: form.firewall_change,
  }
  if (token !== '') request.bot_token = token
  if (form.enabled && chatId === '')
    return { request, error: 'notifications.errors.chatIdRequired' }
  if (form.enabled && token === '' && !tokenStored) {
    return { request, error: 'notifications.errors.botTokenRequired' }
  }
  return { request }
}
