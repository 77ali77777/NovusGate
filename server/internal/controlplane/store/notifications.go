package store

import (
	"context"
	"database/sql"

	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/shared/secretbox"
)

// notificationTokenContext binds the sealed bot token to its column, so a
// node key copied here does not open as a token.
const notificationTokenContext = "notification_settings.bot_token"

// NotificationSettings returns the Telegram settings and the bot token. With
// no row yet it returns the defaults: disabled, every event on, no token.
func (s *Store) NotificationSettings(ctx context.Context) (models.NotificationSettings, string, error) {
	out := models.NotificationSettings{NodeOffline: true, NodeExpired: true, Fail2BanBan: true, FirewallChange: true}
	var sealed sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT enabled, chat_id, bot_token_enc, node_offline, node_expired, fail2ban_ban, firewall_change
		FROM notification_settings WHERE id = 1`).Scan(
		&out.Enabled, &out.ChatID, &sealed, &out.NodeOffline, &out.NodeExpired, &out.Fail2BanBan, &out.FirewallChange)
	if err == sql.ErrNoRows {
		return out, "", nil
	}
	if err != nil {
		return out, "", err
	}
	if !sealed.Valid || sealed.String == "" {
		return out, "", nil
	}
	token, err := secretbox.Open(s.box, sealed.String, notificationTokenContext)
	if err != nil {
		return out, "", err
	}
	out.TokenSet = true
	return out, token, nil
}

// SaveNotificationSettings stores the settings. A nil token keeps the stored
// one; otherwise it is sealed and replaces it.
func (s *Store) SaveNotificationSettings(ctx context.Context, in models.NotificationSettings, token *string) error {
	var sealed sql.NullString
	if token != nil {
		v, err := secretbox.Seal(s.box, *token, notificationTokenContext)
		if err != nil {
			return err
		}
		sealed = sql.NullString{String: v, Valid: true}
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO notification_settings
			(id, enabled, chat_id, bot_token_enc, node_offline, node_expired, fail2ban_ban, firewall_change, updated_at)
		VALUES (1, $1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (id) DO UPDATE SET
			enabled = EXCLUDED.enabled, chat_id = EXCLUDED.chat_id,
			bot_token_enc = CASE WHEN $8 THEN EXCLUDED.bot_token_enc ELSE notification_settings.bot_token_enc END,
			node_offline = EXCLUDED.node_offline, node_expired = EXCLUDED.node_expired,
			fail2ban_ban = EXCLUDED.fail2ban_ban, firewall_change = EXCLUDED.firewall_change,
			updated_at = NOW()`,
		in.Enabled, in.ChatID, sealed, in.NodeOffline, in.NodeExpired, in.Fail2BanBan, in.FirewallChange, token != nil)
	return err
}
