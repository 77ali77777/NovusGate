package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/controlplane/notify"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// SetNotifier enables Telegram notifications (P8). sender sends the test
// message directly, so its error reaches the panel.
func (s *Server) SetNotifier(n *notify.Notifier, sender notify.Sender) {
	s.notifier, s.notifySender = n, sender
}

// NotificationSettingsRequest updates the Telegram settings. An empty or
// missing bot_token keeps the stored token.
type NotificationSettingsRequest struct {
	Enabled        bool   `json:"enabled"`
	ChatID         string `json:"chat_id"`
	BotToken       string `json:"bot_token,omitempty"`
	NodeOffline    bool   `json:"node_offline"`
	NodeExpired    bool   `json:"node_expired"`
	Fail2BanBan    bool   `json:"fail2ban_ban"`
	FirewallChange bool   `json:"firewall_change"`
}

var (
	// A numeric chat/group ID or a public @channel name.
	chatIDRe = regexp.MustCompile(`^(-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$`)
	// BotFather tokens: <bot id>:<35-character secret>.
	botTokenRe = regexp.MustCompile(`^\d{3,15}:[A-Za-z0-9_-]{30,64}$`)
)

func (s *Server) registerNotificationRoutes(api *mux.Router) {
	api.HandleFunc("/notifications/settings", s.handleGetNotificationSettings).Methods("GET")
	api.HandleFunc("/notifications/settings", s.handleUpdateNotificationSettings).Methods("PUT")
	api.HandleFunc("/notifications/test", s.handleTestNotification).Methods("POST")
}

func (s *Server) handleGetNotificationSettings(w http.ResponseWriter, r *http.Request) {
	settings, _, err := s.store.NotificationSettings(r.Context())
	if err != nil {
		slog.Error("notification settings not read", "error", err)
		errorResponse(w, http.StatusInternalServerError, "failed to read the notification settings")
		return
	}
	jsonResponse(w, http.StatusOK, settings)
}

func (s *Server) handleUpdateNotificationSettings(w http.ResponseWriter, r *http.Request) {
	var req NotificationSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorWithCode(w, http.StatusBadRequest, "invalid_request_body", "invalid request body")
		return
	}
	req.ChatID = strings.TrimSpace(req.ChatID)
	req.BotToken = strings.TrimSpace(req.BotToken)
	if req.ChatID != "" && !chatIDRe.MatchString(req.ChatID) {
		errorWithCode(w, http.StatusBadRequest, "invalid_chat_id", "chat_id must be a numeric chat ID or an @channel name")
		return
	}
	if req.BotToken != "" && !botTokenRe.MatchString(req.BotToken) {
		errorWithCode(w, http.StatusBadRequest, "invalid_bot_token", "bot_token does not look like a BotFather token (123456:ABC...)")
		return
	}
	current, storedToken, err := s.store.NotificationSettings(r.Context())
	if err != nil {
		slog.Error("notification settings not read", "error", err)
		errorResponse(w, http.StatusInternalServerError, "failed to read the notification settings")
		return
	}
	if req.Enabled && (req.ChatID == "" || (req.BotToken == "" && storedToken == "")) {
		errorWithCode(w, http.StatusBadRequest, "notifications_incomplete", "enabling notifications needs a chat_id and a bot token")
		return
	}
	in := models.NotificationSettings{Enabled: req.Enabled, ChatID: req.ChatID, NodeOffline: req.NodeOffline,
		NodeExpired: req.NodeExpired, Fail2BanBan: req.Fail2BanBan, FirewallChange: req.FirewallChange}
	var token *string
	if req.BotToken != "" {
		token = &req.BotToken
	}
	if err := s.store.SaveNotificationSettings(r.Context(), in, token); err != nil {
		slog.Error("notification settings not saved", "error", err)
		errorResponse(w, http.StatusInternalServerError, "failed to save the notification settings")
		return
	}
	in.TokenSet = token != nil || current.TokenSet
	slog.Info("notification settings changed", "enabled", in.Enabled, "token_changed", token != nil, "user", sessionUserID(r))
	jsonResponse(w, http.StatusOK, in)
}

func (s *Server) handleTestNotification(w http.ResponseWriter, r *http.Request) {
	if s.notifySender == nil {
		errorWithCode(w, http.StatusServiceUnavailable, "notifications_disabled", "notifications are not configured on this server")
		return
	}
	settings, token, err := s.store.NotificationSettings(r.Context())
	if err != nil {
		slog.Error("notification settings not read", "error", err)
		errorResponse(w, http.StatusInternalServerError, "failed to read the notification settings")
		return
	}
	if settings.ChatID == "" || token == "" {
		errorWithCode(w, http.StatusBadRequest, "notifications_incomplete", "save a chat_id and a bot token first")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := s.notifySender.Send(ctx, token, settings.ChatID, "✅ NovusGate: test message. Notifications reach this chat."); err != nil {
		// The error carries Telegram's description, never the token.
		errorWithCode(w, http.StatusBadGateway, "telegram_failed", err.Error())
		return
	}
	jsonResponse(w, http.StatusOK, StatusMessageResponse{Status: "sent", Message: "test message sent"})
}

// firewallChangeMiddleware reports successful firewall changes (any
// non-GET request under /api/v1/firewall/ that answers 2xx).
func (s *Server) firewallChangeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.notifier == nil || r.Method == http.MethodGet || r.Method == http.MethodHead ||
			!strings.HasPrefix(r.URL.Path, "/api/v1/firewall/") {
			next.ServeHTTP(w, r)
			return
		}
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		if rec.status < 200 || rec.status > 299 {
			return
		}
		who := "API key"
		if user, _ := sessionFrom(r); user != nil {
			who = user.Username
		}
		// Every change is news: the key is unique, so none is deduplicated.
		s.notifier.Notify(notify.Event{Kind: notify.FirewallChange, Key: strconv.FormatInt(time.Now().UnixNano(), 10),
			Text: fmt.Sprintf("🛡️ NovusGate: firewall changed by %s — %s %s", who, r.Method, r.URL.Path)})
	})
}
