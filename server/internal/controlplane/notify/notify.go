// Package notify sends Telegram notifications (P8): nodes going offline or
// expiring, Fail2Ban bans, firewall changes and traffic quotas.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// Kind is an event type; each one has its own switch in the settings.
type Kind string

const (
	NodeOffline    Kind = "node_offline"
	NodeExpired    Kind = "node_expired"
	Fail2BanBan    Kind = "fail2ban_ban"
	FirewallChange Kind = "firewall_change"
	// QuotaExceeded: a node used 80% or all of its traffic quota (P9c).
	QuotaExceeded Kind = "quota_exceeded"
)

// Event is one notification. Events with the same Kind and Key within
// Notifier.Repeat are sent once.
type Event struct {
	Kind Kind
	Key  string
	Text string
}

// Sender delivers a message to a chat.
type Sender interface {
	Send(ctx context.Context, token, chatID, text string) error
}

// Telegram sends through the Bot API.
type Telegram struct {
	BaseURL string // https://api.telegram.org
	Client  *http.Client
}

// Send posts text to chatID. Errors carry Telegram's description but never
// the token (it is part of the URL, which net/http errors would include).
func (t *Telegram) Send(ctx context.Context, token, chatID, text string) error {
	body, _ := json.Marshal(map[string]any{"chat_id": chatID, "text": text, "disable_web_page_preview": true})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.BaseURL+"/bot"+token+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return errors.New("telegram: invalid request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.Client.Do(req)
	if err != nil {
		var ue interface{ Unwrap() error }
		if errors.As(err, &ue) && ue.Unwrap() != nil {
			return fmt.Errorf("telegram unreachable: %v", ue.Unwrap())
		}
		return errors.New("telegram unreachable")
	}
	defer resp.Body.Close()
	var out struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode != http.StatusOK || !out.OK {
		if out.Description == "" {
			out.Description = resp.Status
		}
		return fmt.Errorf("telegram: %s", out.Description)
	}
	return nil
}

// Notifier filters events by the current settings, drops repeats and sends
// them. Notify queues an event and never blocks; Run delivers the queue.
type Notifier struct {
	Settings func(ctx context.Context) (models.NotificationSettings, string, error)
	Sender   Sender
	Now      func() time.Time
	Repeat   time.Duration

	once  sync.Once
	queue chan Event
	mu    sync.Mutex
	last  map[string]time.Time
}

func (n *Notifier) init() {
	n.once.Do(func() {
		n.queue = make(chan Event, 256)
		n.last = map[string]time.Time{}
	})
}

// Notify queues an event; when the queue is full the event is dropped.
func (n *Notifier) Notify(e Event) {
	if n == nil {
		return
	}
	n.init()
	select {
	case n.queue <- e:
	default:
		slog.Warn("notification queue full; event dropped", "kind", e.Kind)
	}
}

// Run delivers queued events until ctx ends.
func (n *Notifier) Run(ctx context.Context) {
	n.init()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-n.queue:
			n.Deliver(ctx, e)
		}
	}
}

// Deliver sends one event now if the settings allow it.
func (n *Notifier) Deliver(ctx context.Context, e Event) {
	n.init()
	s, token, err := n.Settings(ctx)
	if err != nil {
		slog.Warn("notification settings not read", "error", err)
		return
	}
	if !s.Enabled || s.ChatID == "" || token == "" || !wanted(s, e.Kind) {
		return
	}
	key := string(e.Kind) + "|" + e.Key
	now := n.Now()
	n.mu.Lock()
	if prev, ok := n.last[key]; ok && now.Sub(prev) < n.Repeat {
		n.mu.Unlock()
		return
	}
	n.last[key] = now
	n.mu.Unlock()
	sendCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := n.Sender.Send(sendCtx, token, s.ChatID, e.Text); err != nil {
		slog.Warn("notification not sent", "kind", e.Kind, "error", err)
	}
}

func wanted(s models.NotificationSettings, k Kind) bool {
	switch k {
	case NodeOffline:
		return s.NodeOffline
	case NodeExpired:
		return s.NodeExpired
	case Fail2BanBan:
		return s.Fail2BanBan
	case FirewallChange:
		return s.FirewallChange
	case QuotaExceeded:
		return s.QuotaExceeded
	}
	return false
}
