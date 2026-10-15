package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/novusgate/novusgate/internal/shared/models"
)

// HistoryStore keeps the firewall's change history.
type HistoryStore interface {
	// InsertFirewallHistory stores the entries in one transaction.
	InsertFirewallHistory(ctx context.Context, es ...*models.FirewallHistoryEntry) error
	HasFirewallHistory(ctx context.Context) (bool, error)
}

// Actor says who made a change and how; it rides on the request context.
type Actor struct {
	Label  string
	UserID string
}

type actorKey struct{}

// WithActor attaches a to ctx.
func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorKey{}, a)
}

// ActorFrom returns the actor on ctx, or a zero Actor.
func ActorFrom(ctx context.Context) Actor {
	a, _ := ctx.Value(actorKey{}).(Actor)
	return a
}

// copyState copies the slices of st (their elements are not changed by a
// Mutate, which replaces them), so the state before a change survives it.
func copyState(st State) State {
	return State{
		Services:      append([]*models.FirewallService(nil), st.Services...),
		IPRules:       append([]*models.FirewallIPRule(nil), st.IPRules...),
		Forwards:      append([]*models.FirewallForward(nil), st.Forwards...),
		EgressNodeIDs: append([]string(nil), st.EgressNodeIDs...),
	}
}

// historyTimeout bounds a history write: it runs under the engine lock, so a
// hung database must not stop every later firewall change.
var historyTimeout = 10 * time.Second

// record stores after (and, the first time, before as the baseline). A
// failure is logged: the change itself is live and stored already.
func (e *Engine) record(ctx context.Context, actor Actor, before, after State) {
	if e.History == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), historyTimeout)
	defer cancel()
	err := func() error {
		var entries []*models.FirewallHistoryEntry
		has, err := e.History.HasFirewallHistory(ctx)
		if err != nil {
			return err
		}
		if !has {
			base, err := e.historyEntry(Actor{Label: "baseline"}, before)
			if err != nil {
				return err
			}
			// Earlier than the change (timestamps have microsecond precision),
			// so newest-first lists never put the baseline on top.
			base.CreatedAt = base.CreatedAt.Add(-time.Microsecond)
			entries = append(entries, base)
		}
		if actor.Label == "" {
			actor.Label = "change"
		}
		entry, err := e.historyEntry(actor, after)
		if err != nil {
			return err
		}
		return e.History.InsertFirewallHistory(ctx, append(entries, entry)...)
	}()
	if err != nil {
		slog.Warn(fmt.Sprintf("firewall: history not recorded: %v", err))
	}
}

func (e *Engine) historyEntry(a Actor, st State) (*models.FirewallHistoryEntry, error) {
	js, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	return &models.FirewallHistoryEntry{ID: uuid.New().String(), CreatedAt: e.Now(), UserID: a.UserID, Action: a.Label, State: js}, nil
}
