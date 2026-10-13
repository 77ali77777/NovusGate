package rest

import (
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
)

// peerTransition decides what an edit does to the node's WireGuard peer: add
// it when the node becomes active, remove it when it stops being active.
// "Active" is computed from status and expires_at, not from the stored
// status alone: lazy expiry never stored "expired" (B11).
func peerTransition(before, after *models.Node, now time.Time) (add, remove bool) {
	was, is := before.Active(now), after.Active(now)
	return !was && is, was && !is
}
