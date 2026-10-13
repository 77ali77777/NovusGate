package rest

import "github.com/novusgate/novusgate/internal/controlplane/reconciler"

// SetReconciler attaches the WireGuard reconciler (nil when WG_RECONCILER=off).
func (s *Server) SetReconciler(r *reconciler.Reconciler) { s.reconciler = r }

// triggerReconcile asks the reconciler for a run after a write that changes
// peers; without a reconciler it does nothing.
func (s *Server) triggerReconcile() {
	if s.reconciler != nil {
		s.reconciler.Trigger()
	}
}
