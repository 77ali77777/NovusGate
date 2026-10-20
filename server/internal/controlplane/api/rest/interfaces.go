package rest

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/novusgate/novusgate/internal/shared/models"
	"github.com/novusgate/novusgate/internal/wireguard"
)

// Each network's hub interface runs on the host as its systemd unit
// (wg-quick@wgN). The control plane brings it up at start, when a network
// is created and from POST /networks/{id}/restart; a check every
// interfaceCheckEvery brings back one that is missing. The last reason an
// interface did not come up is kept per network and shown with it.

// interfaceCheckEvery is how often KeepInterfaces looks.
const interfaceCheckEvery = 30 * time.Second

// wgBringUp starts (or, with restart, restarts) an interface's unit
// (replaced in tests).
var wgBringUp = func(m *wireguard.Manager, restart bool) error {
	if restart {
		return m.Restart()
	}
	return m.Up()
}

// restoreNetworkPeers puts the network's active nodes back on its interface:
// runtime peers are not in wgN.conf (SaveConfig = false), so an interface
// that (re)starts has none (replaced in tests).
var restoreNetworkPeers = (*Server).restoreNetworkPeers

func (s *Server) restoreNetworkPeers(ctx context.Context, network *models.Network, mgr *wireguard.Manager) {
	nodes, err := s.store.ListNodes(ctx, network.ID)
	if err != nil {
		slog.Warn(fmt.Sprintf("Warning: cannot restore peers for %s: %v", network.InterfaceName, err))
		return
	}
	live, err := mgr.GetPeers()
	if err != nil {
		slog.Warn(fmt.Sprintf("Warning: cannot read peers of %s: %v", network.InterfaceName, err))
		return
	}
	restored, _, errs := restorePeers(mgr, nodes, live, time.Now())
	if restored > 0 || len(errs) > 0 {
		slog.Info(fmt.Sprintf("Restored %d peers on %s (%d errors)", restored, network.InterfaceName, len(errs)))
	}
	for _, e := range errs {
		slog.Warn(fmt.Sprintf("Warning: %s", e))
	}
}

// setInterfaceError keeps (or, with "", clears) why a network's interface
// did not come up.
func (s *Server) setInterfaceError(networkID, reason string) {
	if reason == "" {
		s.ifaceErrs.Delete(networkID)
		return
	}
	s.ifaceErrs.Store(networkID, reason)
}

// withInterfaceStatus fills a network's live interface fields. The reason is
// host detail (unit journal, wg-quick output): viewers get the state only.
func (s *Server) withInterfaceStatus(r *http.Request, n *models.Network) {
	if n == nil {
		return
	}
	n.InterfaceUp = n.InterfaceName != "" && interfaceUp(n.InterfaceName)
	n.InterfaceError = ""
	if user, _ := sessionFrom(r); user != nil && roleRank[user.Role] < roleRank["operator"] {
		return
	}
	if v, ok := s.ifaceErrs.Load(n.ID); ok {
		n.InterfaceError = v.(string)
	}
}

// bringUp starts (or restarts) a network's interface and puts its peers
// back. The outcome is kept for the panel; a failure is logged once per
// reason.
func (s *Server) bringUp(ctx context.Context, network *models.Network, restart bool) error {
	mgr := s.getManager(network.ID)
	if mgr == nil {
		err := fmt.Errorf("WireGuard is not available for %s (wireguard-tools missing on the host?)", network.InterfaceName)
		s.noteInterfaceError(network, err)
		return err
	}
	if err := wgBringUp(mgr, restart); err != nil {
		s.noteInterfaceError(network, err)
		return err
	}
	if prev, ok := s.ifaceErrs.Load(network.ID); ok {
		slog.Info(fmt.Sprintf("[WG] %s is up again (was: %v)", network.InterfaceName, prev))
	}
	s.setInterfaceError(network.ID, "")
	restoreNetworkPeers(s, ctx, network, mgr)
	return nil
}

func (s *Server) noteInterfaceError(network *models.Network, err error) {
	if prev, ok := s.ifaceErrs.Load(network.ID); !ok || prev.(string) != err.Error() {
		slog.Error(fmt.Sprintf("[WG] interface %s of network %s is down: %v", network.InterfaceName, network.Name, err))
	}
	s.setInterfaceError(network.ID, err.Error())
}

// lockInterface serialises everything that starts or stops one interface
// (create, delete, restart, start-up, the check), so a check cannot start a
// unit again after a delete stopped it. It returns the unlock.
func (s *Server) lockInterface(name string) func() {
	v, _ := s.ifaceLocks.LoadOrStore(name, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// ifaceNow is the check's clock (replaced in tests).
var ifaceNow = time.Now

// retryState is the check's back-off for one network's interface.
type retryState struct {
	fails int
	next  time.Time
}

// Back-off of the check after failed bring-ups: 1, 2, 4 … minutes, at most
// maxRetryDelay. Every failed wg-quick start may leave its PostUp firewall
// rules behind, so a failing unit is not retried every 30 s.
const maxRetryDelay = 10 * time.Minute

func retryDelay(fails int) time.Duration {
	d := interfaceCheckEvery
	for i := 0; i < fails && d < maxRetryDelay; i++ {
		d *= 2
	}
	if d > maxRetryDelay {
		d = maxRetryDelay
	}
	return d
}

// keepInterfacesOnce brings up every network interface that is missing.
func (s *Server) keepInterfacesOnce(ctx context.Context) {
	networks, err := s.store.ListNetworks(ctx)
	if err != nil {
		slog.Warn(fmt.Sprintf("[WG] interface check: list networks: %v", err))
		return
	}
	for _, n := range networks {
		if n.InterfaceName == "" || interfaceUp(n.InterfaceName) {
			s.ifaceRetry.Delete(n.ID)
			continue
		}
		s.keepInterface(ctx, n.ID)
	}
	// DNS on the hub addresses: binds what came up since the last run.
	s.SyncDNS(ctx)
}

// keepInterface brings one network's interface back, under its lock and
// only while the network still exists, unless its back-off has not passed.
func (s *Server) keepInterface(ctx context.Context, networkID string) {
	n, err := s.store.GetNetwork(ctx, networkID)
	if err != nil || n == nil || n.InterfaceName == "" {
		return
	}
	unlock := s.lockInterface(n.InterfaceName)
	defer unlock()
	if n, err = s.store.GetNetwork(ctx, networkID); err != nil || n == nil || interfaceUp(n.InterfaceName) {
		return // deleted meanwhile, or brought up by someone else
	}
	var st retryState
	if v, ok := s.ifaceRetry.Load(n.ID); ok {
		st = v.(retryState)
		if ifaceNow().Before(st.next) {
			return
		}
	}
	if err := s.bringUp(ctx, n, false); err != nil {
		st.fails++
		st.next = ifaceNow().Add(retryDelay(st.fails))
		s.ifaceRetry.Store(n.ID, st)
		return
	}
	s.ifaceRetry.Delete(n.ID)
}

// KeepInterfaces checks the interfaces every interfaceCheckEvery until ctx
// ends.
func (s *Server) KeepInterfaces(ctx context.Context) {
	t := time.NewTicker(interfaceCheckEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.keepInterfacesOnce(ctx)
		}
	}
}

// handleRestartInterface restarts a network's interface and restores its
// peers (the panel's "Restart" on a network that is down).
func (s *Server) handleRestartInterface(w http.ResponseWriter, r *http.Request) {
	network, err := s.store.GetNetwork(r.Context(), mux.Vars(r)["id"])
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "failed to get network")
		return
	}
	if network == nil || network.InterfaceName == "" {
		errorResponse(w, http.StatusNotFound, "network not found")
		return
	}
	unlock := s.lockInterface(network.InterfaceName)
	err = s.bringUp(r.Context(), network, true)
	unlock()
	if err != nil {
		errorWithCode(w, http.StatusInternalServerError, "interface_failed", err.Error())
		return
	}
	s.ifaceRetry.Delete(network.ID)
	s.withInterfaceStatus(r, network)
	jsonResponse(w, http.StatusOK, network)
}

// restorePeersAfterUnitRestart puts the peers back after the Server page
// restarted wg-quick@wgN: the unit starts without its runtime peers, and its
// interface exists, so the check would not see the loss.
func (s *Server) restorePeersAfterUnitRestart(ctx context.Context, unit string) {
	iface, ok := strings.CutPrefix(unit, "wg-quick@")
	if !ok {
		return
	}
	networks, err := s.store.ListNetworks(ctx)
	if err != nil {
		slog.Warn(fmt.Sprintf("[WG] restore after restarting %s: %v", unit, err))
		return
	}
	for _, n := range networks {
		if n.InterfaceName != iface {
			continue
		}
		if mgr := s.getManager(n.ID); mgr != nil {
			unlock := s.lockInterface(iface)
			restoreNetworkPeers(s, ctx, n, mgr)
			unlock()
		}
	}
}
