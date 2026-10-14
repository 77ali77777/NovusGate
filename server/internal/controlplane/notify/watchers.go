package notify

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"time"

	"github.com/novusgate/novusgate/internal/wireguard"
)

// Online/offline thresholds on the last handshake. Between them a node keeps
// its previous state, so a late handshake does not flap.
const (
	onlineWithin  = 150 * time.Second // the panel's own threshold
	offlineAfter  = 5 * time.Minute
	watchInterval = time.Minute
)

// WatchedNode is a node with what the watcher needs to find its peer.
type WatchedNode struct {
	ID, Name, Network, Interface, PublicKey string
}

// PeerWatcher reports nodes that go offline and come back.
type PeerWatcher struct {
	Notifier *Notifier
	Nodes    func(ctx context.Context) ([]WatchedNode, error)
	Peers    func(iface string) (map[string]wireguard.PeerStatus, error)
	Now      func() time.Time

	online map[string]bool // last known state per node ID
}

// RunOnce checks every node once.
func (w *PeerWatcher) RunOnce(ctx context.Context) {
	if w.online == nil {
		w.online = map[string]bool{}
	}
	nodes, err := w.Nodes(ctx)
	if err != nil {
		slog.Warn("peer watcher: nodes not read", "error", err)
		return
	}
	peersByIface := map[string]map[string]wireguard.PeerStatus{}
	now := w.Now()
	for _, n := range nodes {
		peers, ok := peersByIface[n.Interface]
		if !ok {
			peers, err = w.Peers(n.Interface)
			if err != nil {
				peers = nil // interface down: its nodes keep their state
			}
			peersByIface[n.Interface] = peers
		}
		p, found := peers[n.PublicKey]
		if peers == nil || !found {
			continue
		}
		age := now.Sub(time.Unix(p.LatestHandshakeTime, 0))
		was, known := w.online[n.ID]
		is := was
		switch {
		case p.LatestHandshakeTime > 0 && age < onlineWithin:
			is = true
		case p.LatestHandshakeTime == 0 || age >= offlineAfter:
			is = false
		}
		w.online[n.ID] = is
		if !known || is == was {
			continue
		}
		if is {
			w.Notifier.Deliver(ctx, Event{Kind: NodeOffline, Key: n.ID + "|up",
				Text: fmt.Sprintf("✅ NovusGate: node %s (%s) is back online", n.Name, n.Network)})
		} else {
			w.Notifier.Deliver(ctx, Event{Kind: NodeOffline, Key: n.ID + "|down",
				Text: fmt.Sprintf("⚠️ NovusGate: node %s (%s) is offline (no handshake for %s)", n.Name, n.Network, offlineAfter)})
		}
	}
}

// Run checks every minute until ctx ends.
func (w *PeerWatcher) Run(ctx context.Context) {
	runEvery(ctx, watchInterval, w.RunOnce)
}

// banRe matches fail2ban's "NOTICE [jail] Ban 1.2.3.4" (not Unban).
var banRe = regexp.MustCompile(`NOTICE\s+\[([^\]]+)\]\s+Ban\s+(\S+)`)

// Fail2BanWatcher reports new bans from fail2ban's log. Lines already in the
// log when it starts are history; a shorter file (rotation) starts over.
type Fail2BanWatcher struct {
	Notifier *Notifier
	Path     string

	offset  int64
	started bool
}

// RunOnce reads what the log gained since the last call.
func (w *Fail2BanWatcher) RunOnce(ctx context.Context) {
	f, err := os.Open(w.Path)
	if err != nil {
		return // no fail2ban on this host
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return
	}
	if !w.started {
		w.started, w.offset = true, st.Size()
		return
	}
	if st.Size() < w.offset {
		w.offset = 0
	}
	if _, err := f.Seek(w.offset, io.SeekStart); err != nil {
		return
	}
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break // a partial last line is read again next time
		}
		w.offset += int64(len(line))
		if m := banRe.FindStringSubmatch(line); m != nil {
			w.Notifier.Deliver(ctx, Event{Kind: Fail2BanBan, Key: m[1] + "|" + m[2],
				Text: fmt.Sprintf("🚫 NovusGate: Fail2Ban banned %s (jail %s)", m[2], m[1])})
		}
	}
}

// Run checks every 30 seconds until ctx ends.
func (w *Fail2BanWatcher) Run(ctx context.Context) {
	runEvery(ctx, 30*time.Second, w.RunOnce)
}

func runEvery(ctx context.Context, every time.Duration, fn func(context.Context)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		fn(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
