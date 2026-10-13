package models

import (
	"net"
	"testing"
	"time"
)

func TestNodeActive(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Minute), now.Add(time.Minute)
	ip := net.ParseIP("10.0.0.5")
	cases := []struct {
		name string
		n    Node
		want bool
	}{
		{"active", Node{PublicKey: "k", VirtualIP: ip, Status: NodeStatusOnline}, true},
		{"future expiry", Node{PublicKey: "k", VirtualIP: ip, ExpiresAt: &future}, true},
		{"expired by time", Node{PublicKey: "k", VirtualIP: ip, ExpiresAt: &past}, false},
		{"expired status", Node{PublicKey: "k", VirtualIP: ip, Status: NodeStatusExpired}, false},
		{"no key", Node{VirtualIP: ip}, false},
		{"no ip", Node{PublicKey: "k"}, false},
		{"exactly at expiry", Node{PublicKey: "k", VirtualIP: ip, ExpiresAt: &now}, true}, // expired only once now is after expires_at, as enrichNode
	}
	for _, c := range cases {
		if got := c.n.Active(now); got != c.want {
			t.Errorf("%s: Active = %v, want %v", c.name, got, c.want)
		}
	}
}
