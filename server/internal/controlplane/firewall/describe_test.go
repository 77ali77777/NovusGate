package firewall

import (
	"reflect"
	"testing"
	"time"

	"github.com/novusgate/novusgate/internal/shared/models"
)

func TestDescribeState(t *testing.T) {
	until := time.Date(2026, 10, 20, 8, 30, 0, 0, time.UTC)
	st := State{
		Services: []*models.FirewallService{
			{Protocol: "tcp", PortFrom: 443, PortTo: 443, Sources: []string{}},
			{Protocol: "udp", PortFrom: 8000, PortTo: 8100, Sources: []string{"203.0.113.0/24", "2001:db8::/32"}, Interface: "wg1", Comment: "games"},
		},
		IPRules: []*models.FirewallIPRule{
			{Action: "block", Prefix: "198.51.100.7/32", Protocol: "tcp", Ports: "22,80", ExpiresAt: &until, Origin: "fail2ban"},
			{Action: "allow", Prefix: "192.0.2.0/24", Origin: "panel", Comment: "office"},
		},
		Forwards:      []*models.FirewallForward{{Protocol: "tcp", PublicPort: 8081, TargetIP: "10.20.0.5", TargetPort: 80, Comment: "cam"}},
		EgressNodeIDs: []string{"n-1", "n-2"},
	}
	got := Describe(st, map[string]string{"n-1": "laptop-01"})
	want := []string{
		"allow 192.0.2.0/24 (office)",
		"block 198.51.100.7/32 tcp 22,80 until 2026-10-20 08:30 UTC [fail2ban]",
		"forward tcp 8081 -> 10.20.0.5:80 (cam)",
		"full tunnel: laptop-01",
		"full tunnel: n-2",
		"service tcp 443 from any",
		"service udp 8000-8100 from 203.0.113.0/24, 2001:db8::/32 on wg1 (games)",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestDiffLines(t *testing.T) {
	added, removed := DiffLines([]string{"a", "b", "b", "c"}, []string{"b", "c", "d"})
	if !reflect.DeepEqual(added, []string{"d"}) || !reflect.DeepEqual(removed, []string{"a", "b"}) {
		t.Fatalf("added %q removed %q", added, removed)
	}
	added, removed = DiffLines(nil, []string{"x"})
	if !reflect.DeepEqual(added, []string{"x"}) || len(removed) != 0 || removed == nil {
		t.Fatalf("from nothing: added %q removed %#v", added, removed)
	}
}
