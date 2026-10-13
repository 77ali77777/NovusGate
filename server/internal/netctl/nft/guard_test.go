package nft

import (
	"net/netip"
	"testing"
	"time"
)

func TestCheckProtection(t *testing.T) {
	rs := fullRuleset()
	inHour := testNow.Add(time.Hour)
	ok := Protection{SSHPorts: []uint16{22, 2222}, Addrs: []netip.Addr{netip.MustParseAddr("10.99.0.2")}}
	if err := CheckProtection(rs, ok, testNow); err != nil {
		t.Fatalf("valid ruleset rejected: %v", err)
	}
	if err := CheckProtection(rs, Protection{}, testNow); err == nil {
		t.Fatal("no detected SSH port must fail closed")
	}
	if err := CheckProtection(rs, Protection{SSHPorts: []uint16{2200}}, testNow); err == nil {
		t.Fatal("a detected SSH port missing from the ruleset must be refused")
	}
	rs.Blocked = append(rs.Blocked, BlockedEntry{Prefix: netip.MustParsePrefix("10.99.0.0/24"), Expires: &inHour})
	if err := CheckProtection(rs, ok, testNow); err == nil {
		t.Fatal("blocking the operator's own address must be refused")
	}
}
