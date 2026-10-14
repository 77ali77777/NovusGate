package rest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Output of `iptables -L INPUT -n -v --line-numbers` (classic format, with the opt column).
const inputWithOpt = `Chain INPUT (policy DROP 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1      120  9000 ACCEPT     all  --  lo     *       0.0.0.0/0            0.0.0.0/0
2     5000  300K ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            state RELATED,ESTABLISHED
3       10   600 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22
4        0     0 ACCEPT     udp  --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpts:51820:51900
5        3   180 ACCEPT     tcp  --  wg0    *       0.0.0.0/0            0.0.0.0/0            tcp dpt:3007
6        0     0 ACCEPT     tcp  --  wg+    *       0.0.0.0/0            0.0.0.0/0            tcp dpt:8080
7        0     0 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:3007
8        0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:3
9        0     0 ACCEPT     tcp  --  *      *       203.0.113.5          0.0.0.0/0            tcp dpt:8443
`

// Newer iptables: numeric protocol and no opt column.
const inputNumericNoOpt = `Chain INPUT (policy DROP 0 packets, 0 bytes)
num   pkts bytes target     prot in     out     source               destination
1        0     0 ACCEPT     6    wg0    *       0.0.0.0/0            0.0.0.0/0            tcp dpt:3007
2        0     0 ACCEPT     6    *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:3
3        0     0 ACCEPT     17   *      *       0.0.0.0/0            0.0.0.0/0            udp dpt:5353
`

func TestFindRuleLineNumber(t *testing.T) {
	cases := []struct {
		name     string
		output   string
		protocol string
		port     int
		want     int
	}{
		{"exact port only, never a prefix of 3007", inputWithOpt, "tcp", 3, 8},
		{"interface-scoped admin rule is not touched", inputWithOpt, "tcp", 3007, 0},
		{"80 does not match 8080", inputWithOpt, "tcp", 80, 0},
		{"source-restricted rule created by Open Port", inputWithOpt, "tcp", 8443, 9},
		{"port range rule is never matched by a single port", inputWithOpt, "udp", 51820, 0},
		{"ssh rule is found (protection is checked by the caller)", inputWithOpt, "tcp", 22, 3},
		{"numeric protocol without opt column", inputNumericNoOpt, "tcp", 3, 2},
		{"numeric udp without opt column", inputNumericNoOpt, "udp", 5353, 3},
		{"numeric format keeps interface protection", inputNumericNoOpt, "tcp", 3007, 0},
		{"short lines do not panic", "1 0 0 ACCEPT\n2 0 0", "tcp", 3, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := findRuleLineNumber(tc.output, tc.protocol, tc.port, "ACCEPT")
			if got != tc.want {
				t.Fatalf("findRuleLineNumber(%s, %d) = %d, want %d", tc.protocol, tc.port, got, tc.want)
			}
		})
	}
}

func TestCustomSSHPortIsProtectedInLegacyMode(t *testing.T) {
	orig := legacySSHPorts
	legacySSHPorts = func() []uint16 { return []uint16{22, 2222} }
	t.Cleanup(func() { legacySSHPorts = orig })

	if !isProtectedRule(FirewallRule{Port: "2222", Target: "ACCEPT"}, legacySSHPorts()) {
		t.Fatal("an ACCEPT for a detected SSH port must be protected")
	}
	if isProtectedRule(FirewallRule{Port: "2223", Target: "ACCEPT"}, legacySSHPorts()) {
		t.Fatal("other ports are not SSH")
	}

	s := &Server{}
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"port":2222,"protocol":"tcp"}`))
	rec := httptest.NewRecorder()
	s.handleFirewallClosePort(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("closing a detected SSH port = %d, want 403", rec.Code)
	}
}

// B22: short lines must not panic, and iptables without the "opt" column
// (nf_tables builds) must still map in/out/source/destination correctly.
func TestParseRuleLine(t *testing.T) {
	for _, short := range []string{
		"1 0 0 ACCEPT all -- lo *",
		"1 0 0 ACCEPT all -- lo * 0.0.0.0/0",
	} {
		if r := parseRuleLine(short, "INPUT"); r != nil {
			t.Errorf("incomplete line %q must be skipped, got %+v", short, r)
		}
	}
	withOpt := parseRuleLine("3 10 600 ACCEPT tcp -- * * 0.0.0.0/0 0.0.0.0/0 tcp dpt:22", "INPUT")
	noOpt := parseRuleLine("3 10 600 ACCEPT 6 * * 0.0.0.0/0 0.0.0.0/0 tcp dpt:22", "INPUT")
	wg := parseRuleLine("5 3 180 ACCEPT 6 wg0 * 0.0.0.0/0 0.0.0.0/0 tcp dpt:3007", "INPUT")
	if withOpt == nil || withOpt.Port != "22" || withOpt.Source != "anywhere" || withOpt.Interface != "" {
		t.Fatalf("classic format: %+v", withOpt)
	}
	if noOpt == nil || noOpt.Port != "22" || noOpt.Source != "anywhere" || noOpt.Destination != "anywhere" || noOpt.Interface != "" {
		t.Fatalf("format without opt: %+v", noOpt)
	}
	if wg == nil || wg.InInterface != "wg0" || wg.Port != "3007" {
		t.Fatalf("interface without opt: %+v", wg)
	}
}

func TestParseRuleLineVariants(t *testing.T) {
	for _, c := range []struct {
		line, target, proto, port, source string
	}{
		{"4 0 0 ACCEPT 6 -- * * 0.0.0.0/0 0.0.0.0/0 tcp dpt:443", "ACCEPT", "6", "443", "anywhere"},         // numeric protocol with the opt column
		{"5 0 0 ACCEPT tcp -f * * 0.0.0.0/0 0.0.0.0/0 tcp dpt:80", "ACCEPT", "tcp", "80", "anywhere"},       // fragments only
		{"6 0 0 ACCEPT tcp !f * * 0.0.0.0/0 0.0.0.0/0 tcp dpt:81", "ACCEPT", "tcp", "81", "anywhere"},       // no fragments
		{"7 2 120 DROP all -- * * 203.0.113.9 0.0.0.0/0", "DROP", "all", "", "203.0.113.9"},                 // a DROP without a port
		{"8 0 0 ACCEPT udp -- * * 0.0.0.0/0 0.0.0.0/0 udp dpt:51820", "ACCEPT", "udp", "51820", "anywhere"}, // udp with the opt column
		{"9 0 0 ACCEPT tcp -- * * 0.0.0.0/0 0.0.0.0/0 /* opened for dpt:9999 */ tcp dpt:8080", "ACCEPT", "tcp", "8080", "anywhere"},
	} {
		r := parseRuleLine(c.line, "INPUT")
		if r == nil || r.Target != c.target || r.Protocol != c.proto || r.Port != c.port || r.Source != c.source {
			t.Errorf("%q = %+v, want target=%s proto=%s port=%q source=%s", c.line, r, c.target, c.proto, c.port, c.source)
		}
	}
}
