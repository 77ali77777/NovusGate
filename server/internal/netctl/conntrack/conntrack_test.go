package conntrack

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadSummarizesTheTable(t *testing.T) {
	root := t.TempDir()
	write(t, root, "sys/net/netfilter/nf_conntrack_count", "4\n")
	write(t, root, "sys/net/netfilter/nf_conntrack_max", "262144\n")
	write(t, root, "net/nf_conntrack",
		"ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.2 dst=10.0.0.1 sport=50000 dport=22 src=10.0.0.1 dst=10.0.0.2 sport=22 dport=50000 [ASSURED] mark=0 zone=0 use=2\n"+
			"ipv4     2 tcp      6 98 TIME_WAIT src=10.0.0.3 dst=10.0.0.1 sport=50001 dport=443 src=10.0.0.1 dst=10.0.0.3 sport=443 dport=50001 [ASSURED] mark=0 zone=0 use=2\n"+
			"ipv4     2 udp      17 25 src=10.99.0.2 dst=1.1.1.1 sport=40000 dport=53 src=1.1.1.1 dst=10.99.0.2 sport=53 dport=40000 mark=0 zone=0 use=2\n"+
			"ipv6     10 icmpv6   58 29 src=2001:db8::1 dst=2001:db8::2 type=128 code=0 id=1 src=2001:db8::2 dst=2001:db8::1 type=129 code=0 id=1 mark=0 zone=0 use=2\n")
	s := Read(root)
	if !s.Available || s.Count != 4 || s.Max != 262144 {
		t.Fatalf("summary = %+v", s)
	}
	if s.ByProtocol["tcp"] != 2 || s.ByProtocol["udp"] != 1 || s.ByProtocol["icmpv6"] != 1 {
		t.Fatalf("by protocol = %v", s.ByProtocol)
	}
	if s.TCPStates["ESTABLISHED"] != 1 || s.TCPStates["TIME_WAIT"] != 1 || len(s.TCPStates) != 2 {
		t.Fatalf("tcp states = %v", s.TCPStates)
	}
}

// Without nf_conntrack loaded (or without the proc listing) the counts that
// exist are still shown; nothing at all means unavailable.
func TestReadWithoutConntrack(t *testing.T) {
	if s := Read(t.TempDir()); s.Available {
		t.Fatalf("empty proc = %+v", s)
	}
	root := t.TempDir()
	write(t, root, "sys/net/netfilter/nf_conntrack_count", "7\n")
	write(t, root, "sys/net/netfilter/nf_conntrack_max", "65536\n")
	s := Read(root)
	if !s.Available || s.Count != 7 || s.Max != 65536 || len(s.ByProtocol) != 0 {
		t.Fatalf("counts only = %+v", s)
	}
}
