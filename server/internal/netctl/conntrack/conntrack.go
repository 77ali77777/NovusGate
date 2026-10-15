// Package conntrack summarizes the host's connection-tracking table for the
// firewall's Live view. The control plane uses the host network, so /proc
// shows the host's table.
package conntrack

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// maxLines bounds the work on a busy host; counts beyond it come from
// nf_conntrack_count only.
const maxLines = 200000

// Summary is the size of the table and its entries by protocol.
type Summary struct {
	Available  bool           `json:"available"`
	Count      int            `json:"count"`
	Max        int            `json:"max"`
	ByProtocol map[string]int `json:"by_protocol"`
	TCPStates  map[string]int `json:"tcp_states"`
	Truncated  bool           `json:"truncated,omitempty"` // the listing had more than maxLines entries
}

// Read summarizes conntrack from procRoot (normally "/proc").
func Read(procRoot string) Summary {
	s := Summary{ByProtocol: map[string]int{}, TCPStates: map[string]int{}}
	count, okCount := readInt(filepath.Join(procRoot, "sys/net/netfilter/nf_conntrack_count"))
	max, okMax := readInt(filepath.Join(procRoot, "sys/net/netfilter/nf_conntrack_max"))
	s.Count, s.Max = count, max
	s.Available = okCount || okMax

	f, err := os.Open(filepath.Join(procRoot, "net/nf_conntrack"))
	if err != nil {
		return s
	}
	defer f.Close()
	s.Available = true
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	lines := 0
	for sc.Scan() {
		if lines++; lines > maxLines {
			s.Truncated = true
			break
		}
		// "ipv4 2 tcp 6 431999 ESTABLISHED src=..." / "ipv4 2 udp 17 25 src=..."
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		proto := fields[2]
		s.ByProtocol[proto]++
		if proto == "tcp" && len(fields) > 5 && !strings.Contains(fields[5], "=") {
			s.TCPStates[fields[5]]++
		}
	}
	return s
}

func readInt(path string) (int, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return n, err == nil
}
