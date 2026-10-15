package nft

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Functional check of limit profiles (P9b) with real packets. Node A
// (10.61.0.2, netns nsA) reaches server B (10.62.0.2, netns nsB) through this
// network namespace, which plays the hub with veths named wg1/wg2. Needs
// NET_ADMIN, SYS_ADMIN, ip_forward=1, nftables, iproute2, iperf3 and ncat;
// server/scripts/limits-functional-check.sh provides them.
func TestLimitsWithRealTraffic(t *testing.T) {
	if os.Getenv("NFT_FUNC") != "1" {
		t.Skip("set NFT_FUNC=1 (server/scripts/limits-functional-check.sh)")
	}
	sh := func(cmd string) string {
		t.Helper()
		out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", cmd, err, out)
		}
		return string(out)
	}
	for i, ns := range []string{"nsA", "nsB"} {
		n := i + 1
		sh(fmt.Sprintf(`ip netns add %[1]s
ip link add wg%[2]d type veth peer name p%[2]d
ip link set p%[2]d netns %[1]s
ip addr add 10.6%[2]d.0.1/24 dev wg%[2]d && ip link set wg%[2]d up
ip netns exec %[1]s ip addr add 10.6%[2]d.0.2/24 dev p%[2]d
ip netns exec %[1]s ip link set p%[2]d up
ip netns exec %[1]s ip link set lo up
ip netns exec %[1]s ip route add default via 10.6%[2]d.0.1`, ns, n))
	}
	t.Cleanup(func() {
		exec.Command("sh", "-c", "nft delete table inet novusgate; ip netns del nsA; ip netns del nsB; pkill iperf3; pkill ncat").Run()
	})
	nodeA := netip.MustParseAddr("10.61.0.2")
	base := Ruleset{
		SSHPorts: []uint16{22}, EgressInterface: "eth0",
		Networks: []VPNNetwork{
			{Interface: "wg1", CIDR: netip.MustParsePrefix("10.61.0.0/24"), ListenPort: 51821},
			{Interface: "wg2", CIDR: netip.MustParsePrefix("10.62.0.0/24"), ListenPort: 51822},
		},
		VPNRules: []VPNRule{
			{ID: "a-b", Src: netip.MustParsePrefix("10.61.0.0/24"), Dst: netip.MustParsePrefix("10.62.0.0/24"), Proto: All, Action: "accept"},
			{ID: "b-a", Src: netip.MustParsePrefix("10.62.0.0/24"), Dst: netip.MustParsePrefix("10.61.0.0/24"), Proto: All, Action: "accept"},
		},
	}
	exe := Executor{Runner: HostRunner{}}
	apply := func(limits ...Limit) {
		t.Helper()
		rs := base
		rs.Limits = limits
		script, err := Compile(rs, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := exe.Apply(script); err != nil {
			t.Fatal(err)
		}
	}
	ping := func() bool {
		return exec.Command("ip", "netns", "exec", "nsA", "ping", "-c1", "-W1", "10.62.0.2").Run() == nil
	}
	// mbps runs iperf3 for 8 s, leaving out the first 2 (the bucket starts
	// full), with the client in clientNS; it returns what the receiver
	// measured, in Mbit/s.
	mbps := func(serverNS, serverIP, clientNS string) float64 {
		t.Helper()
		sh(fmt.Sprintf("ip netns exec %s iperf3 -s -1 -D", serverNS))
		time.Sleep(300 * time.Millisecond)
		out := sh(fmt.Sprintf("ip netns exec %s iperf3 -c %s -t 8 -O 2 -J", clientNS, serverIP))
		var res struct {
			End struct {
				SumReceived struct {
					BitsPerSecond float64 `json:"bits_per_second"`
				} `json:"sum_received"`
			} `json:"end"`
		}
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			t.Fatalf("iperf3 output: %v\n%s", err, out)
		}
		return res.End.SumReceived.BitsPerSecond / 1e6
	}
	within := func(name string, got, want float64) {
		t.Helper()
		t.Logf("%s: %.2f Mbit/s (limit %.0f)", name, got, want)
		if got < want*0.8 || got > want*1.2 {
			t.Errorf("%s: %.2f Mbit/s, want %.0f ±20%%", name, got, want)
		}
	}

	apply()
	if !ping() {
		t.Fatal("A cannot reach B without limits: the topology is broken")
	}
	free := mbps("nsB", "10.62.0.2", "nsA")
	t.Logf("unlimited: %.0f Mbit/s", free)

	// Upload 8 Mbit/s and download 4 Mbit/s for A.
	apply(Limit{Name: "lim_0", ID: "speed", Members: []netip.Addr{nodeA}, UpBytes: 1_000_000, DownBytes: 500_000})
	within("upload A->B", mbps("nsB", "10.62.0.2", "nsA"), 8)
	within("download B->A", mbps("nsA", "10.61.0.2", "nsB"), 4)

	// At most 3 concurrent connections: the 4th never connects.
	apply(Limit{Name: "lim_0", ID: "conns", Members: []netip.Addr{nodeA}, MaxConns: 3})
	sh("ip netns exec nsB sh -c 'ncat -lk 9000 > /dev/null 2>&1 &'")
	time.Sleep(300 * time.Millisecond)
	for i := 1; i <= 3; i++ {
		// bash keeps the connection open on fd 3 and writes to it twice a
		// second, as a live connection does.
		sh("ip netns exec nsA bash -c 'exec 3<>/dev/tcp/10.62.0.2/9000; while true; do echo x >&3; sleep 0.5; done' > /dev/null 2>&1 &")
	}
	time.Sleep(time.Second)
	if exec.Command("ip", "netns", "exec", "nsA", "ncat", "-w", "2", "-z", "10.62.0.2", "9000").Run() == nil {
		t.Error("the 4th connection must be dropped")
	}
	// Every apply replaces the table, which empties the connection sets;
	// the open connections must count again, or the cap would double.
	apply(Limit{Name: "lim_0", ID: "conns", Members: []netip.Addr{nodeA}, MaxConns: 3})
	time.Sleep(1500 * time.Millisecond)
	if exec.Command("ip", "netns", "exec", "nsA", "ncat", "-w", "2", "-z", "10.62.0.2", "9000").Run() == nil {
		t.Error("after a reload the 4th connection must still be dropped")
	}
	// Not through sh: pkill -f would match the shell's own command line.
	// The sleep inherited the socket, so it goes too.
	exec.Command("pkill", "-f", "dev/tcp/10.62.0.2").Run()
	exec.Command("pkill", "-x", "sleep").Run()
	time.Sleep(time.Second)
	if exec.Command("ip", "netns", "exec", "nsA", "ncat", "-w", "2", "-z", "10.62.0.2", "9000").Run() != nil {
		t.Error("after the others closed, a new connection must pass")
	}

	// Schedule: outside the allowed window A is cut off, inside it passes.
	now := time.Now().UTC()
	sec := now.Hour()*3600 + now.Minute()*60 + now.Second()
	other := TimeWindow{Day: (now.Weekday() + 3) % 7, From: 0, To: 86400}
	apply(Limit{Name: "lim_0", ID: "sched", Members: []netip.Addr{nodeA}, Windows: []TimeWindow{other}})
	if ping() {
		t.Error("outside the schedule (another day) A must be blocked")
	}
	// Today, but hours away from now.
	away := TimeWindow{Day: now.Weekday(), From: sec + 3600, To: sec + 7200}
	if sec >= 43200 {
		away = TimeWindow{Day: now.Weekday(), From: sec - 7200, To: sec - 3600}
	}
	apply(Limit{Name: "lim_0", ID: "sched", Members: []netip.Addr{nodeA}, Windows: []TimeWindow{other, away}})
	if ping() {
		t.Error("outside the schedule (another hour today) A must be blocked")
	}
	from, to := sec-600, sec+600
	if from < 0 {
		from = 0
	}
	if to > 86400 {
		to = 86400
	}
	apply(Limit{Name: "lim_0", ID: "sched", Members: []netip.Addr{nodeA},
		Windows: []TimeWindow{other, {Day: now.Weekday(), From: from, To: to}}})
	if !ping() {
		t.Error("inside the schedule A must pass")
	}
	if out := sh("nft list chain inet novusgate lim_0_time"); !strings.Contains(out, "meta hour") {
		t.Errorf("schedule chain:\n%s", out)
	}
}
