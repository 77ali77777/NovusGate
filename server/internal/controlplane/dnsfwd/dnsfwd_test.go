package dnsfwd

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// fakeUpstream answers every UDP and TCP message with the message plus tag.
func fakeUpstream(t *testing.T, tag string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close(); ln.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(append(append([]byte{}, buf[:n]...), tag...), from)
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				msg := make([]byte, binary.BigEndian.Uint16(l[:]))
				io.ReadFull(c, msg)
				resp := append(msg, tag...)
				binary.BigEndian.PutUint16(l[:], uint16(len(resp)))
				c.Write(append(l[:], resp...))
			}()
		}
	}()
	return addr
}

// freeAddr is a loopback address with a port free for UDP and TCP.
func freeAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	return addr
}

// deadAddr answers nothing: a UDP port nobody reads.
func deadAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc.LocalAddr().String()
}

func askUDP(t *testing.T, addr, q string) string {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte(q))
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		return "error: " + err.Error()
	}
	return string(buf[:n])
}

func askTCP(t *testing.T, addr, q string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return "error: " + err.Error()
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(q)))
	c.Write(append(l[:], q...))
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return "error: " + err.Error()
	}
	resp := make([]byte, binary.BigEndian.Uint16(l[:]))
	io.ReadFull(c, resp)
	return string(resp)
}

func TestForwardsUDPAndTCP(t *testing.T) {
	up := fakeUpstream(t, "!a")
	f := New(500 * time.Millisecond)
	t.Cleanup(f.Close)
	hub := freeAddr(t)
	if errs := f.Sync(map[string][]string{hub: {up}}); len(errs) != 0 {
		t.Fatal(errs)
	}
	if !f.Listening(hub) {
		t.Fatal("listening")
	}
	if got := askUDP(t, hub, "q1"); got != "q1!a" {
		t.Fatalf("udp = %q", got)
	}
	if got := askTCP(t, hub, "q2"); got != "q2!a" {
		t.Fatalf("tcp = %q", got)
	}
}

func TestNextUpstreamWhenOneIsDead(t *testing.T) {
	up := fakeUpstream(t, "!b")
	f := New(300 * time.Millisecond)
	t.Cleanup(f.Close)
	hub := freeAddr(t)
	f.Sync(map[string][]string{hub: {deadAddr(t), up}})
	if got := askUDP(t, hub, "q"); got != "q!b" {
		t.Fatalf("udp = %q", got)
	}
}

// Changing a network's DNS servers changes only the upstreams: the hub
// address (what device configs name) stays.
func TestSyncSwapsUpstreamsAndStops(t *testing.T) {
	a, b := fakeUpstream(t, "!a"), fakeUpstream(t, "!b")
	f := New(500 * time.Millisecond)
	t.Cleanup(f.Close)
	hub := freeAddr(t)
	f.Sync(map[string][]string{hub: {a}})
	f.Sync(map[string][]string{hub: {b}})
	if got := askUDP(t, hub, "q"); got != "q!b" {
		t.Fatalf("new upstream: %q", got)
	}
	f.Sync(map[string][]string{})
	if f.Listening(hub) {
		t.Fatal("a removed address stops listening")
	}
	pc, err := net.ListenPacket("udp", hub)
	if err != nil {
		t.Fatalf("the port is free again: %v", err)
	}
	pc.Close()
}

// An address that cannot be bound (the interface is not up yet) is
// reported, and bound on a later Sync.
func TestSyncReportsAddressesItCannotBind(t *testing.T) {
	f := New(500 * time.Millisecond)
	t.Cleanup(f.Close)
	errs := f.Sync(map[string][]string{"192.0.2.77:53": {"127.0.0.1:1"}})
	if errs["192.0.2.77:53"] == nil || f.Listening("192.0.2.77:53") {
		t.Fatalf("errs = %v", errs)
	}
}
