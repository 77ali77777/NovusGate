// Package dnsfwd answers DNS on the hub's VPN addresses and forwards each
// query to the network's DNS servers (server-side routing, P3). Device
// configs name the hub as DNS once; which servers answer is decided here,
// so changing a network's DNS changes no config.
package dnsfwd

import (
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// maxInFlight caps the UDP queries forwarded at once per address.
	maxInFlight = 256
	// maxTCP caps the TCP connections served at once per address.
	maxTCP = 64
)

// Target is what one listen address serves: the upstreams (host:port, tried
// in order, starting with the one that answered last) and the sources it
// answers (the network's own range: a device of another network that
// routes the pool to the hub gets nothing, so isolation holds).
type Target struct {
	Upstreams []string
	Allow     netip.Prefix
}

// Forwarder keeps one UDP and one TCP listener per hub address.
type Forwarder struct {
	timeout time.Duration
	mu      sync.Mutex
	ls      map[string]*listener
}

type listener struct {
	udp    net.PacketConn
	tcp    net.Listener
	target atomic.Pointer[Target]
	sem    chan struct{} // UDP queries in flight
	conns  chan struct{} // TCP connections open
	closed atomic.Bool
	// next is the upstream to try first: the one that answered last.
	next atomic.Int32
	// lastWarn (unix seconds) keeps failed forwards to one warning a minute.
	lastWarn atomic.Int64
}

// New returns a forwarder whose upstream exchanges time out after timeout.
func New(timeout time.Duration) *Forwarder {
	return &Forwarder{timeout: timeout, ls: map[string]*listener{}}
}

// Sync makes the forwarder listen on exactly the addresses of want
// (host:port). It returns the addresses it could not bind; they are tried
// again on the next Sync.
func (f *Forwarder) Sync(want map[string]Target) map[string]error {
	f.mu.Lock()
	defer f.mu.Unlock()
	errs := map[string]error{}
	for addr, l := range f.ls {
		if _, ok := want[addr]; !ok {
			l.close()
			delete(f.ls, addr)
		}
	}
	for addr, t := range want {
		t := Target{Upstreams: append([]string(nil), t.Upstreams...), Allow: t.Allow}
		if l, ok := f.ls[addr]; ok {
			if old := l.target.Load(); old == nil || !sameUpstreams(old.Upstreams, t.Upstreams) {
				l.next.Store(0)
			}
			l.target.Store(&t)
			continue
		}
		l, err := f.listen(addr)
		if err != nil {
			errs[addr] = err
			continue
		}
		l.target.Store(&t)
		f.ls[addr] = l
	}
	return errs
}

func sameUpstreams(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Listening says whether addr is served.
func (f *Forwarder) Listening(addr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.ls[addr]
	return ok
}

// Close stops every listener.
func (f *Forwarder) Close() {
	f.Sync(map[string]Target{})
}

func (f *Forwarder) listen(addr string) (*listener, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		pc.Close()
		return nil, err
	}
	l := &listener{udp: pc, tcp: ln, sem: make(chan struct{}, maxInFlight), conns: make(chan struct{}, maxTCP)}
	go f.serveUDP(l)
	go f.serveTCP(l)
	return l, nil
}

func (l *listener) close() {
	l.closed.Store(true)
	l.udp.Close()
	l.tcp.Close()
}

// allowed: the source address lies in the listener's network.
func (l *listener) allowed(a net.Addr) bool {
	t := l.target.Load()
	if t == nil || !t.Allow.IsValid() {
		return false
	}
	ap, err := netip.ParseAddrPort(a.String())
	return err == nil && t.Allow.Contains(ap.Addr().Unmap())
}

// upstreams returns the upstreams starting with the one that answered last.
func (l *listener) upstreams() ([]string, int) {
	t := l.target.Load()
	if t == nil || len(t.Upstreams) == 0 {
		return nil, 0
	}
	start := int(l.next.Load()) % len(t.Upstreams)
	return t.Upstreams, start
}

// warn logs a failed forward, at most once a minute per address: a dead
// upstream would otherwise log every query.
func (l *listener) warn(err error) {
	now := time.Now().Unix()
	if last := l.lastWarn.Load(); now-last < 60 || !l.lastWarn.CompareAndSwap(last, now) {
		return
	}
	ups, _ := l.upstreams()
	slog.Warn("dns forward failed", "address", l.udp.LocalAddr().String(), "upstreams", ups, "error", err)
}

// exchange tries the upstreams in turn with one try function; the one that
// answers is tried first next time.
func (l *listener) exchange(q []byte, try func(up string, q []byte) ([]byte, error)) ([]byte, error) {
	ups, start := l.upstreams()
	err := errors.New("no DNS upstream")
	for i := range ups {
		idx := (start + i) % len(ups)
		var resp []byte
		if resp, err = try(ups[idx], q); err == nil {
			l.next.Store(int32(idx))
			return resp, nil
		}
	}
	return nil, err
}

func (f *Forwarder) serveUDP(l *listener) {
	buf := make([]byte, 65535)
	for {
		n, from, err := l.udp.ReadFrom(buf)
		if err != nil {
			if l.closed.Load() {
				return
			}
			time.Sleep(50 * time.Millisecond) // a transient error: keep serving
			continue
		}
		if !l.allowed(from) {
			continue
		}
		q := append([]byte(nil), buf[:n]...)
		select {
		case l.sem <- struct{}{}:
		default:
			continue // too many at once: the client retries
		}
		go func() {
			defer func() { <-l.sem }()
			resp, err := l.exchange(q, f.exchangeUDP)
			if err != nil {
				l.warn(err)
				if resp = servfail(q); resp == nil {
					return
				}
			}
			l.udp.WriteTo(resp, from)
		}()
	}
}

func (f *Forwarder) exchangeUDP(up string, q []byte) ([]byte, error) {
	c, err := net.DialTimeout("udp", up, f.timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(f.timeout))
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (f *Forwarder) serveTCP(l *listener) {
	for {
		c, err := l.tcp.Accept()
		if err != nil {
			if l.closed.Load() {
				return
			}
			// Out of file descriptors or similar: wait and keep serving
			// rather than leave a listener that accepts nothing.
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if !l.allowed(c.RemoteAddr()) {
			c.Close()
			continue
		}
		select {
		case l.conns <- struct{}{}:
		default:
			c.Close() // over the cap
			continue
		}
		go func() {
			defer func() { <-l.conns }()
			defer c.Close()
			for {
				c.SetDeadline(time.Now().Add(10 * time.Second))
				q, err := readTCPMsg(c)
				if err != nil {
					return
				}
				resp, err := l.exchange(q, f.exchangeTCP)
				if err != nil {
					l.warn(err)
					if resp = servfail(q); resp == nil {
						return
					}
				}
				if writeTCPMsg(c, resp) != nil {
					return
				}
			}
		}()
	}
}

func (f *Forwarder) exchangeTCP(up string, q []byte) ([]byte, error) {
	c, err := net.DialTimeout("tcp", up, f.timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(f.timeout))
	if err := writeTCPMsg(c, q); err != nil {
		return nil, err
	}
	return readTCPMsg(c)
}

// servfail is the SERVFAIL answer to query q: its header and question with
// QR set, RCODE 2 and no other records; nil when q is not one question.
func servfail(q []byte) []byte {
	if len(q) < 12 || binary.BigEndian.Uint16(q[4:6]) != 1 {
		return nil
	}
	i := 12
	for i < len(q) && q[i] != 0 { // QNAME labels (queries carry no pointers)
		if q[i]&0xC0 != 0 {
			return nil
		}
		i += int(q[i]) + 1
	}
	end := i + 1 + 4 // the zero byte, QTYPE, QCLASS
	if end > len(q) {
		return nil
	}
	resp := append([]byte(nil), q[:end]...)
	resp[2] |= 0x80                   // QR: a response
	resp[3] = resp[3]&0xF0 | 2 | 0x80 // RA, RCODE SERVFAIL
	binary.BigEndian.PutUint16(resp[6:8], 0)
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)
	return resp
}

// DNS over TCP: each message has a two-byte length in front (RFC 1035 4.2.2).
func readTCPMsg(r io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(l[:]))
	_, err := io.ReadFull(r, msg)
	return msg, err
}

func writeTCPMsg(w io.Writer, msg []byte) error {
	if len(msg) > 65535 {
		return errors.New("message too long")
	}
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(msg)))
	_, err := w.Write(append(l[:], msg...))
	return err
}
