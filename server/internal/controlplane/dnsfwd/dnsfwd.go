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
	"sync"
	"sync/atomic"
	"time"
)

// maxInFlight caps the UDP queries forwarded at once per address.
const maxInFlight = 256

// Forwarder keeps one UDP and one TCP listener per hub address.
type Forwarder struct {
	timeout time.Duration
	mu      sync.Mutex
	ls      map[string]*listener
}

type listener struct {
	udp net.PacketConn
	tcp net.Listener
	up  atomic.Pointer[[]string] // upstream host:port, tried in order
	sem chan struct{}
}

// New returns a forwarder whose upstream exchanges time out after timeout.
func New(timeout time.Duration) *Forwarder {
	return &Forwarder{timeout: timeout, ls: map[string]*listener{}}
}

// Sync makes the forwarder listen on exactly the addresses of want (host:port)
// with their upstreams (host:port). It returns the addresses it could not
// bind; they are tried again on the next Sync.
func (f *Forwarder) Sync(want map[string][]string) map[string]error {
	f.mu.Lock()
	defer f.mu.Unlock()
	errs := map[string]error{}
	for addr, l := range f.ls {
		if _, ok := want[addr]; !ok {
			l.close()
			delete(f.ls, addr)
		}
	}
	for addr, ups := range want {
		ups := append([]string(nil), ups...)
		if l, ok := f.ls[addr]; ok {
			l.up.Store(&ups)
			continue
		}
		l, err := f.listen(addr)
		if err != nil {
			errs[addr] = err
			continue
		}
		l.up.Store(&ups)
		f.ls[addr] = l
	}
	return errs
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
	f.Sync(map[string][]string{})
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
	l := &listener{udp: pc, tcp: ln, sem: make(chan struct{}, maxInFlight)}
	go f.serveUDP(l)
	go f.serveTCP(l)
	return l, nil
}

func (l *listener) close() {
	l.udp.Close()
	l.tcp.Close()
}

func (l *listener) upstreams() []string {
	if p := l.up.Load(); p != nil {
		return *p
	}
	return nil
}

func (f *Forwarder) serveUDP(l *listener) {
	buf := make([]byte, 65535)
	for {
		n, from, err := l.udp.ReadFrom(buf)
		if err != nil {
			return // closed
		}
		q := append([]byte(nil), buf[:n]...)
		select {
		case l.sem <- struct{}{}:
		default:
			continue // too many at once: the client retries
		}
		go func() {
			defer func() { <-l.sem }()
			resp, err := f.exchangeUDP(q, l.upstreams())
			if err != nil {
				slog.Debug("dns forward failed", "error", err)
				return
			}
			l.udp.WriteTo(resp, from)
		}()
	}
}

func (f *Forwarder) exchangeUDP(q []byte, ups []string) ([]byte, error) {
	err := errors.New("no DNS upstream")
	for _, up := range ups {
		var c net.Conn
		if c, err = net.DialTimeout("udp", up, f.timeout); err != nil {
			continue
		}
		c.SetDeadline(time.Now().Add(f.timeout))
		if _, err = c.Write(q); err == nil {
			buf := make([]byte, 65535)
			var n int
			if n, err = c.Read(buf); err == nil {
				c.Close()
				return buf[:n], nil
			}
		}
		c.Close()
	}
	return nil, err
}

func (f *Forwarder) serveTCP(l *listener) {
	for {
		c, err := l.tcp.Accept()
		if err != nil {
			return // closed
		}
		go func() {
			defer c.Close()
			for {
				c.SetDeadline(time.Now().Add(10 * time.Second))
				q, err := readTCPMsg(c)
				if err != nil {
					return
				}
				resp, err := f.exchangeTCP(q, l.upstreams())
				if err != nil {
					return
				}
				if writeTCPMsg(c, resp) != nil {
					return
				}
			}
		}()
	}
}

func (f *Forwarder) exchangeTCP(q []byte, ups []string) ([]byte, error) {
	err := errors.New("no DNS upstream")
	for _, up := range ups {
		var c net.Conn
		if c, err = net.DialTimeout("tcp", up, f.timeout); err != nil {
			continue
		}
		c.SetDeadline(time.Now().Add(f.timeout))
		var resp []byte
		if err = writeTCPMsg(c, q); err == nil {
			if resp, err = readTCPMsg(c); err == nil {
				c.Close()
				return resp, nil
			}
		}
		c.Close()
	}
	return nil, err
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
