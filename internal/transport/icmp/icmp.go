// Package icmp provides an ICMP echo-based transport for Burrow tunnel traffic.
// It embeds tunnel data in ICMP Echo Request/Reply packets, allowing traffic
// through networks that block TCP/UDP but permit ICMP (ping).
//
// Two modes are supported:
//   - "ip4:icmp" (production): uses raw ICMP sockets, requires root or CAP_NET_RAW
//   - "udp4" (testing): uses plain UDP sockets carrying ICMP-framed payloads, no root required
package icmp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/loudmumble/burrow/internal/transport"
	goicmp "golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	// protocolICMP is the IANA protocol number for ICMPv4.
	protocolICMP = 1

	// maxPayload is the maximum tunnel payload per ICMP packet.
	// Keeps total packet size well within typical 1500-byte MTU.
	maxPayload = 1400

	// flagData indicates a data frame.
	flagData byte = 0x00

	// flagFIN indicates a connection close.
	flagFIN byte = 0x01
)

func init() {
	transport.Registry["icmp"] = func() transport.Transport { return NewICMPTransport(true) }
}

// ICMPTransport implements transport.Transport over ICMP echo request/reply
// packets. Data is embedded in the ICMP echo data field with a one-byte
// framing header for data/FIN signaling.
type ICMPTransport struct {
	UseUDP    bool // true = "udp4" (no root), false = "ip4:icmp" (root)
	listener  net.PacketConn
	sessions  map[string]*icmpConn
	connCh    chan net.Conn
	mu        sync.Mutex
	addr      string
	done      chan struct{}
	closeOnce sync.Once
}

func NewICMPTransport(useUDP bool) *ICMPTransport {
	return &ICMPTransport{
		UseUDP:   useUDP,
		sessions: make(map[string]*icmpConn),
		connCh:   make(chan net.Conn, 64),
		done:     make(chan struct{}),
	}
}

// Name returns the transport identifier.
func (t *ICMPTransport) Name() string { return "icmp" }

func (t *ICMPTransport) openPacketConn(addr string) (net.PacketConn, error) {
	if t.UseUDP {
		return net.ListenPacket("udp4", addr)
	}
	return goicmp.ListenPacket("ip4:icmp", addr)
}

func (t *ICMPTransport) resolveAddr(addr string) (net.Addr, error) {
	if t.UseUDP {
		return net.ResolveUDPAddr("udp4", addr)
	}
	return net.ResolveIPAddr("ip4", addr)
}

// Listen starts an ICMP listener on addr. For "udp4" mode, addr should be
// "host:port" (use port 0 for auto-assign). For "ip4:icmp" mode, addr should
// be an IP address like "0.0.0.0". Non-blocking.
func (t *ICMPTransport) Listen(_ context.Context, addr string, _ *tls.Config) error {
	pc, err := t.openPacketConn(addr)
	if err != nil {
		return fmt.Errorf("icmp transport listen: %w", err)
	}

	t.mu.Lock()
	t.listener = pc
	t.addr = pc.LocalAddr().String()
	t.mu.Unlock()

	go t.recvLoop()
	return nil
}

// recvLoop reads incoming ICMP packets, demultiplexes by remote address,
// and delivers data to the appropriate session.
func (t *ICMPTransport) recvLoop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-t.done:
			return
		default:
		}

		if err := t.listener.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			select {
			case <-t.done:
			default:
			}
			return
		}

		n, raddr, err := t.listener.ReadFrom(buf)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			select {
			case <-t.done:
			default:
			}
			return
		}

		msg, err := goicmp.ParseMessage(protocolICMP, buf[:n])
		if err != nil {
			continue
		}

		echo, ok := msg.Body.(*goicmp.Echo)
		if !ok || len(echo.Data) == 0 {
			continue
		}

		key := raddr.String()
		flag := echo.Data[0]
		payload := echo.Data[1:]

		t.mu.Lock()
		sess, exists := t.sessions[key]
		if !exists && flag == flagFIN {
			// FIN for unknown session, ignore.
			t.mu.Unlock()
			continue
		}
		if !exists {
			sess = newICMPConn(t.listener, raddr, echo.ID, false)
			t.sessions[key] = sess
			t.mu.Unlock()

			select {
			case t.connCh <- sess:
			case <-t.done:
				sess.Close()
				return
			}
		} else {
			t.mu.Unlock()
		}

		if flag == flagFIN {
			sess.deliverFIN()
		} else {
			sess.deliver(payload)
		}
	}
}

// Accept returns the next inbound ICMP connection. Blocks until available.
func (t *ICMPTransport) Accept() (net.Conn, error) {
	t.mu.Lock()
	pc := t.listener
	t.mu.Unlock()

	if pc == nil {
		return nil, errors.New("icmp transport: not listening")
	}

	select {
	case conn := <-t.connCh:
		return conn, nil
	case <-t.done:
		return nil, transport.ErrTransportClosed
	}
}

// Dial connects to an ICMP endpoint at addr and returns a net.Conn.
// For "udp4" mode, addr is "host:port". For "ip4:icmp", addr is an IP.
func (t *ICMPTransport) Dial(_ context.Context, addr string, _ *tls.Config) (net.Conn, error) {
	clientAddr := ""
	if t.UseUDP {
		clientAddr = "0.0.0.0:0"
	}
	pc, err := t.openPacketConn(clientAddr)
	if err != nil {
		return nil, fmt.Errorf("icmp transport dial: %w", err)
	}

	remoteAddr, err := t.resolveAddr(addr)
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("icmp resolve addr %s: %w", addr, err)
	}

	sessionID := rand.IntN(65534) + 1
	conn := newICMPConn(pc, remoteAddr, sessionID, true)
	go conn.clientRecvLoop()

	return conn, nil
}

// Close shuts down the ICMP transport. Safe to call multiple times.
func (t *ICMPTransport) Close() error {
	var err error
	t.closeOnce.Do(func() {
		close(t.done)

		t.mu.Lock()
		pc := t.listener
		sessions := make([]*icmpConn, 0, len(t.sessions))
		for _, s := range t.sessions {
			sessions = append(sessions, s)
		}
		t.sessions = make(map[string]*icmpConn)
		t.mu.Unlock()

		for _, s := range sessions {
			s.Close()
		}
		if pc != nil {
			err = pc.Close()
		}
	})
	return err
}

// Addr returns the actual listen address after Listen.
func (t *ICMPTransport) Addr() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.addr
}

// ---------------------------------------------------------------------------
// icmpConn — net.Conn over ICMP echo packets
// ---------------------------------------------------------------------------

type icmpConn struct {
	pc        net.PacketConn
	remote    net.Addr
	sessionID int
	ownsPC    bool // true = client side (close PC on Close)

	mu      sync.Mutex
	cond    *sync.Cond
	readBuf []byte
	readEOF bool
	closed  bool
	seq     int

	writeMu   sync.Mutex
	done      chan struct{}
	closeOnce sync.Once
}

func newICMPConn(pc net.PacketConn, remote net.Addr, id int, ownsPC bool) *icmpConn {
	c := &icmpConn{
		pc:        pc,
		remote:    remote,
		sessionID: id,
		ownsPC:    ownsPC,
		done:      make(chan struct{}),
	}
	c.cond = sync.NewCond(&c.mu)
	return c
}

// deliver appends data to the read buffer and signals waiting readers.
func (c *icmpConn) deliver(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	if len(data) > 0 {
		c.readBuf = append(c.readBuf, data...)
	}
	c.cond.Signal()
}

// deliverFIN signals that the peer has closed the connection.
func (c *icmpConn) deliverFIN() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readEOF = true
	c.cond.Broadcast()
}

// clientRecvLoop reads ICMP packets on the client's own PacketConn.
func (c *icmpConn) clientRecvLoop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-c.done:
			return
		default:
		}

		if err := c.pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			select {
			case <-c.done:
			default:
			}
			return
		}

		n, _, err := c.pc.ReadFrom(buf)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			select {
			case <-c.done:
			default:
			}
			return
		}

		msg, err := goicmp.ParseMessage(protocolICMP, buf[:n])
		if err != nil {
			continue
		}

		echo, ok := msg.Body.(*goicmp.Echo)
		if !ok || len(echo.Data) == 0 {
			continue
		}

		flag := echo.Data[0]
		payload := echo.Data[1:]

		if flag == flagFIN {
			c.deliverFIN()
		} else {
			c.deliver(payload)
		}
	}
}

// Read reads tunnel data from the ICMP connection.
func (c *icmpConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for len(c.readBuf) == 0 {
		if c.readEOF || c.closed {
			return 0, io.EOF
		}
		c.cond.Wait()
	}

	n := copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

// Write sends tunnel data over ICMP echo packets. Large writes are
// fragmented into maxPayload-sized chunks.
func (c *icmpConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	select {
	case <-c.done:
		return 0, io.ErrClosedPipe
	default:
	}

	total := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > maxPayload {
			chunk = chunk[:maxPayload]
		}

		c.mu.Lock()
		c.seq++
		seq := c.seq
		c.mu.Unlock()

		data := make([]byte, 1+len(chunk))
		data[0] = flagData
		copy(data[1:], chunk)

		msg := &goicmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &goicmp.Echo{
				ID:   c.sessionID & 0xFFFF,
				Seq:  seq & 0xFFFF,
				Data: data,
			},
		}

		wb, err := msg.Marshal(nil)
		if err != nil {
			return total, fmt.Errorf("icmp marshal: %w", err)
		}

		if _, err := c.pc.WriteTo(wb, c.remote); err != nil {
			return total, fmt.Errorf("icmp write: %w", err)
		}

		total += len(chunk)
		b = b[len(chunk):]
	}

	return total, nil
}

// sendFIN sends a close signal to the peer (best-effort).
func (c *icmpConn) sendFIN() {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.mu.Lock()
	c.seq++
	seq := c.seq
	c.mu.Unlock()

	msg := &goicmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &goicmp.Echo{
			ID:   c.sessionID & 0xFFFF,
			Seq:  seq & 0xFFFF,
			Data: []byte{flagFIN},
		},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return
	}
	_, _ = c.pc.WriteTo(wb, c.remote)
}

// Close closes the ICMP connection.
func (c *icmpConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.sendFIN()

		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		c.cond.Broadcast()

		close(c.done)

		if c.ownsPC {
			err = c.pc.Close()
		}
	})
	return err
}

// LocalAddr returns the local network address.
func (c *icmpConn) LocalAddr() net.Addr {
	return c.pc.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *icmpConn) RemoteAddr() net.Addr {
	return c.remote
}

// SetDeadline is a no-op (ICMP connections use internal timeouts).
func (c *icmpConn) SetDeadline(_ time.Time) error { return nil }

// SetReadDeadline is a no-op.
func (c *icmpConn) SetReadDeadline(_ time.Time) error { return nil }

// SetWriteDeadline is a no-op.
func (c *icmpConn) SetWriteDeadline(_ time.Time) error { return nil }

// isTimeout returns true if err is a network timeout.
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
