// Package pivot implements multi-hop TCP pivot chains for routing traffic
// through a series of intermediate hosts using SOCKS5 CONNECT tunneling.
package pivot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/loudmumble/burrow/internal/relay"
	"github.com/loudmumble/burrow/internal/transport"
)

// Hop represents a single node in a pivot chain.
type Hop struct {
	Host    string
	Port    int
	User    string
	Key     string
	latency time.Duration
	active  bool
}

// Endpoint returns host:port string.
func (h *Hop) Endpoint() string {
	return fmt.Sprintf("%s:%d", h.Host, h.Port)
}

// HopStatus tracks the state of a hop.
type HopStatus int

const (
	HopPending HopStatus = iota
	HopActive
	HopFailed
	HopClosed
)

// Chain orchestrates a sequence of TCP hops to reach a final destination.
// For single-hop chains, traffic is routed directly via TCP.
// For multi-hop chains, hops[0..N-2] are SOCKS5 proxies and hops[N-1] is
// the final target. Traffic is routed through nested SOCKS5 CONNECT tunnels.
type Chain struct {
	hops        []Hop
	active      bool
	latency     time.Duration
	mu          sync.Mutex
	logger      *log.Logger
	listener    net.Listener
	listenAddr  string
	dialTimeout time.Duration
	connWg      sync.WaitGroup
	bytesTotal  atomic.Int64
}

// NewChain creates a pivot chain from a list of hops.
func NewChain(hops []Hop) *Chain {
	return &Chain{
		hops:        hops,
		logger:      log.Default(),
		dialTimeout: 10 * time.Second,
	}
}

// socks5Handshake performs an RFC 1928 compliant SOCKS5 no-auth greeting
// and CONNECT request on an existing connection to tunnel to the target.
func socks5Handshake(conn net.Conn, target string, timeout time.Duration) error {
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	// Phase 1: Greeting — offer NO AUTH (0x00)
	greeting := []byte{0x05, 0x01, 0x00}
	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("socks5 greeting write: %w", err)
	}

	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, greetResp); err != nil {
		return fmt.Errorf("socks5 greeting read: %w (target=%s)", err, target)
	}
	if greetResp[0] != 0x05 {
		return fmt.Errorf("socks5 greeting: bad version %d (expected 5, target=%s)", greetResp[0], target)
	}
	if greetResp[1] != 0x00 {
		return fmt.Errorf("socks5 greeting rejected: ver=%d method=%d (target=%s, wanted method=0 for no-auth)", greetResp[0], greetResp[1], target)
	}

	// Phase 2: Build and send CONNECT request
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("socks5 parse target: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("socks5 parse port: %w", err)
	}

	var req []byte
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		// ATYP 0x01 — IPv4
		req = make([]byte, 10)
		req[0] = 0x05
		req[1] = 0x01 // CONNECT
		req[2] = 0x00 // RSV
		req[3] = 0x01 // ATYP IPv4
		copy(req[4:8], ip4)
		req[8] = byte(port >> 8)
		req[9] = byte(port)
	} else if ip != nil {
		// ATYP 0x04 — IPv6
		req = make([]byte, 22)
		req[0] = 0x05
		req[1] = 0x01
		req[2] = 0x00
		req[3] = 0x04
		copy(req[4:20], ip.To16())
		req[20] = byte(port >> 8)
		req[21] = byte(port)
	} else {
		// ATYP 0x03 — Domain
		dLen := len(host)
		req = make([]byte, 7+dLen)
		req[0] = 0x05
		req[1] = 0x01
		req[2] = 0x00
		req[3] = 0x03
		req[4] = byte(dLen)
		copy(req[5:5+dLen], host)
		req[5+dLen] = byte(port >> 8)
		req[6+dLen] = byte(port)
	}

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 connect write: %w", err)
	}

	// Phase 3: Read CONNECT response — VER(1) REP(1) RSV(1) ATYP(1) BND.ADDR(var) BND.PORT(2)
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("socks5 connect response: %w", err)
	}
	if header[0] != 0x05 {
		return fmt.Errorf("socks5 connect: bad version %d", header[0])
	}
	if header[1] != 0x00 {
		return fmt.Errorf("socks5 connect: reply code %d", header[1])
	}

	// Consume variable-length BND.ADDR + BND.PORT based on ATYP
	switch header[3] {
	case 0x01: // IPv4: 4 bytes addr + 2 bytes port
		if _, err := io.ReadFull(conn, make([]byte, 6)); err != nil {
			return fmt.Errorf("socks5 read bnd ipv4: %w", err)
		}
	case 0x03: // Domain: 1 byte len + domain + 2 bytes port
		dLen := make([]byte, 1)
		if _, err := io.ReadFull(conn, dLen); err != nil {
			return fmt.Errorf("socks5 read bnd domain len: %w", err)
		}
		if _, err := io.ReadFull(conn, make([]byte, int(dLen[0])+2)); err != nil {
			return fmt.Errorf("socks5 read bnd domain: %w", err)
		}
	case 0x04: // IPv6: 16 bytes addr + 2 bytes port
		if _, err := io.ReadFull(conn, make([]byte, 18)); err != nil {
			return fmt.Errorf("socks5 read bnd ipv6: %w", err)
		}
	default:
		return fmt.Errorf("socks5 connect: unsupported bnd atyp %d", header[3])
	}

	return nil
}

func (c *Chain) dialThroughChain(target string) (net.Conn, error) {
	network := transport.NetworkForAddr(c.hops[0].Endpoint(), "tcp")
	conn, err := net.DialTimeout(network, c.hops[0].Endpoint(), c.dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial first hop %s: %w", c.hops[0].Endpoint(), err)
	}

	for i := 1; i < len(c.hops); i++ {
		if err := socks5Handshake(conn, c.hops[i].Endpoint(), c.dialTimeout); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 hop %d (%s): %w", i+1, c.hops[i].Endpoint(), err)
		}
	}

	// Final SOCKS5 CONNECT to the target
	if err := socks5Handshake(conn, target, c.dialTimeout); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 target %s: %w", target, err)
	}

	return conn, nil
}

// Establish connects through each hop sequentially, measuring latency.
// For single-hop chains, a direct TCP connection validates the hop.
// For multi-hop chains, the first hop is connected via TCP and each
// subsequent hop is verified via SOCKS5 CONNECT through the tunnel.
func (c *Chain) Establish() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.latency = 0
	// Verify every hop in the chain, measuring first hop connection latency
	start := time.Now()
	network := transport.NetworkForAddr(c.hops[0].Endpoint(), "tcp")
	conn, err := net.DialTimeout(network, c.hops[0].Endpoint(), c.dialTimeout)
	if err != nil {
		c.hops[0].active = false
		return fmt.Errorf("hop 1 (%s) connection failed: %w", c.hops[0].Endpoint(), err)
	}
	defer conn.Close()

	c.hops[0].latency = time.Since(start)
	c.hops[0].active = true
	c.latency += c.hops[0].latency

	for i := 1; i < len(c.hops); i++ {
		start := time.Now()
		if err := socks5Handshake(conn, c.hops[i].Endpoint(), c.dialTimeout); err != nil {
			c.hops[i].active = false
			return fmt.Errorf("hop %d (%s) verification failed: %w", i+1, c.hops[i].Endpoint(), err)
		}
		c.hops[i].latency = time.Since(start)
		c.hops[i].active = true
		c.latency += c.hops[i].latency
	}

	c.active = true
	return nil
}

func (c *Chain) teardownFrom(fromIdx int) {
	for j := fromIdx; j >= 0; j-- {
		c.hops[j].active = false
	}
}

// StartListener opens a local SOCKS-like listener that forwards through the chain.
func (c *Chain) StartListener(ctx context.Context, listenAddr string) error {
	network := transport.NetworkForAddr(listenAddr, "tcp")
	ln, err := net.Listen(network, listenAddr)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.listener = ln
	c.listenAddr = ln.Addr().String()
	c.mu.Unlock()

	c.logger.Printf("[pivot] listener on %s -> chain of %d hops", c.listenAddr, len(c.hops))

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	go c.acceptLoop(ctx, ln)
	return nil
}

func (c *Chain) acceptLoop(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		transport.TuneConn(conn)
		c.connWg.Add(1)
		go func() {
			defer c.connWg.Done()
			c.relayThrough(ctx, conn)
		}()
	}
}

// relayThrough forwards a local connection through the chain to the last hop.
// For multi-hop chains, a new SOCKS5 tunnel is created via dialThroughChain.
// For single-hop chains, a direct TCP connection is made to the target.
func (c *Chain) relayThrough(ctx context.Context, local net.Conn) {
	defer local.Close()

	c.mu.Lock()
	if !c.active || len(c.hops) == 0 {
		c.mu.Unlock()
		return
	}
	lastHop := c.hops[len(c.hops)-1]
	nHops := len(c.hops)
	c.mu.Unlock()

	var remote net.Conn
	var err error
 	if nHops > 1 {
		remote, err = c.dialThroughChain(lastHop.Endpoint())
	} else {
		network := transport.NetworkForAddr(lastHop.Endpoint(), "tcp")
		remote, err = net.DialTimeout(network, lastHop.Endpoint(), c.dialTimeout)
	}
	if err != nil {
		c.logger.Printf("[pivot] relay dial to %s failed: %v", lastHop.Endpoint(), err)
		return
	}
	defer remote.Close()

	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		n, _ := relay.CopyBuffered(dst, src)
		c.bytesTotal.Add(n)
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}

	}

	go cp(remote, local)
	go cp(local, remote)
	<-done
	time.Sleep(50 * time.Millisecond)
	remote.Close()
	local.Close()
	<-done

}

// Route returns a human-readable route string.
func (c *Chain) Route() string {
	if len(c.hops) == 0 {
		return "(empty chain)"
	}
	route := ""
	for i, hop := range c.hops {
		if i > 0 {
			route += " -> "
		}
		route += hop.Endpoint()
	}
	return route
}

// Latency returns the total measured latency across all hops.
func (c *Chain) Latency() time.Duration {
	return c.latency
}

// Depth returns the number of hops in the chain.
func (c *Chain) Depth() int {
	return len(c.hops)
}

// IsActive returns whether the chain has been established.
func (c *Chain) IsActive() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active
}

// Dial connects through the chain to a target address.
// For multi-hop chains, a new SOCKS5 tunnel is created via dialThroughChain.
// For single-hop chains, a direct TCP connection is made.
func (c *Chain) Dial(network, addr string) (net.Conn, error) {
	c.mu.Lock()
	if !c.active {
		c.mu.Unlock()
		return nil, fmt.Errorf("chain not established")
	}
	nHops := len(c.hops)
	c.mu.Unlock()

	if nHops > 1 {
		return c.dialThroughChain(addr)
	}

	conn, err := net.DialTimeout(network, addr, c.dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial through chain: %w", err)
	}
	return conn, nil
}

// Close tears down all hops and the listener.
// For multi-hop chains, all hops share the underlying TCP connection
// through hops[0], so closing it tears down the entire tunnel.
func (c *Chain) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.active = false

	if c.listener != nil {
		c.listener.Close()
	}

	for i := range c.hops {
		c.hops[i].active = false
	}

	c.connWg.Wait()
	return nil
}
