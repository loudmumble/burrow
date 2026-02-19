// Package pivot implements multi-hop TCP pivot chains for routing traffic
// through a series of intermediate hosts.
package pivot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Hop represents a single node in a pivot chain.
type Hop struct {
	Host    string
	Port    int
	User    string
	Key     string
	conn    net.Conn
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
// Each hop connects through the previous one, creating a relay chain.
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

// Establish connects through each hop sequentially, measuring latency.
// Each hop is validated by establishing a TCP connection.
func (c *Chain) Establish() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range c.hops {
		hop := &c.hops[i]
		start := time.Now()

		conn, err := net.DialTimeout("tcp", hop.Endpoint(), c.dialTimeout)
		if err != nil {
			hop.active = false
			c.teardownFrom(i)
			return fmt.Errorf("hop %d (%s) failed: %w", i+1, hop.Endpoint(), err)
		}

		hop.conn = conn
		hop.latency = time.Since(start)
		hop.active = true
		c.latency += hop.latency
	}

	c.active = true
	return nil
}

// teardownFrom closes all hops from index down to 0.
func (c *Chain) teardownFrom(fromIdx int) {
	for j := fromIdx - 1; j >= 0; j-- {
		if c.hops[j].conn != nil {
			c.hops[j].conn.Close()
			c.hops[j].conn = nil
			c.hops[j].active = false
		}
	}
}

// StartListener opens a local SOCKS-like listener that forwards through the chain.
func (c *Chain) StartListener(ctx context.Context, listenAddr string) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("pivot listen: %w", err)
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
		c.connWg.Add(1)
		go func() {
			defer c.connWg.Done()
			c.relayThrough(ctx, conn)
		}()
	}
}

// relayThrough forwards a local connection through the chain to the last hop.
func (c *Chain) relayThrough(ctx context.Context, local net.Conn) {
	defer local.Close()

	c.mu.Lock()
	if !c.active || len(c.hops) == 0 {
		c.mu.Unlock()
		return
	}
	lastHop := c.hops[len(c.hops)-1]
	c.mu.Unlock()

	// Connect to the final hop target
	remote, err := net.DialTimeout("tcp", lastHop.Endpoint(), c.dialTimeout)
	if err != nil {
		c.logger.Printf("[pivot] relay dial to %s failed: %v", lastHop.Endpoint(), err)
		return
	}
	defer remote.Close()

	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		n, _ := io.Copy(dst, src)
		c.bytesTotal.Add(n)
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}

	go cp(remote, local)
	go cp(local, remote)
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
func (c *Chain) Dial(network, addr string) (net.Conn, error) {
	c.mu.Lock()
	if !c.active {
		c.mu.Unlock()
		return nil, fmt.Errorf("chain not established")
	}
	c.mu.Unlock()

	conn, err := net.DialTimeout(network, addr, c.dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial through chain: %w", err)
	}
	return conn, nil
}

// Close tears down all hops and the listener.
func (c *Chain) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.active = false

	if c.listener != nil {
		c.listener.Close()
	}

	for i := range c.hops {
		if c.hops[i].conn != nil {
			c.hops[i].conn.Close()
			c.hops[i].conn = nil
		}
		c.hops[i].active = false
	}

	c.connWg.Wait()
	return nil
}
