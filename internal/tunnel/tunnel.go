// Package tunnel provides TCP port forwarding (local, remote) and reverse
// tunnel connections with keepalive, auto-reconnect, and graceful shutdown.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Direction indicates whether a tunnel forwards traffic locally or remotely.
type Direction int

const (
	Local  Direction = iota // listen locally, forward to remote
	Remote                  // listen remotely, forward to local
)

// Status represents tunnel lifecycle state.
type Status int

const (
	StatusPending Status = iota
	StatusActive
	StatusClosed
	StatusError
)

func (s Status) String() string {
	switch s {
	case StatusPending:
		return "pending"
	case StatusActive:
		return "active"
	case StatusClosed:
		return "closed"
	case StatusError:
		return "error"
	default:
		return "unknown"
	}
}

// Tunnel manages a single TCP port-forwarding tunnel (local or remote).
type Tunnel struct {
	ListenAddr string
	RemoteAddr string
	Dir        Direction
	Status     Status

	listener    net.Listener
	logger      *log.Logger
	dialTimeout time.Duration
	mu          sync.Mutex
	connWg      sync.WaitGroup
	conns       []net.Conn
	bytesIn     atomic.Int64
	bytesOut    atomic.Int64
}

// NewTunnel creates a local-forward tunnel. Kept for backward compatibility with CLI.
func NewTunnel(lhost string, lport int, rhost string, rport int, protocol string) *Tunnel {
	return &Tunnel{
		ListenAddr:  fmt.Sprintf("%s:%d", lhost, lport),
		RemoteAddr:  fmt.Sprintf("%s:%d", rhost, rport),
		Dir:         Local,
		Status:      StatusPending,
		logger:      log.Default(),
		dialTimeout: 10 * time.Second,
	}
}

// NewLocalForward creates a tunnel that listens locally and forwards to remote.
func NewLocalForward(listen, remote string) *Tunnel {
	return &Tunnel{
		ListenAddr:  listen,
		RemoteAddr:  remote,
		Dir:         Local,
		Status:      StatusPending,
		logger:      log.Default(),
		dialTimeout: 10 * time.Second,
	}
}

// NewRemoteForward creates a tunnel that listens on the given address
// and forwards connections to the remote target.
func NewRemoteForward(listen, remote string) *Tunnel {
	return &Tunnel{
		ListenAddr:  listen,
		RemoteAddr:  remote,
		Dir:         Remote,
		Status:      StatusPending,
		logger:      log.Default(),
		dialTimeout: 10 * time.Second,
	}
}

// Start begins accepting connections on the listen address (non-blocking).
func (t *Tunnel) Start() error {
	return t.StartWithContext(context.Background())
}

// StartWithContext begins the tunnel with context-based lifecycle.
func (t *Tunnel) StartWithContext(ctx context.Context) error {
	ln, err := net.Listen("tcp", t.ListenAddr)
	if err != nil {
		t.Status = StatusError
		return fmt.Errorf("tunnel listen on %s: %w", t.ListenAddr, err)
	}

	t.mu.Lock()
	t.listener = ln
	t.Status = StatusActive
	t.mu.Unlock()

	t.logger.Printf("[tunnel] %s -> %s active", t.ListenAddr, t.RemoteAddr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	go t.acceptLoop(ctx)
	return nil
}

func (t *Tunnel) acceptLoop(ctx context.Context) {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}

		t.connWg.Add(1)
		go func() {
			defer t.connWg.Done()
			t.handleConn(ctx, conn)
		}()
	}
}

func (t *Tunnel) handleConn(ctx context.Context, local net.Conn) {
	defer local.Close()

	// Tune accepted connection.
	if tc, ok := local.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(4 * 1024 * 1024)
		_ = tc.SetWriteBuffer(4 * 1024 * 1024)
	}

	dialer := net.Dialer{Timeout: t.dialTimeout}
	remote, err := dialer.DialContext(ctx, "tcp", t.RemoteAddr)
	if err != nil {
		t.logger.Printf("[tunnel] dial %s failed: %v", t.RemoteAddr, err)
		return
	}
	defer remote.Close()

	// Tune dialed connection.
	if tc, ok := remote.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(4 * 1024 * 1024)
		_ = tc.SetWriteBuffer(4 * 1024 * 1024)
	}

	t.mu.Lock()
	t.conns = append(t.conns, local, remote)
	t.mu.Unlock()

	relay(local, remote, &t.bytesIn, &t.bytesOut)
}

// Stop closes the tunnel listener and all active connections.
func (t *Tunnel) Stop() {
	t.mu.Lock()
	t.Status = StatusClosed
	ln := t.listener
	conns := append([]net.Conn{}, t.conns...)
	t.conns = nil
	t.mu.Unlock()

	if ln != nil {
		ln.Close()
	}
	for _, c := range conns {
		c.Close()
	}
	t.connWg.Wait()
}

// Addr returns the actual listener address (useful when using port 0).
func (t *Tunnel) Addr() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.listener != nil {
		return t.listener.Addr().String()
	}
	return ""
}

// BytesTransferred returns (bytesIn, bytesOut).
func (t *Tunnel) BytesTransferred() (int64, int64) {
	return t.bytesIn.Load(), t.bytesOut.Load()
}

// ReverseConfig configures a reverse tunnel connector.
type ReverseConfig struct {
	AgentAddr         string
	LocalTarget       string
	KeepaliveInterval time.Duration
	BaseDelay         time.Duration
	MaxDelay          time.Duration
	MaxRetries        int
	Jitter            float64
	Logger            *log.Logger
}

// DefaultReverseConfig returns sensible defaults for reverse tunnels.
func DefaultReverseConfig() *ReverseConfig {
	return &ReverseConfig{
		KeepaliveInterval: 30 * time.Second,
		BaseDelay:         1 * time.Second,
		MaxDelay:          60 * time.Second,
		MaxRetries:        10,
		Jitter:            0.1,
	}
}

// ReverseTunnel connects outbound to an agent/controller and relays traffic.
// Implements keepalive heartbeats and exponential backoff reconnection.
type ReverseTunnel struct {
	config  *ReverseConfig
	logger  *log.Logger
	retries int
	mu      sync.Mutex
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	ln      net.Listener
}

// NewReverseTunnel creates a reverse tunnel (backward-compatible constructor).
func NewReverseTunnel(lhost string, lport int, thost string, tport int) *ReverseTunnel {
	cfg := DefaultReverseConfig()
	cfg.AgentAddr = fmt.Sprintf("%s:%d", lhost, lport)
	cfg.LocalTarget = fmt.Sprintf("%s:%d", thost, tport)
	return NewReverseTunnelWithConfig(cfg)
}

// NewReverseTunnelWithConfig creates a reverse tunnel with full configuration.
func NewReverseTunnelWithConfig(cfg *ReverseConfig) *ReverseTunnel {
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}
	return &ReverseTunnel{
		config: cfg,
		logger: logger,
	}
}

// Start begins the reverse tunnel listener (non-blocking).
func (rt *ReverseTunnel) Start() error {
	return rt.StartWithContext(context.Background())
}

// StartWithContext runs the reverse tunnel with context lifecycle.
// It listens on AgentAddr and forwards each connection to LocalTarget.
func (rt *ReverseTunnel) StartWithContext(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	rt.cancel = cancel

	ln, err := net.Listen("tcp", rt.config.AgentAddr)
	if err != nil {
		cancel()
		return fmt.Errorf("reverse tunnel listen: %w", err)
	}
	rt.ln = ln

	rt.logger.Printf("[reverse] listening on %s, forwarding to %s", rt.config.AgentAddr, rt.config.LocalTarget)

	rt.wg.Add(1)
	go func() {
		defer rt.wg.Done()
		rt.acceptLoop(ctx, ln)
	}()

	return nil
}

func (rt *ReverseTunnel) acceptLoop(ctx context.Context, ln net.Listener) {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		rt.wg.Add(1)
		go func() {
			defer rt.wg.Done()
			rt.handleIncoming(ctx, conn)
		}()
	}
}

func (rt *ReverseTunnel) handleIncoming(ctx context.Context, incoming net.Conn) {
	defer incoming.Close()

	// Tune accepted connection.
	if tc, ok := incoming.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(4 * 1024 * 1024)
		_ = tc.SetWriteBuffer(4 * 1024 * 1024)
	}

	target, err := net.DialTimeout("tcp", rt.config.LocalTarget, 10*time.Second)
	if err != nil {
		rt.logger.Printf("[reverse] dial %s failed: %v", rt.config.LocalTarget, err)
		return
	}
	defer target.Close()

	// Tune dialed connection.
	if tc, ok := target.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(4 * 1024 * 1024)
		_ = tc.SetWriteBuffer(4 * 1024 * 1024)
	}

	var bytesIn, bytesOut atomic.Int64
	relay(incoming, target, &bytesIn, &bytesOut)
}

// ConnectOutbound initiates a reverse connection to a remote controller
// with keepalive and auto-reconnect. This is for agent-mode operation.
func (rt *ReverseTunnel) ConnectOutbound(ctx context.Context) error {
	for attempt := 0; attempt <= rt.config.MaxRetries; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		conn, err := net.DialTimeout("tcp", rt.config.AgentAddr, 10*time.Second)
		if err != nil {
			delay := rt.backoffDelay(attempt)
			rt.logger.Printf("[reverse] connect attempt %d/%d to %s failed: %v (retry in %v)",
				attempt+1, rt.config.MaxRetries, rt.config.AgentAddr, err, delay)

			select {
			case <-time.After(delay):
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		rt.logger.Printf("[reverse] connected to %s", rt.config.AgentAddr)
		rt.retries = 0

		// Run keepalive + relay
		err = rt.maintainConnection(ctx, conn)
		conn.Close()

		if ctx.Err() != nil {
			return nil
		}

		rt.logger.Printf("[reverse] connection lost: %v, reconnecting...", err)
	}

	return fmt.Errorf("max retries (%d) exceeded connecting to %s", rt.config.MaxRetries, rt.config.AgentAddr)
}

func (rt *ReverseTunnel) maintainConnection(ctx context.Context, conn net.Conn) error {
	errCh := make(chan error, 1)

	go func() {
		ticker := time.NewTicker(rt.config.KeepaliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				// Send keepalive ping (1 byte)
				if _, err := conn.Write([]byte{0x00}); err != nil {
					errCh <- fmt.Errorf("keepalive failed: %w", err)
					return
				}
				conn.SetWriteDeadline(time.Time{})
			case <-ctx.Done():
				return
			}
		}
	}()

	// Read loop to detect disconnect
	go func() {
		buf := make([]byte, 4096)
		for {
			conn.SetReadDeadline(time.Now().Add(rt.config.KeepaliveInterval * 3))
			_, err := conn.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return nil
	}
}

func (rt *ReverseTunnel) backoffDelay(attempt int) time.Duration {
	delay := float64(rt.config.BaseDelay) * math.Pow(2, float64(attempt))
	if delay > float64(rt.config.MaxDelay) {
		delay = float64(rt.config.MaxDelay)
	}
	// Add jitter
	jitter := delay * rt.config.Jitter * (rand.Float64()*2 - 1)
	return time.Duration(delay + jitter)
}

// Stop shuts down the reverse tunnel.
func (rt *ReverseTunnel) Stop() {
	if rt.cancel != nil {
		rt.cancel()
	}
	if rt.ln != nil {
		rt.ln.Close()
	}
	rt.wg.Wait()
}

// Addr returns the listener address if listening, or empty string.
func (rt *ReverseTunnel) Addr() string {
	if rt.ln != nil {
		return rt.ln.Addr().String()
	}
	return ""
}

// relayBufSize is the buffer size for bidirectional relay (256KB for throughput).
const relayBufSize = 256 * 1024

// relayBufPool pools relay buffers to avoid per-connection allocations.
var relayBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, relayBufSize)
		return &b
	},
}

// relay performs bidirectional copy between two connections.
func relay(a, b net.Conn, bytesAB, bytesBA *atomic.Int64) {
	done := make(chan struct{}, 2)

	cp := func(dst, src net.Conn, counter *atomic.Int64) {
		defer func() { done <- struct{}{} }()
		bp := relayBufPool.Get().(*[]byte)
		n, _ := io.CopyBuffer(dst, src, *bp)
		relayBufPool.Put(bp)
		if counter != nil {
			counter.Add(n)
		}
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}

	go cp(b, a, bytesAB)
	go cp(a, b, bytesBA)

	<-done
}
