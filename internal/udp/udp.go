// Package udp provides standalone UDP port forwarding. It listens on a local
// UDP port, forwards datagrams to a remote UDP target, and relays responses
// back to the original source address.
package udp

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/loudmumble/burrow/internal/transport"
)

// Status represents forwarder lifecycle state.
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

const (
	defaultTimeout = 60 * time.Second
	reaperInterval = 10 * time.Second
	readBufSize    = 65535
)

// udpClient tracks a single client's forwarding state.
type udpClient struct {
	remoteConn *net.UDPConn
	lastActive time.Time
	srcAddr    *net.UDPAddr
}

// Forwarder is a UDP port forwarder. It binds a local UDP socket and
// forwards datagrams to a remote target, relaying responses back.
type Forwarder struct {
	ListenAddr string
	RemoteAddr string
	Status     Status
	Timeout    time.Duration

	logger   *log.Logger
	conn     *net.UDPConn
	bytesIn  atomic.Int64
	bytesOut atomic.Int64
	clients  map[string]*udpClient
	mu       sync.Mutex
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// NewForwarder creates a UDP forwarder with the default idle timeout (60s).
func NewForwarder(listen, remote string) *Forwarder {
	return NewForwarderWithTimeout(listen, remote, defaultTimeout)
}

// NewForwarderWithTimeout creates a UDP forwarder with a custom idle timeout.
func NewForwarderWithTimeout(listen, remote string, timeout time.Duration) *Forwarder {
	return &Forwarder{
		ListenAddr: listen,
		RemoteAddr: remote,
		Status:     StatusPending,
		Timeout:    timeout,
		logger:     log.Default(),
		clients:    make(map[string]*udpClient),
	}
}

// Start begins forwarding UDP traffic (non-blocking).
func (f *Forwarder) Start() error {
	return f.StartWithContext(context.Background())
}

// StartWithContext begins forwarding with context-based lifecycle.
func (f *Forwarder) StartWithContext(ctx context.Context) error {
	resNet := "udp"
	if !strings.Contains(f.ListenAddr, "[") {
		resNet = "udp4"
	}
	laddr, err := net.ResolveUDPAddr(resNet, f.ListenAddr)
	if err != nil {
		f.Status = StatusError
		return fmt.Errorf("udp resolve listen %s: %w", f.ListenAddr, err)
	}

	network := "udp"
	if !strings.Contains(f.ListenAddr, "[") {
		network = "udp4"
	}
	conn, err := net.ListenUDP(network, laddr)
	if err == nil {
		transport.TunePacketConn(conn)
	}
	if err != nil {
		f.Status = StatusError
		return fmt.Errorf("udp listen on %s: %w", f.ListenAddr, err)
	}

	ctx, cancel := context.WithCancel(ctx)

	f.mu.Lock()
	f.conn = conn
	f.cancel = cancel
	f.Status = StatusActive
	f.mu.Unlock()

	f.logger.Printf("[udp] %s -> %s active", f.ListenAddr, f.RemoteAddr)

	f.wg.Add(2)
	go func() {
		defer f.wg.Done()
		f.readLoop(ctx)
	}()
	go func() {
		defer f.wg.Done()
		f.reaper(ctx)
	}()

	return nil
}

// Stop shuts down the forwarder and all client connections.
func (f *Forwarder) Stop() {
	f.mu.Lock()
	f.Status = StatusClosed
	cancel := f.cancel
	conn := f.conn
	clients := make(map[string]*udpClient, len(f.clients))
	for k, v := range f.clients {
		clients[k] = v
	}
	f.clients = make(map[string]*udpClient)
	f.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if conn != nil {
		conn.Close()
	}
	for _, c := range clients {
		c.remoteConn.Close()
	}
	f.wg.Wait()
}

// Addr returns the actual listener address (useful when using port 0).
func (f *Forwarder) Addr() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conn != nil {
		return f.conn.LocalAddr().String()
	}
	return ""
}

// BytesTransferred returns (bytesIn, bytesOut).
func (f *Forwarder) BytesTransferred() (int64, int64) {
	return f.bytesIn.Load(), f.bytesOut.Load()
}

// readLoop reads datagrams from the listening socket and forwards them.
func (f *Forwarder) readLoop(ctx context.Context) {
	buf := make([]byte, readBufSize)
	for {
		// Set a short deadline so we can check context cancellation.
		f.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, srcAddr, err := f.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// Timeout is expected; loop back to check context.
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		f.bytesIn.Add(int64(n))

		client, err := f.getOrCreateClient(ctx, srcAddr)
		if err != nil {
			f.logger.Printf("[udp] create client for %s: %v", srcAddr, err)
			continue
		}

		f.mu.Lock()
		client.lastActive = time.Now()
		f.mu.Unlock()

		_, err = client.remoteConn.Write(buf[:n])
		if err != nil {
			f.logger.Printf("[udp] forward to %s: %v", f.RemoteAddr, err)
		}
	}
}

// getOrCreateClient returns an existing udpClient for the source address,
// or creates a new one with a dedicated connection to the remote target.
func (f *Forwarder) getOrCreateClient(ctx context.Context, srcAddr *net.UDPAddr) (*udpClient, error) {
	key := srcAddr.String()

	f.mu.Lock()
	if c, ok := f.clients[key]; ok {
		f.mu.Unlock()
		return c, nil
	}
	f.mu.Unlock()

	resNet := "udp"
	if !strings.Contains(f.RemoteAddr, "[") {
		resNet = "udp4"
	}
	raddr, err := net.ResolveUDPAddr(resNet, f.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve remote %s: %w", f.RemoteAddr, err)
	}

	network := "udp"
	if !strings.Contains(f.RemoteAddr, "[") {
		network = "udp4"
	}
	remoteConn, err := net.DialUDP(network, nil, raddr)
	if err == nil {
		transport.TuneConn(remoteConn)
	}
	if err != nil {
		return nil, fmt.Errorf("dial remote %s: %w", f.RemoteAddr, err)
	}

	c := &udpClient{
		remoteConn: remoteConn,
		lastActive: time.Now(),
		srcAddr:    srcAddr,
	}

	f.mu.Lock()
	// Double-check after acquiring lock.
	if existing, ok := f.clients[key]; ok {
		f.mu.Unlock()
		remoteConn.Close()
		return existing, nil
	}
	f.clients[key] = c
	f.mu.Unlock()

	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		f.clientReadLoop(ctx, c)
	}()

	return c, nil
}

// clientReadLoop reads responses from the remote target and relays them
// back to the original source address via the listening socket.
func (f *Forwarder) clientReadLoop(ctx context.Context, c *udpClient) {
	buf := make([]byte, readBufSize)
	for {
		c.remoteConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := c.remoteConn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Check if this client was reaped.
				f.mu.Lock()
				_, alive := f.clients[c.srcAddr.String()]
				f.mu.Unlock()
				if !alive {
					return
				}
				continue
			}
			return
		}

		f.bytesOut.Add(int64(n))

		f.mu.Lock()
		c.lastActive = time.Now()
		f.mu.Unlock()

		_, err = f.conn.WriteToUDP(buf[:n], c.srcAddr)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			f.logger.Printf("[udp] relay to %s: %v", c.srcAddr, err)
		}
	}
}

// reaper periodically closes idle client connections.
func (f *Forwarder) reaper(ctx context.Context) {
	ticker := time.NewTicker(reaperInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.reapIdle()
		}
	}
}

// reapIdle removes clients that have been idle for longer than the timeout.
func (f *Forwarder) reapIdle() {
	now := time.Now()
	f.mu.Lock()
	defer f.mu.Unlock()

	for key, c := range f.clients {
		if now.Sub(c.lastActive) > f.Timeout {
			c.remoteConn.Close()
			delete(f.clients, key)
		}
	}
}
