// Package transport defines the universal Transport interface for Burrow and
// provides shared utilities (backoff, registry) used by all transport
// implementations. Concrete transports live in sub-packages (ws/, raw/).
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"math"
	"math/rand/v2"
	"net"
	"time"
)

// ErrTransportClosed is returned when the transport has been shut down.
var ErrTransportClosed = errors.New("transport: closed")

// Transport is the universal interface for all burrow transports.
// Every transport produces net.Conn that yamux can multiplex.
type Transport interface {
	// Listen starts accepting connections on addr. Non-blocking.
	Listen(ctx context.Context, addr string, tlsCfg *tls.Config) error
	// Accept returns the next inbound connection. Blocks until available.
	Accept() (net.Conn, error)
	// Dial connects to a remote transport endpoint and returns a net.Conn.
	Dial(ctx context.Context, addr string, tlsCfg *tls.Config) (net.Conn, error)
	// Close shuts down the transport.
	Close() error
	// Addr returns the actual listen address after Listen.
	Addr() string
	// Name returns the transport identifier (e.g. "ws", "dns", "icmp", "tcp", "raw").
	Name() string
}

// Registry maps transport names to constructor functions.
// Sub-packages register themselves via init().
var Registry = map[string]func() Transport{}

// Backoff computes exponential backoff with jitter, capped at 30s.
func Backoff(base time.Duration, attempt int) time.Duration {
	delay := float64(base) * math.Pow(2, float64(attempt))
	maxDelay := float64(30 * time.Second)
	if delay > maxDelay {
		delay = maxDelay
	}
	// Add 10% jitter
	jitter := delay * 0.1 * (rand.Float64()*2 - 1)
	return time.Duration(delay + jitter)
}
