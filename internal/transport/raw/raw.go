// Package raw provides a plain TCP/TLS transport for Burrow tunnel traffic.
// It is the default transport and produces net.Conn directly from the
// standard library's net and crypto/tls packages.
package raw

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/loudmumble/burrow/internal/transport"
)

func init() {
	transport.Registry["raw"] = func() transport.Transport { return NewRawTransport() }
}

// RawTransport implements transport.Transport over plain TCP/TLS connections.
type RawTransport struct {
	listener  net.Listener
	mu        sync.Mutex
	addr      string
	done      chan struct{}
	closeOnce sync.Once
}

// NewRawTransport creates a new raw TCP/TLS transport.
func NewRawTransport() *RawTransport {
	return &RawTransport{
		done: make(chan struct{}),
	}
}

// Name returns the transport identifier.
func (t *RawTransport) Name() string { return "raw" }

// Listen starts a TCP or TLS listener on addr. Non-blocking.
func (t *RawTransport) Listen(_ context.Context, addr string, tlsCfg *tls.Config) error {
	var ln net.Listener
	var err error

	if tlsCfg != nil {
		ln, err = tls.Listen("tcp", addr, tlsCfg)
	} else {
		ln, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("raw transport listen: %w", err)
	}

	t.mu.Lock()
	t.listener = ln
	t.addr = ln.Addr().String()
	t.mu.Unlock()

	return nil
}

// Accept returns the next inbound TCP/TLS connection. Blocks.
func (t *RawTransport) Accept() (net.Conn, error) {
	t.mu.Lock()
	ln := t.listener
	t.mu.Unlock()

	if ln == nil {
		return nil, errors.New("raw transport: not listening")
	}

	conn, err := ln.Accept()
	if err != nil {
		select {
		case <-t.done:
			return nil, transport.ErrTransportClosed
		default:
			return nil, fmt.Errorf("raw transport accept: %w", err)
		}
	}
	return conn, nil
}

// Dial connects to a remote TCP/TLS endpoint. Uses a 10-second timeout
// for the underlying TCP connection.
func (t *RawTransport) Dial(ctx context.Context, addr string, tlsCfg *tls.Config) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if tlsCfg != nil {
		return tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	}
	return dialer.DialContext(ctx, "tcp", addr)
}

// Close shuts down the listener. Safe to call multiple times.
func (t *RawTransport) Close() error {
	var err error
	t.closeOnce.Do(func() {
		close(t.done)
		t.mu.Lock()
		ln := t.listener
		t.mu.Unlock()
		if ln != nil {
			err = ln.Close()
		}
	})
	return err
}

// Addr returns the actual listen address after Listen.
func (t *RawTransport) Addr() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.addr
}
