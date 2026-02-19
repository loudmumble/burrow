// Package mux provides stream multiplexing over a single connection using yamux.
//
// Allows multiple logical streams (each implementing net.Conn) over one TCP or
// WebSocket connection. Used for agent-proxy communication in Burrow.
package mux

import (
	"io"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

// Default yamux configuration values.
const (
	defaultAcceptBacklog          = 256
	defaultKeepAliveInterval      = 30 * time.Second
	defaultConnectionWriteTimeout = 10 * time.Second
	defaultMaxStreamWindowSize    = 256 * 1024
)

// Session wraps a yamux.Session, providing multiplexed streams over a single connection.
type Session struct {
	session *yamux.Session
}

// defaultConfig returns the yamux configuration used for all sessions.
func defaultConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.AcceptBacklog = defaultAcceptBacklog
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = defaultKeepAliveInterval
	cfg.ConnectionWriteTimeout = defaultConnectionWriteTimeout
	cfg.MaxStreamWindowSize = defaultMaxStreamWindowSize
	// Suppress yamux's internal logging. Only one of Logger/LogOutput may be set.
	cfg.LogOutput = io.Discard
	cfg.Logger = nil
	return cfg
}

// NewServerSession creates a server-side multiplexed session from an existing connection.
// The server side accepts streams initiated by the client.
func NewServerSession(conn net.Conn) (*Session, error) {
	sess, err := yamux.Server(conn, defaultConfig())
	if err != nil {
		return nil, err
	}
	return &Session{session: sess}, nil
}

// NewClientSession creates a client-side multiplexed session from an existing connection.
// The client side initiates streams that the server accepts.
func NewClientSession(conn net.Conn) (*Session, error) {
	sess, err := yamux.Client(conn, defaultConfig())
	if err != nil {
		return nil, err
	}
	return &Session{session: sess}, nil
}

// Open opens a new multiplexed stream. The returned net.Conn can be used
// for bidirectional communication. Only the client side should call Open.
func (s *Session) Open() (net.Conn, error) {
	return s.session.Open()
}

// Accept waits for and returns the next incoming stream. The returned net.Conn
// can be used for bidirectional communication. Only the server side should call Accept.
func (s *Session) Accept() (net.Conn, error) {
	return s.session.Accept()
}

// Close closes the multiplexed session and the underlying connection.
func (s *Session) Close() error {
	return s.session.Close()
}

// IsClosed returns true if the session has been closed.
func (s *Session) IsClosed() bool {
	return s.session.IsClosed()
}

// NumStreams returns the number of currently active streams.
func (s *Session) NumStreams() int {
	return s.session.NumStreams()
}
