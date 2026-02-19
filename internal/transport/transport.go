// Package transport provides WebSocket-based transport for Burrow tunnel
// traffic over HTTP/HTTPS. It wraps nhooyr.io/websocket connections as
// net.Conn for seamless integration with existing tunnel infrastructure.
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"sync"
	"time"

	"nhooyr.io/websocket"
)

var (
	// ErrServerClosed is returned when the server has been stopped.
	ErrServerClosed = errors.New("transport server closed")
	// ErrNoHandler is returned when Server.Handler is nil.
	ErrNoHandler = errors.New("transport server: handler is nil")
)

// Server is an HTTP(S) server that upgrades connections to WebSocket
// and presents them as net.Conn to the Handler.
type Server struct {
	// ListenAddr is the TCP address to listen on (e.g. ":0" for random port).
	ListenAddr string
	// TLSCert enables HTTPS when set. If nil, serves plain HTTP.
	TLSCert *tls.Certificate
	// TLSConfig allows providing a full TLS configuration. If nil and TLSCert
	// is set, a basic config is created from TLSCert.
	TLSConfig *tls.Config
	// Handler is called for each accepted WebSocket connection, adapted as net.Conn.
	Handler func(conn net.Conn)

	httpServer *http.Server
	listener   net.Listener
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
}

// Start begins serving HTTP(S) and upgrading WebSocket connections. The server
// runs until ctx is cancelled or Stop is called.
func (s *Server) Start(ctx context.Context) error {
	if s.Handler == nil {
		return ErrNoHandler
	}

	s.mu.Lock()
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()

	ln, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return fmt.Errorf("transport server listen: %w", err)
	}

	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleWebSocket)

	s.httpServer = &http.Server{
		Handler: mux,
	}

	go func() {
		var serveErr error
		if s.TLSCert != nil || s.TLSConfig != nil {
			tlsCfg := s.tlsConfig()
			tlsLn := tls.NewListener(ln, tlsCfg)
			serveErr = s.httpServer.Serve(tlsLn)
		} else {
			serveErr = s.httpServer.Serve(ln)
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			// Unexpected error; log would go here in production.
			_ = serveErr
		}
	}()

	return nil
}

func (s *Server) tlsConfig() *tls.Config {
	if s.TLSConfig != nil {
		return s.TLSConfig
	}
	return &tls.Config{
		Certificates: []tls.Certificate{*s.TLSCert},
		MinVersion:   tls.VersionTLS12,
	}
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // Origin checking handled at auth layer
	})
	if err != nil {
		return
	}

	s.mu.Lock()
	srvCtx := s.ctx
	s.mu.Unlock()

	// Use the server's context so connections close on shutdown.
	netConn := WebSocketNetConn(srvCtx, wsConn)
	s.Handler(netConn)
}

// Stop gracefully shuts down the server with a 5-second timeout.
func (s *Server) Stop() error {
	s.mu.Lock()
	cancel := s.cancel
	srv := s.httpServer
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if srv != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		return srv.Shutdown(shutdownCtx)
	}
	return nil
}

// Addr returns the actual listen address. Useful when ListenAddr uses port 0.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return ""
}

// Client connects to a transport Server via WebSocket.
type Client struct {
	// ServerURL is the WebSocket URL to connect to (e.g. "ws://host:port" or "wss://host:port").
	ServerURL string
	// TLSConfig is optional TLS configuration for wss:// connections.
	TLSConfig *tls.Config
	// ReconnectBackoff is the base delay for exponential backoff (default: 1s).
	ReconnectBackoff time.Duration
}

// Connect dials the WebSocket server and returns a net.Conn adapter.
func (c *Client) Connect(ctx context.Context) (net.Conn, error) {
	opts := &websocket.DialOptions{}
	if c.TLSConfig != nil {
		opts.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: c.TLSConfig,
			},
		}
	}

	wsConn, _, err := websocket.Dial(ctx, c.ServerURL, opts)
	if err != nil {
		return nil, fmt.Errorf("websocket dial %s: %w", c.ServerURL, err)
	}

	return WebSocketNetConn(ctx, wsConn), nil
}

// ConnectWithRetry dials the WebSocket server with exponential backoff.
// maxRetries of 0 means try once (no retries). Negative means infinite retries.
func (c *Client) ConnectWithRetry(ctx context.Context, maxRetries int) (net.Conn, error) {
	baseDelay := c.ReconnectBackoff
	if baseDelay <= 0 {
		baseDelay = time.Second
	}

	var lastErr error
	for attempt := 0; ; attempt++ {
		if ctx.Err() != nil {
			if lastErr != nil {
				return nil, fmt.Errorf("context cancelled after %d attempts: %w", attempt, lastErr)
			}
			return nil, ctx.Err()
		}

		conn, err := c.Connect(ctx)
		if err == nil {
			return conn, nil
		}
		lastErr = err

		if maxRetries >= 0 && attempt >= maxRetries {
			return nil, fmt.Errorf("max retries (%d) exceeded: %w", maxRetries, lastErr)
		}

		delay := backoff(baseDelay, attempt)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, fmt.Errorf("context cancelled during backoff: %w", lastErr)
		}
	}
}

// backoff computes exponential backoff with jitter, capped at 30s.
func backoff(base time.Duration, attempt int) time.Duration {
	delay := float64(base) * math.Pow(2, float64(attempt))
	maxDelay := float64(30 * time.Second)
	if delay > maxDelay {
		delay = maxDelay
	}
	// Add 10% jitter
	jitter := delay * 0.1 * (rand.Float64()*2 - 1)
	return time.Duration(delay + jitter)
}

// WebSocketNetConn wraps a websocket.Conn as a net.Conn using the nhooyr.io
// websocket library's NetConn adapter with binary message framing.
func WebSocketNetConn(ctx context.Context, ws *websocket.Conn) net.Conn {
	return websocket.NetConn(ctx, ws, websocket.MessageBinary)
}
