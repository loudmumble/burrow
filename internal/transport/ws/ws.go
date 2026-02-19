// Package ws provides a WebSocket-based transport for Burrow tunnel traffic
// over HTTP/HTTPS. It wraps nhooyr.io/websocket connections as net.Conn for
// seamless integration with yamux multiplexing.
package ws

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/loudmumble/burrow/internal/transport"
	"nhooyr.io/websocket"
)

func init() {
	transport.Registry["ws"] = func() transport.Transport { return NewWSTransport() }
}

// WSTransport implements transport.Transport over WebSocket connections.
// On the server side it runs an HTTP(S) server that upgrades to WebSocket;
// on the client side it dials a ws:// or wss:// endpoint.
type WSTransport struct {
	httpServer *http.Server
	listener   net.Listener
	connCh     chan net.Conn
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	addr       string
	closed     chan struct{}
}

// NewWSTransport creates a new WebSocket transport.
func NewWSTransport() *WSTransport {
	return &WSTransport{
		connCh: make(chan net.Conn, 64),
		closed: make(chan struct{}),
	}
}

// Name returns the transport identifier.
func (t *WSTransport) Name() string { return "ws" }

// Listen starts an HTTP(S) server on addr that upgrades incoming requests to
// WebSocket. Connections are available via Accept. Non-blocking.
func (t *WSTransport) Listen(ctx context.Context, addr string, tlsCfg *tls.Config) error {
	t.mu.Lock()
	t.ctx, t.cancel = context.WithCancel(ctx)
	t.mu.Unlock()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("ws transport listen: %w", err)
	}

	t.mu.Lock()
	t.listener = ln
	t.addr = ln.Addr().String()
	t.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/", t.handleWebSocket)

	t.httpServer = &http.Server{
		Handler: mux,
	}

	go func() {
		var serveErr error
		if tlsCfg != nil {
			tlsLn := tls.NewListener(ln, tlsCfg)
			serveErr = t.httpServer.Serve(tlsLn)
		} else {
			serveErr = t.httpServer.Serve(ln)
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			_ = serveErr
		}
		close(t.closed)
	}()

	return nil
}

func (t *WSTransport) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // Origin checking handled at auth layer
	})
	if err != nil {
		return
	}

	t.mu.Lock()
	srvCtx := t.ctx
	t.mu.Unlock()

	netConn := WebSocketNetConn(srvCtx, wsConn)
	select {
	case t.connCh <- netConn:
	case <-srvCtx.Done():
		netConn.Close()
	}
}

// Accept returns the next inbound WebSocket connection as a net.Conn. Blocks.
func (t *WSTransport) Accept() (net.Conn, error) {
	t.mu.Lock()
	ctx := t.ctx
	t.mu.Unlock()

	if ctx == nil {
		return nil, errors.New("ws transport: not listening")
	}

	select {
	case conn := <-t.connCh:
		return conn, nil
	case <-ctx.Done():
		return nil, transport.ErrTransportClosed
	case <-t.closed:
		return nil, transport.ErrTransportClosed
	}
}

// Dial connects to a WebSocket server at addr and returns a net.Conn.
// addr should be a ws:// or wss:// URL.
func (t *WSTransport) Dial(ctx context.Context, addr string, tlsCfg *tls.Config) (net.Conn, error) {
	opts := &websocket.DialOptions{}
	if tlsCfg != nil {
		opts.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
		}
	}

	wsConn, _, err := websocket.Dial(ctx, addr, opts)
	if err != nil {
		return nil, fmt.Errorf("websocket dial %s: %w", addr, err)
	}

	return WebSocketNetConn(ctx, wsConn), nil
}

// DialWithRetry connects with exponential backoff.
// maxRetries of 0 means try once (no retries). Negative means infinite retries.
func (t *WSTransport) DialWithRetry(ctx context.Context, addr string, tlsCfg *tls.Config, baseDelay time.Duration, maxRetries int) (net.Conn, error) {
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

		conn, err := t.Dial(ctx, addr, tlsCfg)
		if err == nil {
			return conn, nil
		}
		lastErr = err

		if maxRetries >= 0 && attempt >= maxRetries {
			return nil, fmt.Errorf("max retries (%d) exceeded: %w", maxRetries, lastErr)
		}

		delay := transport.Backoff(baseDelay, attempt)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, fmt.Errorf("context cancelled during backoff: %w", lastErr)
		}
	}
}

// Close gracefully shuts down the WebSocket transport with a 5-second timeout.
func (t *WSTransport) Close() error {
	t.mu.Lock()
	cancel := t.cancel
	srv := t.httpServer
	t.mu.Unlock()

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

// Addr returns the actual listen address after Listen. Useful when
// the listen address uses port 0.
func (t *WSTransport) Addr() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.addr
}

// WebSocketNetConn wraps a websocket.Conn as a net.Conn using the nhooyr.io
// websocket library's NetConn adapter with binary message framing.
func WebSocketNetConn(ctx context.Context, ws *websocket.Conn) net.Conn {
	return websocket.NetConn(ctx, ws, websocket.MessageBinary)
}
