// Package proxy implements HTTP forward proxy with CONNECT tunnel support.
//
// Handles both HTTP CONNECT method (for HTTPS tunneling) and regular
// HTTP forward proxy requests (GET/POST etc.) with hop-by-hop header
// stripping and optional Basic proxy authentication.
package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/loudmumble/burrow/internal/relay"
)

// HTTPProxyConfig holds HTTP proxy server configuration.
type HTTPProxyConfig struct {
	ListenAddr     string
	Username       string
	Password       string
	DialTimeout    time.Duration
	ReadTimeout    time.Duration
	MaxConnections int
	Logger         *log.Logger
	// Dialer overrides the default net.Dial for outbound connections.
	// When set, all HTTP proxy traffic is routed through this function
	// instead of directly dialing the target. Used for routing through
	// yamux agent sessions (non-root mode).
	Dialer func(ctx context.Context, network, addr string) (net.Conn, error)
}

// DefaultHTTPProxyConfig returns an HTTPProxyConfig with sensible defaults.
func DefaultHTTPProxyConfig() *HTTPProxyConfig {
	return &HTTPProxyConfig{
		ListenAddr:     "127.0.0.1:8080",
		DialTimeout:    10 * time.Second,
		ReadTimeout:    30 * time.Second,
		MaxConnections: 1024,
	}
}

// HTTPProxy is a forward HTTP proxy server with CONNECT tunnel support.
type HTTPProxy struct {
	config      *HTTPProxyConfig
	listener    net.Listener
	logger      *log.Logger
	activeConns atomic.Int64
	totalConns  atomic.Int64
	bytesIn     atomic.Int64
	bytesOut    atomic.Int64
	mu          sync.Mutex
	connWg      sync.WaitGroup
}

// NewHTTPProxy creates a new HTTP proxy server.
func NewHTTPProxy(addr string, port int, username, password string) *HTTPProxy {
	cfg := DefaultHTTPProxyConfig()
	cfg.ListenAddr = fmt.Sprintf("%s:%d", addr, port)
	cfg.Username = username
	cfg.Password = password
	return NewHTTPProxyWithConfig(cfg)
}

// NewHTTPProxyWithConfig creates an HTTP proxy server with full configuration.
func NewHTTPProxyWithConfig(cfg *HTTPProxyConfig) *HTTPProxy {
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}
	return &HTTPProxy{
		config: cfg,
		logger: logger,
	}
}

// Start begins listening for HTTP proxy connections. Blocks until context is cancelled.
func (p *HTTPProxy) Start() error {
	return p.StartWithContext(context.Background())
}

// StartWithContext begins listening with context-based lifecycle control.
func (p *HTTPProxy) StartWithContext(ctx context.Context) error {
	ln, err := net.Listen("tcp", p.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("http-proxy listen: %w", err)
	}

	p.mu.Lock()
	p.listener = ln
	p.mu.Unlock()

	p.logger.Printf("[http-proxy] listening on %s", p.config.ListenAddr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			p.logger.Printf("[http-proxy] accept error: %v", err)
			continue
		}

		if p.config.MaxConnections > 0 && p.activeConns.Load() >= int64(p.config.MaxConnections) {
			conn.Close()
			continue
		}

		p.activeConns.Add(1)
		p.totalConns.Add(1)
		p.connWg.Add(1)

		go func() {
			defer p.connWg.Done()
			defer p.activeConns.Add(-1)
			p.handleConnection(ctx, conn)
		}()
	}
}

// Stop gracefully shuts down the proxy server.
func (p *HTTPProxy) Stop() {
	p.mu.Lock()
	ln := p.listener
	p.mu.Unlock()

	if ln != nil {
		ln.Close()
	}
	p.connWg.Wait()
}

// Addr returns the listener address, or empty string if not listening.
func (p *HTTPProxy) Addr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener != nil {
		return p.listener.Addr().String()
	}
	return ""
}

// Stats returns server statistics.
func (p *HTTPProxy) Stats() (active, total, bytesIn, bytesOut int64) {
	return p.activeConns.Load(), p.totalConns.Load(), p.bytesIn.Load(), p.bytesOut.Load()
}

// hopByHopHeaders are headers that should be stripped when forwarding
// HTTP requests, per RFC 2616 section 13.5.1.
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// handleConnection processes a single HTTP proxy client connection.
func (p *HTTPProxy) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	if p.config.ReadTimeout > 0 {
		conn.SetDeadline(time.Now().Add(p.config.ReadTimeout))
	}

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		p.logger.Printf("[http-proxy] read request error from %s: %v", conn.RemoteAddr(), err)
		return
	}

	// Check proxy authentication
	if p.config.Username != "" {
		if !p.checkAuth(req) {
			p.sendResponse(conn, http.StatusProxyAuthRequired, "Proxy Authentication Required")
			p.logger.Printf("[http-proxy] auth failed from %s", conn.RemoteAddr())
			return
		}
	}

	if req.Method == http.MethodConnect {
		p.handleConnect(ctx, conn, req)
	} else {
		p.handleHTTP(ctx, conn, req)
	}
}

// checkAuth validates Proxy-Authorization header with Basic auth.
func (p *HTTPProxy) checkAuth(req *http.Request) bool {
	authHeader := req.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		return false
	}

	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(authHeader[len(prefix):])
	if err != nil {
		return false
	}

	creds := string(decoded)
	idx := strings.IndexByte(creds, ':')
	if idx < 0 {
		return false
	}

	return creds[:idx] == p.config.Username && creds[idx+1:] == p.config.Password
}

// handleConnect handles HTTP CONNECT tunneling (for HTTPS).
func (p *HTTPProxy) handleConnect(ctx context.Context, conn net.Conn, req *http.Request) {
	target := req.Host
	if !strings.Contains(target, ":") {
		target = target + ":443"
	}

	var targetConn net.Conn
	var err error
	if p.config.Dialer != nil {
		targetConn, err = p.config.Dialer(ctx, "tcp", target)
	} else {
		dialer := net.Dialer{Timeout: p.config.DialTimeout}
		targetConn, err = dialer.DialContext(ctx, "tcp", target)
	}
	if err != nil {
		p.sendResponse(conn, http.StatusBadGateway, fmt.Sprintf("Bad Gateway: %v", err))
		p.logger.Printf("[http-proxy] CONNECT to %s failed: %v", target, err)
		return
	}
	defer targetConn.Close()

	// Send 200 Connection Established
	_, err = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		p.logger.Printf("[http-proxy] write 200 to %s failed: %v", conn.RemoteAddr(), err)
		return
	}

	// Clear deadline for relay phase
	conn.SetDeadline(time.Time{})

	p.logger.Printf("[http-proxy] CONNECT %s -> %s established", conn.RemoteAddr(), target)

	// Bidirectional relay
	p.httpRelay(ctx, conn, targetConn)
}

// handleHTTP handles regular HTTP forward proxy requests (GET, POST, etc.).
func (p *HTTPProxy) handleHTTP(ctx context.Context, conn net.Conn, req *http.Request) {
	// Ensure the URL is absolute
	if req.URL.Host == "" {
		p.sendResponse(conn, http.StatusBadRequest, "Bad Request: missing host")
		return
	}

	target := req.URL.Host
	if !strings.Contains(target, ":") {
		target = target + ":80"
	}

	var targetConn net.Conn
	var err error
	if p.config.Dialer != nil {
		targetConn, err = p.config.Dialer(ctx, "tcp", target)
	} else {
		dialer := net.Dialer{Timeout: p.config.DialTimeout}
		targetConn, err = dialer.DialContext(ctx, "tcp", target)
	}
	if err != nil {
		p.sendResponse(conn, http.StatusBadGateway, fmt.Sprintf("Bad Gateway: %v", err))
		p.logger.Printf("[http-proxy] connect to %s failed: %v", target, err)
		return
	}
	defer targetConn.Close()

	// Strip hop-by-hop headers
	for _, h := range hopByHopHeaders {
		req.Header.Del(h)
	}

	// Prevent req.Write from re-adding Connection: close
	req.Close = false

	// Convert absolute URL to relative for the upstream server
	req.RequestURI = ""

	// Write the request to target, tracking bytes
	cw := &countingWriter{w: targetConn, counter: &p.bytesIn}
	if err := req.Write(cw); err != nil {
		p.sendResponse(conn, http.StatusBadGateway, "Bad Gateway: failed to forward request")
		p.logger.Printf("[http-proxy] write to %s failed: %v", target, err)
		return
	}

	// Read response from target
	resp, err := http.ReadResponse(bufio.NewReader(targetConn), req)
	if err != nil {
		p.sendResponse(conn, http.StatusBadGateway, "Bad Gateway: failed to read response")
		p.logger.Printf("[http-proxy] read response from %s failed: %v", target, err)
		return
	}
	defer resp.Body.Close()

	// Strip hop-by-hop headers from response
	for _, h := range hopByHopHeaders {
		resp.Header.Del(h)
	}

	// Write response back to client, tracking bytes
	rcw := &countingWriter{w: conn, counter: &p.bytesOut}
	if err := resp.Write(rcw); err != nil {
		p.logger.Printf("[http-proxy] write response to %s failed: %v", conn.RemoteAddr(), err)
	}

	p.logger.Printf("[http-proxy] %s %s -> %d", req.Method, req.URL, resp.StatusCode)
}

// sendResponse writes a simple HTTP response to the client.
func (p *HTTPProxy) sendResponse(conn net.Conn, statusCode int, body string) {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n",
		statusCode, http.StatusText(statusCode), len(body))
	if statusCode == http.StatusProxyAuthRequired {
		resp += "Proxy-Authenticate: Basic realm=\"proxy\"\r\n"
	}
	resp += "\r\n" + body
	conn.Write([]byte(resp))
}

// httpRelay performs bidirectional data copying between two connections.
func (p *HTTPProxy) httpRelay(ctx context.Context, client, target net.Conn) {
	done := make(chan struct{}, 2)

	copyFunc := func(dst, src net.Conn, counter *atomic.Int64) {
		defer func() { done <- struct{}{} }()
		n, _ := relay.CopyBuffered(dst, src)
		counter.Add(n)
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}

	go copyFunc(target, client, &p.bytesIn)
	go copyFunc(client, target, &p.bytesOut)

	// Wait for either direction to finish or context cancellation
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// countingWriter wraps a writer and counts bytes written.
type countingWriter struct {
	w       io.Writer
	counter *atomic.Int64
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.counter.Add(int64(n))
	return n, err
}
