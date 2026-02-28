// Package http provides an HTTP-based transport for Burrow tunnel traffic.
// It simulates a persistent bidirectional net.Conn over sequential HTTP
// requests, making C2 traffic look like normal web browsing. Unlike the ws
// transport, this uses pure HTTP request/response polling — no WebSocket
// upgrade — so it works through proxies that block WebSocket.
package http

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/loudmumble/burrow/internal/transport"
)

func init() {
	transport.Registry["http"] = func() transport.Transport {
		return NewHTTPTransport()
	}
}

// defaultPathPrefix is the URL path prefix for transport endpoints.
const defaultPathPrefix = "/t/"

// longPollTimeout is how long the server waits for outbound data before
// returning 204 No Content on a GET /t/data poll.
const longPollTimeout = 30 * time.Second

// chanBufSize is the buffer size for data channels in stream pairs.
const chanBufSize = 64

// connectResponse is the JSON body returned by POST /t/connect.
type connectResponse struct {
	ID string `json:"id"`
}

// ---------------------------------------------------------------------------
// streamConn — virtual net.Conn backed by buffered channels
// ---------------------------------------------------------------------------

// streamConn implements net.Conn over a pair of byte-slice channels.
// One side writes to outCh and reads from inCh; the peer sees the reverse.
type streamConn struct {
	id     string
	inCh   chan []byte // data arriving for this side
	outCh  chan []byte // data sent by this side
	local  net.Addr
	remote net.Addr

	mu           sync.Mutex
	closed       bool
	closeCh      chan struct{}
	readBuf      []byte // leftover bytes from a previous read
	readDeadline time.Time
}

func newStreamConn(id string, inCh, outCh chan []byte, local, remote net.Addr) *streamConn {
	return &streamConn{
		id:      id,
		inCh:    inCh,
		outCh:   outCh,
		local:   local,
		remote:  remote,
		closeCh: make(chan struct{}),
	}
}

func (c *streamConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, io.EOF
	}
	// Drain leftover buffer first.
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		c.mu.Unlock()
		return n, nil
	}
	deadline := c.readDeadline
	c.mu.Unlock()

	// Build a timer channel for deadline support.
	var timer *time.Timer
	var timerCh <-chan time.Time
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return 0, &timeoutError{}
		}
		timer = time.NewTimer(d)
		timerCh = timer.C
		defer timer.Stop()
	}

	select {
	case data, ok := <-c.inCh:
		if !ok {
			return 0, io.EOF
		}
		n := copy(p, data)
		if n < len(data) {
			c.mu.Lock()
			c.readBuf = append(c.readBuf, data[n:]...)
			c.mu.Unlock()
		}
		return n, nil
	case <-c.closeCh:
		return 0, io.EOF
	case <-timerCh:
		return 0, &timeoutError{}
	}
}

func (c *streamConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, errors.New("write on closed connection")
	}
	c.mu.Unlock()

	// Copy the slice so the caller can reuse p.
	buf := make([]byte, len(p))
	copy(buf, p)

	select {
	case c.outCh <- buf:
		return len(p), nil
	case <-c.closeCh:
		return 0, errors.New("write on closed connection")
	}
}

func (c *streamConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	close(c.closeCh)
	return nil
}

func (c *streamConn) LocalAddr() net.Addr              { return c.local }
func (c *streamConn) RemoteAddr() net.Addr             { return c.remote }
func (c *streamConn) SetDeadline(t time.Time) error    { return c.SetReadDeadline(t) }
func (c *streamConn) SetWriteDeadline(time.Time) error { return nil } // writes are non-blocking or fail fast
func (c *streamConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}

// timeoutError satisfies net.Error for deadline support.
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true } //nolint:staticcheck // net.Error compat

// httpAddr implements net.Addr for HTTP transport addresses.
type httpAddr struct {
	addr string
}

func (a httpAddr) Network() string { return "http" }
func (a httpAddr) String() string  { return a.addr }

// ---------------------------------------------------------------------------
// clientConn — client-side virtual net.Conn using HTTP polling
// ---------------------------------------------------------------------------

// clientConn wraps HTTP request/response as a net.Conn for the dialing side.
type clientConn struct {
	streamID string
	baseURL  string
	client   *http.Client
	local    net.Addr
	remote   net.Addr

	mu           sync.Mutex
	closed       bool
	closeCh      chan struct{}
	readBuf      []byte
	readDeadline time.Time
}

func (c *clientConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, io.EOF
	}
	// Drain leftover buffer first.
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		c.mu.Unlock()
		return n, nil
	}
	deadline := c.readDeadline
	c.mu.Unlock()

	// Build context with deadline for the HTTP request.
	ctx := context.Background()
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return 0, &timeoutError{}
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}

	url := c.baseURL + "data?s=" + c.streamID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("http read: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		// Check if the connection was closed.
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if closed {
			return 0, io.EOF
		}
		return 0, fmt.Errorf("http read: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		// No data available — retry (the caller, typically yamux, will retry).
		return 0, nil
	}
	if resp.StatusCode == http.StatusGone {
		return 0, io.EOF
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("http read: unexpected status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("http read body: %w", err)
	}
	if len(data) == 0 {
		return 0, nil
	}

	n := copy(p, data)
	if n < len(data) {
		c.mu.Lock()
		c.readBuf = append(c.readBuf, data[n:]...)
		c.mu.Unlock()
	}
	return n, nil
}

func (c *clientConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, errors.New("write on closed connection")
	}
	c.mu.Unlock()

	url := c.baseURL + "data?s=" + c.streamID
	resp, err := c.client.Post(url, "application/octet-stream", bytes.NewReader(p))
	if err != nil {
		return 0, fmt.Errorf("http write: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusGone {
		return 0, errors.New("write on closed connection")
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("http write: unexpected status %d", resp.StatusCode)
	}
	return len(p), nil
}

func (c *clientConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.closeCh)
	c.mu.Unlock()

	// Best-effort close notification to server.
	url := c.baseURL + "close?s=" + c.streamID
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil // best effort
	}
	resp.Body.Close()
	return nil
}

func (c *clientConn) LocalAddr() net.Addr              { return c.local }
func (c *clientConn) RemoteAddr() net.Addr             { return c.remote }
func (c *clientConn) SetDeadline(t time.Time) error    { return c.SetReadDeadline(t) }
func (c *clientConn) SetWriteDeadline(time.Time) error { return nil }
func (c *clientConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}

// ---------------------------------------------------------------------------
// HTTPTransport — implements transport.Transport
// ---------------------------------------------------------------------------

// HTTPTransport implements transport.Transport over HTTP request/response
// polling. Server-side streams are managed via an HTTP server; client-side
// streams use an http.Client to poll for data.
type HTTPTransport struct {
	httpServer *http.Server
	listener   net.Listener
	connCh     chan net.Conn // accepted connections queued here
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	addr       string
	closed     chan struct{}

	// streams maps stream-id → server-side streamConn (the server's half).
	streams sync.Map
}

// NewHTTPTransport creates a new HTTP transport.
func NewHTTPTransport() *HTTPTransport {
	return &HTTPTransport{
		connCh: make(chan net.Conn, 64),
		closed: make(chan struct{}),
	}
}

// Name returns the transport identifier.
func (t *HTTPTransport) Name() string { return "http" }

// Listen starts an HTTP(S) server on addr. Non-blocking.
func (t *HTTPTransport) Listen(ctx context.Context, addr string, tlsCfg *tls.Config) error {
	t.mu.Lock()
	t.ctx, t.cancel = context.WithCancel(ctx)
	t.mu.Unlock()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("http transport listen: %w", err)
	}
	ln = transport.WrapListener(ln)

	t.mu.Lock()
	t.listener = ln
	t.addr = ln.Addr().String()
	t.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc(defaultPathPrefix+"connect", t.handleConnect)
	mux.HandleFunc(defaultPathPrefix+"data", t.handleData)
	mux.HandleFunc(defaultPathPrefix+"close", t.handleClose)
	mux.HandleFunc("/", t.handleCover)

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
			log.Printf("[http] server error: %v", serveErr)
		}
		close(t.closed)
	}()

	return nil
}

// handleCover serves a fake page on GET / for cover traffic.
func (t *HTTPTransport) handleCover(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>`)
}

// handleConnect creates a new stream and returns its ID.
// POST /t/connect
func (t *HTTPTransport) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	t.mu.Lock()
	srvCtx := t.ctx
	t.mu.Unlock()
	if srvCtx == nil || srvCtx.Err() != nil {
		http.Error(w, "server closed", http.StatusServiceUnavailable)
		return
	}

	// Generate random stream ID.
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	streamID := hex.EncodeToString(idBytes)

	// Create channel pair: clientToServer and serverToClient.
	clientToServer := make(chan []byte, chanBufSize)
	serverToClient := make(chan []byte, chanBufSize)

	localAddr := httpAddr{addr: t.Addr()}
	remoteAddr := httpAddr{addr: r.RemoteAddr}

	// Server-side conn: reads from clientToServer, writes to serverToClient.
	srvConn := newStreamConn(streamID, clientToServer, serverToClient, localAddr, remoteAddr)

	// Store both channels and the server conn for the HTTP handlers.
	t.streams.Store(streamID, &serverStream{
		conn:           srvConn,
		clientToServer: clientToServer,
		serverToClient: serverToClient,
	})

	// Send response with stream ID.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(connectResponse{ID: streamID})

	// Enqueue the server-side conn for Accept().
	select {
	case t.connCh <- srvConn:
	case <-srvCtx.Done():
		srvConn.Close()
	}
}

// serverStream holds both channel directions and the server-side conn.
type serverStream struct {
	conn           *streamConn
	clientToServer chan []byte // client writes here, server reads
	serverToClient chan []byte // server writes here, client reads
}

// handleData handles both POST (client→server) and GET (server→client) data.
// POST /t/data?s=<stream-id> — client sends data
// GET  /t/data?s=<stream-id> — client polls for data (long-poll)
func (t *HTTPTransport) handleData(w http.ResponseWriter, r *http.Request) {
	streamID := r.URL.Query().Get("s")
	if streamID == "" {
		http.Error(w, "missing stream id", http.StatusBadRequest)
		return
	}

	val, ok := t.streams.Load(streamID)
	if !ok {
		w.WriteHeader(http.StatusGone)
		return
	}
	ss := val.(*serverStream)

	switch r.Method {
	case http.MethodPost:
		t.handleDataPost(w, r, ss)
	case http.MethodGet:
		t.handleDataGet(w, ss)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (t *HTTPTransport) handleDataPost(w http.ResponseWriter, r *http.Request, ss *serverStream) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	if len(data) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Write data into the clientToServer channel.
	select {
	case ss.clientToServer <- data:
		w.WriteHeader(http.StatusOK)
	case <-ss.conn.closeCh:
		w.WriteHeader(http.StatusGone)
	}
}

func (t *HTTPTransport) handleDataGet(w http.ResponseWriter, ss *serverStream) {
	// Long-poll: wait up to longPollTimeout for data from server→client.
	timer := time.NewTimer(longPollTimeout)
	defer timer.Stop()

	select {
	case data, ok := <-ss.serverToClient:
		if !ok {
			w.WriteHeader(http.StatusGone)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	case <-ss.conn.closeCh:
		w.WriteHeader(http.StatusGone)
	case <-timer.C:
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleClose closes a stream.
// POST /t/close?s=<stream-id>
func (t *HTTPTransport) handleClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	streamID := r.URL.Query().Get("s")
	if streamID == "" {
		http.Error(w, "missing stream id", http.StatusBadRequest)
		return
	}

	val, ok := t.streams.LoadAndDelete(streamID)
	if !ok {
		w.WriteHeader(http.StatusGone)
		return
	}
	ss := val.(*serverStream)
	ss.conn.Close()
	w.WriteHeader(http.StatusOK)
}

// Accept returns the next inbound virtual connection. Blocks.
func (t *HTTPTransport) Accept() (net.Conn, error) {
	t.mu.Lock()
	ctx := t.ctx
	t.mu.Unlock()

	if ctx == nil {
		return nil, errors.New("http transport: not listening")
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

// Dial connects to an HTTP transport server and returns a virtual net.Conn.
// addr should be host:port (plain HTTP) or host:port (HTTPS when tlsCfg != nil).
func (t *HTTPTransport) Dial(ctx context.Context, addr string, tlsCfg *tls.Config) (net.Conn, error) {
	scheme := "http"
	httpTransport := &http.Transport{}
	if tlsCfg != nil {
		scheme = "https"
		httpTransport.TLSClientConfig = tlsCfg
	}

	client := &http.Client{
		Transport: httpTransport,
		Timeout:   60 * time.Second,
	}

	baseURL := fmt.Sprintf("%s://%s%s", scheme, addr, defaultPathPrefix)

	// POST /t/connect to create a stream.
	connectURL := baseURL + "connect"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, connectURL, nil)
	if err != nil {
		return nil, fmt.Errorf("http dial: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http dial %s: %w", addr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http dial: connect returned %d", resp.StatusCode)
	}

	var cr connectResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return nil, fmt.Errorf("http dial: decode connect response: %w", err)
	}
	if cr.ID == "" {
		return nil, errors.New("http dial: empty stream id")
	}

	// Build a long-poll-friendly client (no global timeout).
	pollClient := &http.Client{
		Transport: httpTransport,
	}

	conn := &clientConn{
		streamID: cr.ID,
		baseURL:  baseURL,
		client:   pollClient,
		local:    httpAddr{addr: "client"},
		remote:   httpAddr{addr: addr},
		closeCh:  make(chan struct{}),
	}
	return conn, nil
}

// Close gracefully shuts down the HTTP transport with a 5-second timeout.
func (t *HTTPTransport) Close() error {
	t.mu.Lock()
	cancel := t.cancel
	srv := t.httpServer
	t.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	// Close all active streams.
	t.streams.Range(func(key, val any) bool {
		ss := val.(*serverStream)
		ss.conn.Close()
		t.streams.Delete(key)
		return true
	})

	if srv != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		return srv.Shutdown(shutdownCtx)
	}
	return nil
}

// Addr returns the actual listen address after Listen.
func (t *HTTPTransport) Addr() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.addr
}
