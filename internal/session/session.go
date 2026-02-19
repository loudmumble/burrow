// Package session provides agent session management for the Burrow proxy server.
//
// Manager tracks connected agents, their tunnels, routes, and implements
// web.SessionProvider for the WebUI dashboard.
package session

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/loudmumble/burrow/internal/web"
)

// Info holds metadata about a connected agent session.
type Info struct {
	ID        string    `json:"id"`
	Hostname  string    `json:"hostname"`
	OS        string    `json:"os"`
	IPs       []string  `json:"ips"`
	PID       int       `json:"pid"`
	Remote    string    `json:"remote"`
	CreatedAt time.Time `json:"created_at"`
	Active    bool      `json:"active"`
}

// Manager tracks all active agent sessions.
type Manager struct {
	sessions map[string]*Info
	mu       sync.RWMutex
}

// NewManager creates a new session manager.
func NewManager() *Manager {
	return &Manager{
		sessions: make(map[string]*Info),
	}
}

// List returns all active sessions.
func (m *Manager) List() []*Info {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*Info, 0, len(m.sessions))
	for _, s := range m.sessions {
		result = append(result, s)
	}
	return result
}

// Get returns a session by ID, or nil if not found.
func (m *Manager) Get(id string) *Info {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[id]
}

// Add registers a new session.
func (m *Manager) Add(info *Info) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[info.ID] = info
}

// Remove deletes a session by ID.
func (m *Manager) Remove(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
}

// Count returns the number of active sessions.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// ListSessions implements web.SessionProvider.
func (m *Manager) ListSessions() []web.SessionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]web.SessionInfo, 0, len(m.sessions))
	for _, s := range m.sessions {
		result = append(result, web.SessionInfo{
			ID:        s.ID,
			Hostname:  s.Hostname,
			OS:        s.OS,
			IPs:       s.IPs,
			Active:    s.Active,
			CreatedAt: s.CreatedAt.Format(time.RFC3339),
		})
	}
	return result
}

// GetSession implements web.SessionProvider.
func (m *Manager) GetSession(id string) (web.SessionInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	if !ok {
		return web.SessionInfo{}, false
	}
	return web.SessionInfo{
		ID:        s.ID,
		Hostname:  s.Hostname,
		OS:        s.OS,
		IPs:       s.IPs,
		Active:    s.Active,
		CreatedAt: s.CreatedAt.Format(time.RFC3339),
	}, true
}

// GetTunnels implements web.SessionProvider.
// TODO: Track tunnels per session and return real data.
func (m *Manager) GetTunnels(_ string) []web.TunnelInfo {
	return nil
}

// GetRoutes implements web.SessionProvider.
// TODO: Track routes per session and return real data.
func (m *Manager) GetRoutes(_ string) []web.RouteInfo {
	return nil
}

// AddTunnel implements web.SessionProvider.
// TODO: Send MsgTunnelRequest to agent and return result.
func (m *Manager) AddTunnel(_, _, _, _, _ string) (web.TunnelInfo, error) {
	return web.TunnelInfo{}, fmt.Errorf("not implemented")
}

// RemoveTunnel implements web.SessionProvider.
// TODO: Send MsgTunnelClose to agent.
func (m *Manager) RemoveTunnel(_, _ string) error {
	return fmt.Errorf("not implemented")
}

// AddRoute implements web.SessionProvider.
// TODO: Send MsgRouteAdd to agent.
func (m *Manager) AddRoute(_, _ string) (web.RouteInfo, error) {
	return web.RouteInfo{}, fmt.Errorf("not implemented")
}

// RemoveRoute implements web.SessionProvider.
// TODO: Send MsgRouteRemove to agent.
func (m *Manager) RemoveRoute(_, _ string) error {
	return fmt.Errorf("not implemented")
}

// Server listens for incoming agent connections and creates mux sessions.
type Server struct {
	// ListenAddr is the TCP address to listen on.
	ListenAddr string
	// TLSConfig is optional; if nil, connections are plain TCP.
	TLSConfig *tls.Config
	// Manager tracks connected sessions.
	Manager *Manager
	// OnConnection is called for each accepted agent connection.
	// TODO: Replace with full agent handler that reads handshake, creates mux session, etc.
	OnConnection func(conn net.Conn)

	listener net.Listener
	mu       sync.Mutex
	done     chan struct{}
}

// NewServer creates a Server with the given configuration.
func NewServer(listenAddr string, tlsCfg *tls.Config, mgr *Manager) *Server {
	return &Server{
		ListenAddr: listenAddr,
		TLSConfig:  tlsCfg,
		Manager:    mgr,
		done:       make(chan struct{}),
	}
}

// Start begins accepting connections. Blocks until Stop is called or an error occurs.
func (s *Server) Start() error {
	var ln net.Listener
	var err error

	if s.TLSConfig != nil {
		ln, err = tls.Listen("tcp", s.ListenAddr, s.TLSConfig)
	} else {
		ln, err = net.Listen("tcp", s.ListenAddr)
	}
	if err != nil {
		return fmt.Errorf("session server listen: %w", err)
	}

	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return nil // clean shutdown
			default:
				return fmt.Errorf("session server accept: %w", err)
			}
		}
		if s.OnConnection != nil {
			go s.OnConnection(conn)
		} else {
			// TODO: default handler — read handshake, create mux session, register with Manager
			conn.Close()
		}
	}
}

// Addr returns the actual listen address. Useful when binding to port 0.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return ""
}

// Stop gracefully shuts down the server.
func (s *Server) Stop() error {
	close(s.done)
	s.mu.Lock()
	ln := s.listener
	s.mu.Unlock()
	if ln != nil {
		return ln.Close()
	}
	return nil
}
