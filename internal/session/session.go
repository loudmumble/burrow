// Package session provides agent session management for the Burrow proxy server.
//
// Manager tracks connected agents, their tunnels, routes, and implements
// web.SessionProvider for the WebUI dashboard.
package session

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/loudmumble/burrow/internal/mux"
	"github.com/loudmumble/burrow/internal/protocol"
	"github.com/loudmumble/burrow/internal/tun"
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

// AgentConn holds the mux session and control stream for a connected agent.
type AgentConn struct {
	Info    *Info
	Mux     *mux.Session
	Ctrl    net.Conn
	tunnels map[string]*web.TunnelInfo
	routes  map[string]*web.RouteInfo
	mu      sync.RWMutex
	writeMu sync.Mutex

	bytesIn  atomic.Int64
	bytesOut atomic.Int64

	tunStream net.Conn    // yamux data stream for TUN packets
	tunActive bool
	tunReady  chan error  // signaled when data stream is ready
}

// Manager tracks all active agent sessions.
type Manager struct {
	sessions   map[string]*AgentConn
	mu         sync.RWMutex
	tunIface   *tun.Interface
	tunSession string           // which session owns TUN
	tunCancel  context.CancelFunc
	tunPrevHostname string
	tunPrevRoutes   []string
}

// NewManager creates a new session manager.
func NewManager() *Manager {
	return &Manager{
		sessions: make(map[string]*AgentConn),
	}
}

// Shutdown cleanly tears down all TUN state. Call on server exit.
func (m *Manager) Shutdown() {
	m.mu.RLock()
	sid := m.tunSession
	m.mu.RUnlock()
	if sid != "" {
		_ = m.StopTun(sid)
	}
}

// List returns all active sessions.
func (m *Manager) List() []*Info {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*Info, 0, len(m.sessions))
	for _, ac := range m.sessions {
		result = append(result, ac.Info)
	}
	return result
}

// Get returns a session by ID, or nil if not found.
func (m *Manager) Get(id string) *Info {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if ac, ok := m.sessions[id]; ok {
		return ac.Info
	}
	return nil
}

// Add registers a new session without a mux connection.
func (m *Manager) Add(info *Info) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[info.ID] = &AgentConn{
		Info:    info,
		tunnels: make(map[string]*web.TunnelInfo),
		routes:  make(map[string]*web.RouteInfo),
	}
}

// AddConn registers a new session with its mux session and control stream.
func (m *Manager) AddConn(info *Info, muxSess *mux.Session, ctrl net.Conn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[info.ID] = &AgentConn{
		Info:    info,
		Mux:     muxSess,
		Ctrl:    ctrl,
		tunnels: make(map[string]*web.TunnelInfo),
		routes:  make(map[string]*web.RouteInfo),
	}
}

// Remove deletes a session by ID. If TUN is active on this session, it is stopped first.
func (m *Manager) Remove(id string) {
	// If this session owns TUN, save state for auto-restore and stop it.
	m.mu.RLock()
	ownsTun := m.tunSession == id && m.tunIface != nil
	ac := m.sessions[id]
	m.mu.RUnlock()
	if ownsTun && ac != nil {
		// Save hostname and routes for TUN auto-restore on reconnect.
		ac.mu.RLock()
		prevRoutes := make([]string, 0, len(ac.routes))
		for cidr := range ac.routes {
			prevRoutes = append(prevRoutes, cidr)
		}
		ac.mu.RUnlock()
		m.mu.Lock()
		m.tunPrevHostname = ac.Info.Hostname
		m.tunPrevRoutes = prevRoutes
		m.mu.Unlock()
		_ = m.StopTun(id) // best-effort cleanup
	} else if ownsTun {
		_ = m.StopTun(id)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
}

// WasTunActive returns whether TUN was active for the given hostname
// before its session was removed.
func (m *Manager) WasTunActive(hostname string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tunPrevHostname == hostname
}

// ClearTunPrev clears the saved TUN auto-restore state.
func (m *Manager) ClearTunPrev() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tunPrevHostname = ""
	m.tunPrevRoutes = nil
}

// Count returns the number of active sessions.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// getConn returns the AgentConn for a session, or nil if not found.
func (m *Manager) getConn(id string) *AgentConn {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[id]
}

// WriteCtrl writes a protocol message to the control stream of the given session.
// It serializes access to the control stream to prevent interleaved writes.
func (m *Manager) WriteCtrl(sessionID string, msg *protocol.Message) error {
	ac := m.getConn(sessionID)
	if ac == nil || ac.Ctrl == nil {
		return fmt.Errorf("session %s not connected", sessionID)
	}
	ac.writeMu.Lock()
	defer ac.writeMu.Unlock()
	return protocol.WriteMessage(ac.Ctrl, msg)
}

// UpdateTunnelStatus updates a tunnel's status after receiving an ack from the agent.
func (m *Manager) UpdateTunnelStatus(sessionID, tunnelID, boundAddr, errStr string) {
	ac := m.getConn(sessionID)
	if ac == nil {
		return
	}
	ac.mu.Lock()
	defer ac.mu.Unlock()
	t, ok := ac.tunnels[tunnelID]
	if !ok {
		return
	}
	if errStr != "" {
		t.Active = false
		t.Error = errStr
	} else {
		t.Active = true
		t.Error = ""
		if boundAddr != "" {
			t.ListenAddr = boundAddr
		}
	}
}

// ListSessions implements web.SessionProvider.
func (m *Manager) ListSessions() []web.SessionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]web.SessionInfo, 0, len(m.sessions))
	for _, ac := range m.sessions {
		s := ac.Info
		result = append(result, web.SessionInfo{
			ID:        s.ID,
			Hostname:  s.Hostname,
			OS:        s.OS,
			IPs:       s.IPs,
			Active:    s.Active,
			CreatedAt: s.CreatedAt.Format(time.RFC3339),
			TunActive: m.tunSession == s.ID && m.tunIface != nil,
			BytesIn:   ac.bytesIn.Load(),
			BytesOut:  ac.bytesOut.Load(),
		})
	}
	return result
}

// GetSession implements web.SessionProvider.
func (m *Manager) GetSession(id string) (web.SessionInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ac, ok := m.sessions[id]
	if !ok {
		return web.SessionInfo{}, false
	}
	s := ac.Info
	return web.SessionInfo{
		ID:        s.ID,
		Hostname:  s.Hostname,
		OS:        s.OS,
		IPs:       s.IPs,
		Active:    s.Active,
		CreatedAt: s.CreatedAt.Format(time.RFC3339),
		TunActive: m.tunSession == s.ID && m.tunIface != nil,
		BytesIn:   ac.bytesIn.Load(),
		BytesOut:  ac.bytesOut.Load(),
	}, true
}

// GetTunnels implements web.SessionProvider.
func (m *Manager) GetTunnels(sessionID string) []web.TunnelInfo {
	ac := m.getConn(sessionID)
	if ac == nil {
		return nil
	}
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	if len(ac.tunnels) == 0 {
		return nil
	}
	result := make([]web.TunnelInfo, 0, len(ac.tunnels))
	for _, t := range ac.tunnels {
		result = append(result, *t)
	}
	return result
}

// GetRoutes implements web.SessionProvider.
func (m *Manager) GetRoutes(sessionID string) []web.RouteInfo {
	ac := m.getConn(sessionID)
	if ac == nil {
		return nil
	}
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	if len(ac.routes) == 0 {
		return nil
	}
	result := make([]web.RouteInfo, 0, len(ac.routes))
	for _, r := range ac.routes {
		result = append(result, *r)
	}
	return result
}

// AddTunnel implements web.SessionProvider.
// Sends a TunnelRequest to the agent and stores the tunnel optimistically.
func (m *Manager) AddTunnel(sessionID, direction, listen, remote, proto string) (web.TunnelInfo, error) {
	ac := m.getConn(sessionID)
	if ac == nil {
		return web.TunnelInfo{}, fmt.Errorf("session %s not found", sessionID)
	}

	if _, _, err := net.SplitHostPort(listen); err != nil {
		return web.TunnelInfo{}, fmt.Errorf("invalid listen address %q: %w", listen, err)
	}
	if _, _, err := net.SplitHostPort(remote); err != nil {
		return web.TunnelInfo{}, fmt.Errorf("invalid remote address %q: %w", remote, err)
	}

	tunnelID := genID()

	if ac.Ctrl != nil {
		req := &protocol.TunnelRequestPayload{
			ID:         tunnelID,
			Direction:  direction,
			ListenAddr: listen,
			RemoteAddr: remote,
			Protocol:   proto,
		}
		msg, err := protocol.EncodeTunnelRequest(req)
		if err != nil {
			return web.TunnelInfo{}, fmt.Errorf("encode tunnel request: %w", err)
		}
		ac.writeMu.Lock()
		err = protocol.WriteMessage(ac.Ctrl, msg)
		ac.writeMu.Unlock()
		if err != nil {
			return web.TunnelInfo{}, fmt.Errorf("send tunnel request: %w", err)
		}
	}

	info := &web.TunnelInfo{
		ID:         tunnelID,
		SessionID:  sessionID,
		Direction:  direction,
		ListenAddr: listen,
		RemoteAddr: remote,
		Protocol:   proto,
		Active:     true,
	}
	ac.mu.Lock()
	ac.tunnels[tunnelID] = info
	ac.mu.Unlock()

	return *info, nil
}

// RemoveTunnel implements web.SessionProvider.
// Sends a TunnelClose to the agent and removes the tunnel from tracking.
func (m *Manager) RemoveTunnel(sessionID, tunnelID string) error {
	ac := m.getConn(sessionID)
	if ac == nil {
		return fmt.Errorf("session %s not found", sessionID)
	}

	if ac.Ctrl != nil {
		msg := protocol.EncodeTunnelClose(tunnelID)
		ac.writeMu.Lock()
		protocol.WriteMessage(ac.Ctrl, msg)
		ac.writeMu.Unlock()
	}

	ac.mu.Lock()
	delete(ac.tunnels, tunnelID)
	ac.mu.Unlock()

	return nil
}

// StopTunnel sends a TunnelClose to the agent and marks the tunnel inactive,
// but keeps the tunnel definition so it can be restarted later.
func (m *Manager) StopTunnel(sessionID, tunnelID string) error {
	ac := m.getConn(sessionID)
	if ac == nil {
		return fmt.Errorf("session %s not found", sessionID)
	}

	ac.mu.RLock()
	t, ok := ac.tunnels[tunnelID]
	ac.mu.RUnlock()
	if !ok {
		return fmt.Errorf("tunnel %s not found", tunnelID)
	}
	if !t.Active {
		return fmt.Errorf("tunnel %s already stopped", tunnelID)
	}

	// Send TunnelClose to agent.
	if ac.Ctrl != nil {
		msg := protocol.EncodeTunnelClose(tunnelID)
		ac.writeMu.Lock()
		protocol.WriteMessage(ac.Ctrl, msg)
		ac.writeMu.Unlock()
	}

	// Mark inactive but keep in map.
	ac.mu.Lock()
	t.Active = false
	ac.mu.Unlock()

	return nil
}

// StartTunnel re-sends a TunnelRequest to the agent for an existing inactive tunnel.
func (m *Manager) StartTunnel(sessionID, tunnelID string) error {
	ac := m.getConn(sessionID)
	if ac == nil {
		return fmt.Errorf("session %s not found", sessionID)
	}

	ac.mu.RLock()
	t, ok := ac.tunnels[tunnelID]
	ac.mu.RUnlock()
	if !ok {
		return fmt.Errorf("tunnel %s not found", tunnelID)
	}
	if t.Active {
		return fmt.Errorf("tunnel %s already active", tunnelID)
	}

	if ac.Ctrl == nil {
		return fmt.Errorf("session %s has no control stream", sessionID)
	}

	// Re-send TunnelRequest to agent.
	req := &protocol.TunnelRequestPayload{
		ID:         tunnelID,
		Direction:  t.Direction,
		ListenAddr: t.ListenAddr,
		RemoteAddr: t.RemoteAddr,
		Protocol:   t.Protocol,
	}
	msg, err := protocol.EncodeTunnelRequest(req)
	if err != nil {
		return fmt.Errorf("encode tunnel request: %w", err)
	}
	ac.writeMu.Lock()
	err = protocol.WriteMessage(ac.Ctrl, msg)
	ac.writeMu.Unlock()
	if err != nil {
		return fmt.Errorf("send tunnel request: %w", err)
	}

	// Optimistically mark active and clear any previous error (agent ack will confirm/deny).
	ac.mu.Lock()
	t.Active = true
	t.Error = ""
	ac.mu.Unlock()

	return nil
}

// AddRoute implements web.SessionProvider.
// Sends a RouteAdd to the agent and stores the route.
func (m *Manager) AddRoute(sessionID, cidr string) (web.RouteInfo, error) {
	ac := m.getConn(sessionID)
	if ac == nil {
		return web.RouteInfo{}, fmt.Errorf("session %s not found", sessionID)
	}

	if ac.Ctrl != nil {
		payload := &protocol.RoutePayload{CIDR: cidr, Gateway: "default"}
		msg, err := protocol.EncodeRouteAdd(payload)
		if err != nil {
			return web.RouteInfo{}, fmt.Errorf("encode route add: %w", err)
		}
		ac.writeMu.Lock()
		err = protocol.WriteMessage(ac.Ctrl, msg)
		ac.writeMu.Unlock()
		if err != nil {
			return web.RouteInfo{}, fmt.Errorf("send route add: %w", err)
		}
	}

	info := &web.RouteInfo{
		CIDR:      cidr,
		SessionID: sessionID,
		Active:    true,
	}
	ac.mu.Lock()
	ac.routes[cidr] = info
	ac.mu.Unlock()

	// If TUN is active for this session, add kernel route via TUN interface.
	m.mu.RLock()
	if m.tunIface != nil && m.tunSession == sessionID {
		m.tunIface.AddRoute(cidr)
	}
	m.mu.RUnlock()

	return *info, nil
}

// RemoveRoute implements web.SessionProvider.
// Sends a RouteRemove to the agent and removes the route from tracking.
func (m *Manager) RemoveRoute(sessionID, cidr string) error {
	ac := m.getConn(sessionID)
	if ac == nil {
		return fmt.Errorf("session %s not found", sessionID)
	}

	if ac.Ctrl != nil {
		payload := &protocol.RoutePayload{CIDR: cidr}
		msg, err := protocol.EncodeRouteRemove(payload)
		if err != nil {
			return fmt.Errorf("encode route remove: %w", err)
		}
		ac.writeMu.Lock()
		err = protocol.WriteMessage(ac.Ctrl, msg)
		ac.writeMu.Unlock()
		if err != nil {
			return fmt.Errorf("send route remove: %w", err)
		}
	}

	ac.mu.Lock()
	delete(ac.routes, cidr)
	ac.mu.Unlock()

	// If TUN is active for this session, remove kernel route from TUN interface.
	m.mu.RLock()
	if m.tunIface != nil && m.tunSession == sessionID {
		m.tunIface.RemoveRoute(cidr)
	}
	m.mu.RUnlock()

	return nil
}

// genID returns a random 8-byte hex identifier.
func genID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
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
			// Default handler: close connection when no handler is configured.
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

// --- TUN mode methods ---

// StartTun activates the TUN interface for transparent routing on the given session.
// Only one session can own the TUN interface at a time.
func (m *Manager) StartTun(sessionID string) error {
	m.mu.Lock()
	if m.tunSession != "" {
		m.mu.Unlock()
		return fmt.Errorf("TUN already active on session %s", m.tunSession)
	}
	m.mu.Unlock()

	ac := m.getConn(sessionID)
	if ac == nil {
		return fmt.Errorf("session %s not found", sessionID)
	}
	if ac.Ctrl == nil {
		return fmt.Errorf("session %s has no control stream", sessionID)
	}

	// Create and configure TUN interface.
	iface, err := tun.New("")
	if err != nil {
		return fmt.Errorf("create TUN: %w", err)
	}
	ip, mask := tun.DefaultMagicIP()
	if err := iface.Configure(ip, mask); err != nil {
		iface.Close()
		return fmt.Errorf("configure TUN: %w", err)
	}

	// Prepare to receive data stream from agent.
	ac.mu.Lock()
	ac.tunReady = make(chan error, 1)
	ac.mu.Unlock()

	// Send MsgTunStart on control stream.
	msg := protocol.EncodeTunStart()
	ac.writeMu.Lock()
	err = protocol.WriteMessage(ac.Ctrl, msg)
	ac.writeMu.Unlock()
	if err != nil {
		iface.Close()
		return fmt.Errorf("send TUN start: %w", err)
	}

	// Wait for agent to open data stream (signaled via HandleDataStream).
	select {
	case readyErr := <-ac.tunReady:
		if readyErr != nil {
			iface.Close()
			return fmt.Errorf("agent TUN start: %w", readyErr)
		}
	case <-time.After(20 * time.Second):
		iface.Close()
		return fmt.Errorf("TUN start timeout: agent did not respond in 20s")
	}

	// Store TUN state and start relay goroutines.
	tunCtx, tunCancel := context.WithCancel(context.Background())
	m.mu.Lock()
	m.tunIface = iface
	m.tunSession = sessionID
	m.tunCancel = tunCancel
	m.mu.Unlock()

	go m.tunRelayToStream(tunCtx, iface, ac)
	go m.tunRelayFromStream(tunCtx, iface, ac)

	// Re-apply kernel routes for any routes already tracked on this session.
	// Use remove-before-add to clear any stale entries from a previous TUN interface.
	ac.mu.RLock()
	for cidr := range ac.routes {
		_ = iface.RemoveRoute(cidr) // ignore error if route doesn't exist yet
		if err := iface.AddRoute(cidr); err != nil {
			fmt.Fprintf(os.Stderr, "[!] TUN re-add route %s: %v\n", cidr, err)
		}
	}
	ac.mu.RUnlock()

	// Auto-add /24 routes derived from agent IPs.
	ac.mu.Lock()
	for _, ipStr := range ac.Info.IPs {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if ip.To4() == nil || ip.IsLoopback() {
			continue
		}
		ip4 := ip.To4()
		cidr := fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
		if _, exists := ac.routes[cidr]; exists {
			continue
		}
		if err := iface.AddRoute(cidr); err != nil {
			fmt.Fprintf(os.Stderr, "[!] TUN auto-route %s: %v\n", cidr, err)
			continue
		}
		ac.routes[cidr] = &web.RouteInfo{
			CIDR:      cidr,
			SessionID: sessionID,
			Active:    true,
		}
		fmt.Printf("[*] TUN auto-route: %s via %s\n", cidr, iface.Name)
	}
	ac.mu.Unlock()

	fmt.Printf("[*] TUN active on session %s — add routes with 'route add <cidr>'\n", sessionID)

	return nil
}

// StopTun deactivates the TUN interface for the given session.
func (m *Manager) StopTun(sessionID string) error {
	m.mu.Lock()
	if m.tunSession != sessionID {
		m.mu.Unlock()
		return fmt.Errorf("TUN not active on session %s", sessionID)
	}
	iface := m.tunIface
	tunCancel := m.tunCancel
	m.tunIface = nil
	m.tunSession = ""
	m.tunCancel = nil
	m.mu.Unlock()

	// Cancel relay goroutines.
	if tunCancel != nil {
		tunCancel()
	}

	// Close TUN interface.
	if iface != nil {
		iface.Close()
	}

	// Close data stream.
	ac := m.getConn(sessionID)
	if ac != nil {
		ac.mu.Lock()
		if ac.tunStream != nil {
			ac.tunStream.Close()
			ac.tunStream = nil
		}
		ac.tunActive = false
		ac.mu.Unlock()
		ac.tunReady = nil

		// Send MsgTunStop to agent.
		if ac.Ctrl != nil {
			stopMsg := protocol.EncodeTunStop()
			ac.writeMu.Lock()
			protocol.WriteMessage(ac.Ctrl, stopMsg)
			ac.writeMu.Unlock()
		}
	}

	return nil
}

// HandleTunAck processes a TUN start acknowledgment from the agent.
func (m *Manager) HandleTunAck(sessionID, errStr string) {
	ac := m.getConn(sessionID)
	if ac == nil {
		return
	}
	ac.mu.RLock()
	ch := ac.tunReady
	ac.mu.RUnlock()
	if ch == nil {
		return
	}
	if errStr != "" {
		select {
		case ch <- fmt.Errorf("%s", errStr):
		default:
		}
	}
	// Success ack is signaled by HandleDataStream when the data stream is ready.
}
// HandleDataStream stores the yamux data stream opened by the agent for TUN packets.
func (m *Manager) HandleDataStream(sessionID string, stream net.Conn) {
	ac := m.getConn(sessionID)
	if ac == nil {
		stream.Close()
		return
	}
	ac.mu.Lock()
	ac.tunStream = stream
	ac.tunActive = true
	ch := ac.tunReady
	ac.mu.Unlock()
	if ch != nil {
		select {
		case ch <- nil:
		default:
		}
	}
}

// IsTunActive returns whether TUN mode is active for the given session.
func (m *Manager) IsTunActive(sessionID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tunSession == sessionID && m.tunIface != nil
}

// tunRelayToStream reads packets from the TUN interface and writes them to the data stream.
func (m *Manager) tunRelayToStream(ctx context.Context, iface *tun.Interface, ac *AgentConn) {
	buf := make([]byte, tun.DefaultMTU+64)
	// Cache stream reference — only recheck on nil (avoids per-packet mutex).
	ac.mu.RLock()
	stream := ac.tunStream
	ac.mu.RUnlock()
	for {
		if ctx.Err() != nil {
			return
		}
		n, err := iface.Read(buf)
		if err != nil {
			if ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "[!] TUN read error: %v\n", err)
			}
			return
		}
		if stream == nil {
			ac.mu.RLock()
			stream = ac.tunStream
			ac.mu.RUnlock()
			if stream == nil {
				continue
			}
		}
		if err := protocol.WriteRawPacket(stream, buf[:n]); err != nil {
			if ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "[!] TUN write-to-stream error: %v\n", err)
			}
			return
		}
		ac.bytesOut.Add(int64(n))
	}
}

// tunRelayFromStream reads packets from the data stream and writes them to the TUN interface.
func (m *Manager) tunRelayFromStream(ctx context.Context, iface *tun.Interface, ac *AgentConn) {
	ac.mu.RLock()
	stream := ac.tunStream
	ac.mu.RUnlock()
	if stream == nil {
		fmt.Fprintln(os.Stderr, "[!] TUN relay: no data stream")
		return
	}
	for {
		if ctx.Err() != nil {
			return
		}
		pkt, err := protocol.ReadRawPacket(stream)
		if err != nil {
			if ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "[!] TUN read-from-stream error: %v\n", err)
				// Auto-cleanup: relay died but session should survive.
				go m.StopTun(ac.Info.ID)
			}
			return
		}
		if _, err := iface.Write(pkt); err != nil {
			protocol.PutPacketBuf(pkt)
			if ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "[!] TUN write-to-iface error: %v\n", err)
				go m.StopTun(ac.Info.ID)
			}
			return
		}
		ac.bytesIn.Add(int64(len(pkt)))
		protocol.PutPacketBuf(pkt)
	}
}
