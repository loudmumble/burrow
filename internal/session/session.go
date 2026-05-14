// Package session provides agent session management for the Burrow proxy server.
//
// Manager tracks connected agents, their tunnels, routes, and implements
// web.SessionProvider for the WebUI dashboard.
package session

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/loudmumble/burrow/internal/discovery"
	"github.com/loudmumble/burrow/internal/mux"
	"github.com/loudmumble/burrow/internal/protocol"
	"github.com/loudmumble/burrow/internal/proxy"
	"github.com/loudmumble/burrow/internal/transport"
	"github.com/loudmumble/burrow/internal/tun"
	"github.com/loudmumble/burrow/internal/web"
)

// Info holds metadata about a connected agent session.
type Info struct {
	ID        string    `json:"id"`
	Hostname  string    `json:"hostname"`
	OS        string    `json:"os"`
	Arch      string    `json:"arch,omitempty"`
	IPs       []string  `json:"ips"`
	PID       int       `json:"pid"`
	Remote    string    `json:"remote"`
	CreatedAt time.Time `json:"created_at"`
	Active    bool      `json:"active"`
	Transport string    `json:"transport"`
	Version   string    `json:"version"`
	NumCPU    int       `json:"num_cpu,omitempty"`
	Debugged  bool      `json:"debugged,omitempty"`
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

	// Per-tunnel byte counters keyed by tunnel ID.
	// Separate from the TunnelInfo DTO so they can be incremented
	// lock-free from relay goroutines and merged into TunnelInfo on read.
	tunnelBytesIn  map[string]*atomic.Int64
	tunnelBytesOut map[string]*atomic.Int64

	tunStream net.Conn    // yamux data stream for TUN packets
	tunActive bool
	tunReady  chan error  // signaled when data stream is ready

	tapStream net.Conn    // yamux data stream for TAP frames
	tapActive bool
	tapReady  chan error  // signaled when TAP data stream is ready

	socksServer *proxy.SOCKS5
	socksCancel context.CancelFunc
	execResults     map[string]chan *protocol.ExecResponsePayload
	downloadResults map[string]chan *protocol.FileDownloadResponsePayload
	uploadResults   map[string]chan *protocol.FileUploadResponsePayload

	lastPingSent atomic.Value // time.Time
	rtt          atomic.Int64 // microseconds
}

// Manager tracks all active agent sessions.
// PrevTunnelConfig holds the configuration needed to restore a tunnel on reconnect.
type PrevTunnelConfig struct {
	Direction  string
	ListenAddr string
	RemoteAddr string
	Protocol   string
}

// PrevSessionState stores session configuration for auto-restore on agent reconnect.
type PrevSessionState struct {
	Tunnels []PrevTunnelConfig
	Routes  []string
	TapAddr string // empty if TAP wasn't active
}

type Manager struct {
	sessions   map[string]*AgentConn
	mu         sync.RWMutex
	events     *web.EventBus
	tunIface   *tun.Interface
	tunSession string           // which session owns TUN
	tunCancel  context.CancelFunc
	tunPrevHostname string
	tunPrevRoutes   []string
	tapIface   *tun.TAPInterface
	tapSession string           // which session owns TAP
	tapCancel  context.CancelFunc
	tapAddr    string           // assigned TAP IP (e.g. "10.10.10.200/24")
	labels     map[string]string // session ID -> user label
	prevStates map[string]*PrevSessionState // hostname -> state to restore on reconnect
	scanResults map[string][]*discovery.Target // session ID -> scan results
	hostNotes   map[string]string             // "ip" -> user note
}

// NewManager creates a new session manager.
func NewManager() *Manager {
	return &Manager{
		sessions:    make(map[string]*AgentConn),
		prevStates:  make(map[string]*PrevSessionState),
		labels:      make(map[string]string),
		scanResults: make(map[string][]*discovery.Target),
		hostNotes:   make(map[string]string),
	}
}

// SetEventBus attaches an EventBus to the manager for real-time event publishing.
func (m *Manager) SetEventBus(eb *web.EventBus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = eb
}

// GetEventBus returns the EventBus attached to this manager, or nil.
func (m *Manager) GetEventBus() *web.EventBus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.events
}

// publishEvent publishes an event if an EventBus is attached.
func (m *Manager) publishEvent(evtType web.EventType, data interface{}) {
	if m.events != nil {
		m.events.Publish(web.Event{Type: evtType, Data: data})
	}
}

// Shutdown cleanly tears down all TUN and TAP state. Call on server exit.
func (m *Manager) Shutdown() {
	m.mu.RLock()
	tunSid := m.tunSession
	tapSid := m.tapSession
	m.mu.RUnlock()
	if tunSid != "" {
		_ = m.StopTun(tunSid)
	}
	if tapSid != "" {
		_ = m.StopTap(tapSid)
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
		Info:           info,
		tunnels:        make(map[string]*web.TunnelInfo),
		routes:         make(map[string]*web.RouteInfo),
		tunnelBytesIn:  make(map[string]*atomic.Int64),
		tunnelBytesOut: make(map[string]*atomic.Int64),
		execResults:     make(map[string]chan *protocol.ExecResponsePayload),
		downloadResults: make(map[string]chan *protocol.FileDownloadResponsePayload),
		uploadResults:   make(map[string]chan *protocol.FileUploadResponsePayload),
	}
}
// AddConn registers a new session with its mux session and control stream.
func (m *Manager) AddConn(info *Info, muxSess *mux.Session, ctrl net.Conn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[info.ID] = &AgentConn{
		Info:           info,
		Mux:            muxSess,
		Ctrl:           ctrl,
		tunnels:        make(map[string]*web.TunnelInfo),
		routes:         make(map[string]*web.RouteInfo),
		tunnelBytesIn:  make(map[string]*atomic.Int64),
		tunnelBytesOut: make(map[string]*atomic.Int64),
		execResults:     make(map[string]chan *protocol.ExecResponsePayload),
		downloadResults: make(map[string]chan *protocol.FileDownloadResponsePayload),
		uploadResults:   make(map[string]chan *protocol.FileUploadResponsePayload),
	}
	m.publishEvent(web.EventSessionConnect, map[string]string{"id": info.ID, "hostname": info.Hostname})
}

// Remove deletes a session by ID. If TUN is active on this session, it is stopped first.
// Tunnel, route, and TAP configurations are saved for auto-restore on agent reconnect.
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

	// Save TAP address for auto-restore.
	m.mu.RLock()
	ownsTap := m.tapSession == id && m.tapIface != nil
	tapAddr := m.tapAddr
	m.mu.RUnlock()
	if ownsTap {
		_ = m.StopTap(id)
	}

	// Save tunnel/route/TAP config for auto-restore on reconnect.
	if ac != nil {
		ac.mu.RLock()
		var prevTunnels []PrevTunnelConfig
		for _, t := range ac.tunnels {
			prevTunnels = append(prevTunnels, PrevTunnelConfig{
				Direction:  t.Direction,
				ListenAddr: t.ListenAddr,
				RemoteAddr: t.RemoteAddr,
				Protocol:   t.Protocol,
			})
		}
		var prevRoutes []string
		for cidr := range ac.routes {
			prevRoutes = append(prevRoutes, cidr)
		}
		ac.mu.RUnlock()

		if len(prevTunnels) > 0 || len(prevRoutes) > 0 || (ownsTap && tapAddr != "") {
			state := &PrevSessionState{
				Tunnels: prevTunnels,
				Routes:  prevRoutes,
			}
			if ownsTap {
				state.TapAddr = tapAddr
			}
			m.mu.Lock()
			m.prevStates[ac.Info.Hostname] = state
			m.mu.Unlock()
		}
	}

	// Clean up SOCKS5 proxy if active.
	if ac != nil {
		ac.mu.Lock()
		socksSrv := ac.socksServer
		socksCancel := ac.socksCancel
		ac.socksServer = nil
		ac.socksCancel = nil
		ac.mu.Unlock()
		if socksCancel != nil {
			socksCancel()
		}
		if socksSrv != nil {
			socksSrv.Stop()
		}

		// Best-effort close active tunnels — send TunnelClose for each.
		ac.mu.RLock()
		tunnelIDs := make([]string, 0, len(ac.tunnels))
		for tid, t := range ac.tunnels {
			if t.Active {
				tunnelIDs = append(tunnelIDs, tid)
			}
		}
		ac.mu.RUnlock()
		for _, tid := range tunnelIDs {
			if ac.Ctrl != nil {
				closeMsg := protocol.EncodeTunnelClose(tid)
				ac.writeMu.Lock()
				_ = ac.writeCtrlMsg(closeMsg) // best-effort
				ac.writeMu.Unlock()
			}
		}

		// Close pending result channels so blocked goroutines unblock immediately
		// instead of waiting for their full timeout.
		ac.mu.Lock()
		for k, ch := range ac.execResults {
			close(ch)
			delete(ac.execResults, k)
		}
		for k, ch := range ac.downloadResults {
			close(ch)
			delete(ac.downloadResults, k)
		}
		for k, ch := range ac.uploadResults {
			close(ch)
			delete(ac.uploadResults, k)
		}
		ac.mu.Unlock()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
	m.publishEvent(web.EventSessionDisconnect, map[string]string{"id": id})
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

// TunPrevRoutes returns a copy of the saved routes from the previous TUN session.
func (m *Manager) TunPrevRoutes() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cp := make([]string, len(m.tunPrevRoutes))
	copy(cp, m.tunPrevRoutes)
	return cp
}

// PrevState returns the saved session state for a hostname, or nil if none exists.
func (m *Manager) PrevState(hostname string) *PrevSessionState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.prevStates[hostname]
}

// ClearPrevState removes saved session state for a hostname after successful restore.
func (m *Manager) ClearPrevState(hostname string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.prevStates, hostname)
}

// FindByHostname returns the session ID for a given hostname, if one exists.
func (m *Manager) FindByHostname(hostname string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for id, ac := range m.sessions {
		if ac.Info.Hostname == hostname {
			return id, true
		}
	}
	return "", false
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

// writeCtrlMsg writes a protocol message to the control stream with a write
// deadline so that a stalled TCP/mux write can never hold writeMu indefinitely.
// MUST be called with ac.writeMu held.
const ctrlWriteTimeout = 15 * time.Second

func (ac *AgentConn) writeCtrlMsg(msg *protocol.Message) error {
	if err := ac.Ctrl.SetWriteDeadline(time.Now().Add(ctrlWriteTimeout)); err != nil {
		// Non-fatal — proceed without deadline if the stream doesn't support it.
		_ = err
	}
	err := protocol.WriteMessage(ac.Ctrl, msg)
	// Always clear the deadline so subsequent reads aren't affected.
	_ = ac.Ctrl.SetWriteDeadline(time.Time{})
	return err
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
	return ac.writeCtrlMsg(msg)
}

// UpdateTunnelStatus updates a tunnel's status after receiving an ack from the agent.
func (m *Manager) UpdateTunnelStatus(sessionID, tunnelID, boundAddr, errStr string) {
	ac := m.getConn(sessionID)
	if ac == nil {
		return
	}
	ac.mu.Lock()
	t, ok := ac.tunnels[tunnelID]
	if !ok {
		ac.mu.Unlock()
		return
	}
	t.Pending = false
	if errStr != "" {
		t.Active = false
		t.Error = errStr
		ac.mu.Unlock()
		m.publishEvent(web.EventTunnelError, map[string]string{
			"session_id": sessionID,
			"tunnel_id":  tunnelID,
			"error":      errStr,
		})
	} else {
		t.Active = true
		t.Error = ""
		if boundAddr != "" {
			t.ListenAddr = boundAddr
		}
		ac.mu.Unlock()
		m.publishEvent(web.EventTunnelStart, map[string]string{
			"session_id": sessionID,
			"tunnel_id":  tunnelID,
			"bound_addr": boundAddr,
		})
	}
}

// ListSessions implements web.SessionProvider.
func (m *Manager) ListSessions() []web.SessionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]web.SessionInfo, 0, len(m.sessions))
	for _, ac := range m.sessions {
		result = append(result, m.buildSessionInfo(ac))
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
	return m.buildSessionInfo(ac), true
}

// buildSessionInfo creates a SessionInfo from an AgentConn. Caller must hold m.mu.RLock.
func (m *Manager) buildSessionInfo(ac *AgentConn) web.SessionInfo {
	s := ac.Info
	socksAddr := ""
	var socksActive, socksBytesIn, socksBytesOut int64
	ac.mu.RLock()
	srv := ac.socksServer
	ac.mu.RUnlock()
	if srv != nil {
		socksAddr = srv.Addr()
		socksActive, _, socksBytesIn, socksBytesOut = srv.Stats()
	}
	ac.mu.RLock()
	tunnelCount := len(ac.tunnels)
	routeCount := len(ac.routes)
	ac.mu.RUnlock()
	return web.SessionInfo{
		ID:            s.ID,
		Hostname:      s.Hostname,
		OS:            s.OS,
		IPs:           s.IPs,
		Active:        s.Active,
		CreatedAt:     s.CreatedAt.Format(time.RFC3339),
		TunActive:     m.tunSession == s.ID && m.tunIface != nil,
		TapActive:     m.tapSession == s.ID && m.tapIface != nil,
		BytesIn:       ac.bytesIn.Load(),
		BytesOut:      ac.bytesOut.Load(),
		SocksAddr:     socksAddr,
		Transport:     s.Transport,
		AgentVersion:  s.Version,
		PID:           s.PID,
		Tunnels:       tunnelCount,
		Routes:        routeCount,
		SocksActive:   socksActive,
		SocksBytesIn:  socksBytesIn,
		SocksBytesOut: socksBytesOut,
		RTTMicros:     ac.rtt.Load(),
	}
}

// MarkPingSent records the time a ping was sent to the agent.
func (m *Manager) MarkPingSent(sessionID string) {
	ac := m.getConn(sessionID)
	if ac != nil {
		ac.lastPingSent.Store(time.Now())
	}
}

// AddBytesIn adds to the session's inbound byte counter.
func (m *Manager) AddBytesIn(sessionID string, n int64) {
	if ac := m.getConn(sessionID); ac != nil {
		ac.bytesIn.Add(n)
	}
}

// AddBytesOut adds to the session's outbound byte counter.
func (m *Manager) AddBytesOut(sessionID string, n int64) {
	if ac := m.getConn(sessionID); ac != nil {
		ac.bytesOut.Add(n)
	}
}


// AddTunnelBytesIn increments the per-tunnel inbound byte counter.
// Also increments the session-level counter for aggregate metrics.
func (m *Manager) AddTunnelBytesIn(sessionID, tunnelID string, n int64) {
	if ac := m.getConn(sessionID); ac != nil {
		ac.bytesIn.Add(n)
		ac.mu.RLock()
		ctr := ac.tunnelBytesIn[tunnelID]
		ac.mu.RUnlock()
		if ctr != nil {
			ctr.Add(n)
		}
	}
}

// AddTunnelBytesOut increments the per-tunnel outbound byte counter.
// Also increments the session-level counter for aggregate metrics.
func (m *Manager) AddTunnelBytesOut(sessionID, tunnelID string, n int64) {
	if ac := m.getConn(sessionID); ac != nil {
		ac.bytesOut.Add(n)
		ac.mu.RLock()
		ctr := ac.tunnelBytesOut[tunnelID]
		ac.mu.RUnlock()
		if ctr != nil {
			ctr.Add(n)
		}
	}
}

// EnsureTunnelCounters creates per-tunnel byte counter slots for a tunnel ID.
// Called when a tunnel is registered to guarantee slots exist before relay starts.
func (m *Manager) EnsureTunnelCounters(sessionID, tunnelID string) {
	ac := m.getConn(sessionID)
	if ac == nil {
		return
	}
	ac.mu.Lock()
	defer ac.mu.Unlock()
	if _, ok := ac.tunnelBytesIn[tunnelID]; !ok {
		ac.tunnelBytesIn[tunnelID] = &atomic.Int64{}
	}
	if _, ok := ac.tunnelBytesOut[tunnelID]; !ok {
		ac.tunnelBytesOut[tunnelID] = &atomic.Int64{}
	}
}

// FindTunnelByRemoteAddr returns the tunnel ID whose RemoteAddr matches the
// given address, or empty string if none found. Used by the remote tunnel
// relay to attribute bytes to the correct per-tunnel counter.
func (m *Manager) FindTunnelByRemoteAddr(sessionID, remoteAddr string) string {
	ac := m.getConn(sessionID)
	if ac == nil {
		return ""
	}
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	for id, t := range ac.tunnels {
		if t.RemoteAddr == remoteAddr && t.Direction == "remote" {
			return id
		}
	}
	return ""
}

// MarkPongReceived records a pong response and computes RTT.
func (m *Manager) MarkPongReceived(sessionID string) {
	ac := m.getConn(sessionID)
	if ac == nil {
		return
	}
	if sent, ok := ac.lastPingSent.Load().(time.Time); ok && !sent.IsZero() {
		ac.rtt.Store(time.Since(sent).Microseconds())
	}
}

// SetLabel sets a user-defined label for a session.
func (m *Manager) SetLabel(sessionID, label string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if label == "" {
		delete(m.labels, sessionID)
	} else {
		m.labels[sessionID] = label
	}
}

// GetLabel returns the user-defined label for a session.
func (m *Manager) GetLabel(sessionID string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.labels[sessionID]
}

// KillSession tears down all tunnels, routes, SOCKS5, and TUN on a session.
func (m *Manager) KillSession(sessionID string) error {
	ac := m.getConn(sessionID)
	if ac == nil {
		return fmt.Errorf("session %s not found", sessionID)
	}
	// Stop TUN if this session owns it.
	m.mu.RLock()
	ownsTun := m.tunSession == sessionID && m.tunIface != nil
	ownsTap := m.tapSession == sessionID && m.tapIface != nil
	m.mu.RUnlock()
	if ownsTun {
		_ = m.StopTun(sessionID)
	}
	// Stop TAP if this session owns it.
	if ownsTap {
		_ = m.StopTap(sessionID)
	}
	// Stop SOCKS5 if active.
	if m.IsSOCKS5Active(sessionID) {
		_ = m.StopSOCKS5(sessionID)
	}
	// Remove all tunnels.
	ac.mu.RLock()
	tunnelIDs := make([]string, 0, len(ac.tunnels))
	for tid := range ac.tunnels {
		tunnelIDs = append(tunnelIDs, tid)
	}
	ac.mu.RUnlock()
	for _, tid := range tunnelIDs {
		_ = m.RemoveTunnel(sessionID, tid)
	}
	// Remove all routes.
	ac.mu.RLock()
	routeCIDRs := make([]string, 0, len(ac.routes))
	for cidr := range ac.routes {
		routeCIDRs = append(routeCIDRs, cidr)
	}
	ac.mu.RUnlock()
	for _, cidr := range routeCIDRs {
		_ = m.RemoveRoute(sessionID, cidr)
	}
	// Close the mux session to disconnect the agent.
	if ac.Mux != nil {
		ac.Mux.Close()
	}
	return nil
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
		copy := *t
		// Merge live per-tunnel byte counters into the returned DTO.
		if ctr, ok := ac.tunnelBytesIn[t.ID]; ok {
			copy.BytesIn = ctr.Load()
		}
		if ctr, ok := ac.tunnelBytesOut[t.ID]; ok {
			copy.BytesOut = ctr.Load()
		}
		result = append(result, copy)
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

	// Send tunnel request to agent and mark active immediately.
	// StartTunnel is only for re-activating stopped tunnels.
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
		err = ac.writeCtrlMsg(msg)
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
		Pending:    true, // wait for agent ack before marking active
	}
	ac.mu.Lock()
	ac.tunnels[tunnelID] = info
	// Pre-create per-tunnel byte counter slots so relay goroutines can
	// increment without holding the tunnel mutex.
	if _, ok := ac.tunnelBytesIn[tunnelID]; !ok {
		ac.tunnelBytesIn[tunnelID] = &atomic.Int64{}
	}
	if _, ok := ac.tunnelBytesOut[tunnelID]; !ok {
		ac.tunnelBytesOut[tunnelID] = &atomic.Int64{}
	}
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
		err := ac.writeCtrlMsg(msg)
		ac.writeMu.Unlock()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] RemoveTunnel: send close to agent %s: %v\n", sessionID, err)
		}
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
	if !t.Active && !t.Pending {
		return fmt.Errorf("tunnel %s already stopped", tunnelID)
	}

	// Send TunnelClose to agent.
	if ac.Ctrl != nil {
		msg := protocol.EncodeTunnelClose(tunnelID)
		ac.writeMu.Lock()
		err := ac.writeCtrlMsg(msg)
		ac.writeMu.Unlock()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] StopTunnel: send close to agent %s: %v\n", sessionID, err)
		}
	}

	// Mark inactive but keep in map.
	ac.mu.Lock()
	t.Active = false
	t.Pending = false
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
	err = ac.writeCtrlMsg(msg)
	ac.writeMu.Unlock()
	if err != nil {
		return fmt.Errorf("send tunnel request: %w", err)
	}

	// Mark pending — agent ack will confirm or deny.
	ac.mu.Lock()
	t.Pending = true
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
		err = ac.writeCtrlMsg(msg)
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
		err = ac.writeCtrlMsg(msg)
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

	network := transport.NetworkForAddr(s.ListenAddr, "tcp")
	if s.TLSConfig != nil {
		ln, err = tls.Listen(network, s.ListenAddr, s.TLSConfig)
	} else {
		ln, err = net.Listen(network, s.ListenAddr)
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
		transport.TuneConn(conn)
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

// isSessionDead returns true if the session has been removed from the manager
// or its underlying mux connection is closed. Must be called with m.mu held.
func (m *Manager) isSessionDead(id string) bool {
	ac, exists := m.sessions[id]
	if !exists {
		return true // Already removed
	}
	if ac.Mux != nil && ac.Mux.IsClosed() {
		return true // Mux connection dead
	}
	return false
}

// reclaimStaleTun checks whether the current TUN owner is a dead session and
// cleans up if so. Must NOT hold m.mu on entry — it acquires it internally.
// Returns true if a stale lock was reclaimed.
func (m *Manager) reclaimStaleTun() bool {
	m.mu.Lock()
	if m.tunSession == "" {
		m.mu.Unlock()
		return false
	}
	if !m.isSessionDead(m.tunSession) {
		m.mu.Unlock()
		return false
	}
	// Dead session — reclaim TUN lock.
	owner := m.tunSession
	iface := m.tunIface
	cancel := m.tunCancel
	m.tunIface = nil
	m.tunSession = ""
	m.tunCancel = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if iface != nil {
		iface.Close()
	}
	fmt.Fprintf(os.Stderr, "[*] Reclaimed stale TUN lock from dead session %s\n", owner)
	return true
}

// StartTun activates the TUN interface for transparent routing on the given session.
// Only one session can own the TUN interface at a time.
func (m *Manager) StartTun(sessionID string) error {
	m.reclaimStaleTun()
	m.mu.Lock()
	if m.tunSession != "" {
		m.mu.Unlock()
		return fmt.Errorf("TUN already active on session %s", m.tunSession)
	}
	m.tunSession = sessionID // Claim immediately to prevent TOCTOU race
	m.mu.Unlock()

	// Release claim on any failure below.
	releaseOnFail := true
	defer func() {
		if releaseOnFail {
			m.mu.Lock()
			if m.tunSession == sessionID {
				m.tunSession = ""
			}
			m.mu.Unlock()
		}
	}()

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
	err = ac.writeCtrlMsg(msg)
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
	releaseOnFail = false

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


	fmt.Printf("[*] TUN active on session %s — add routes with 'route add <cidr>'\n", sessionID)

	return nil
}

// StopTun deactivates the TUN interface for the given session.
func (m *Manager) StopTun(sessionID string) error {
	m.mu.Lock()
	if m.tunSession == "" {
		m.mu.Unlock()
		return nil // Already stopped — idempotent
	}
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
		ac.tunReady = nil
		ac.mu.Unlock()

		// Send MsgTunStop to agent.
		if ac.Ctrl != nil {
			stopMsg := protocol.EncodeTunStop()
			ac.writeMu.Lock()
			err := ac.writeCtrlMsg(stopMsg)
			ac.writeMu.Unlock()
			if err != nil {
				return fmt.Errorf("send TUN stop to agent: %w", err)
			}
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
	if ac.tunStream != nil {
		ac.tunStream.Close() // Close old stream to prevent leak
	}
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

// --- TAP (Layer 2) methods ---

// StartTap activates TAP mode on the given session, creating a TAP interface
// on the operator side and telling the agent to open an AF_PACKET raw socket
// on the specified interface (or auto-detect if empty).
// reclaimStaleTap checks whether the current TAP owner is a dead session and
// cleans up if so. Same logic as reclaimStaleTun.
func (m *Manager) reclaimStaleTap() bool {
	m.mu.Lock()
	if m.tapSession == "" {
		m.mu.Unlock()
		return false
	}
	if !m.isSessionDead(m.tapSession) {
		m.mu.Unlock()
		return false
	}
	owner := m.tapSession
	tapIface := m.tapIface
	cancel := m.tapCancel
	m.tapIface = nil
	m.tapSession = ""
	m.tapCancel = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if tapIface != nil {
		tapIface.Close()
	}
	fmt.Fprintf(os.Stderr, "[*] Reclaimed stale TAP lock from dead session %s\n", owner)
	return true
}

func (m *Manager) StartTap(sessionID, iface string) error {
	m.reclaimStaleTap()
	m.mu.Lock()
	if m.tapSession != "" {
		m.mu.Unlock()
		return fmt.Errorf("TAP already active on session %s", m.tapSession)
	}
	m.tapSession = sessionID
	m.mu.Unlock()

	releaseOnFail := true
	defer func() {
		if releaseOnFail {
			m.mu.Lock()
			if m.tapSession == sessionID {
				m.tapSession = ""
			}
			m.mu.Unlock()
		}
	}()

	ac := m.getConn(sessionID)
	if ac == nil {
		return fmt.Errorf("session %s not found", sessionID)
	}
	if ac.Ctrl == nil {
		return fmt.Errorf("session %s has no control stream", sessionID)
	}

	// Parse user-supplied CIDR for the TAP interface.
	var tapIP net.IP
	var tapMask net.IPMask
	if iface != "" {
		var parseErr error
		tapIP, tapMask, parseErr = parseTAPAddr(iface)
		if parseErr != nil {
			return parseErr
		}
	}

	// Create TAP interface on operator side.
	tapIface, err := tun.NewTAP("")
	if err != nil {
		return fmt.Errorf("create TAP: %w", err)
	}
	if err := tapIface.Configure(tapIP, tapMask); err != nil {
		tapIface.Close()
		return fmt.Errorf("configure TAP: %w", err)
	}

	// Prepare to receive data stream.
	ac.mu.Lock()
	ac.tapReady = make(chan error, 1)
	ac.mu.Unlock()

	// Send MsgTapStart on control stream.
	payload := &protocol.TapStartPayload{Interface: iface}
	msg, err := protocol.EncodeTapStart(payload)
	if err != nil {
		tapIface.Close()
		return fmt.Errorf("encode TAP start: %w", err)
	}
	ac.writeMu.Lock()
	err = ac.writeCtrlMsg(msg)
	ac.writeMu.Unlock()
	if err != nil {
		tapIface.Close()
		return fmt.Errorf("send TAP start: %w", err)
	}

	// Wait for agent to open data stream.
	select {
	case readyErr := <-ac.tapReady:
		if readyErr != nil {
			tapIface.Close()
			return fmt.Errorf("agent TAP start: %w", readyErr)
		}
	case <-time.After(20 * time.Second):
		tapIface.Close()
		return fmt.Errorf("TAP start timeout: agent did not respond in 20s")
	}

	// Store TAP state and start relay.
	tapCtx, tapCancel := context.WithCancel(context.Background())
	tapAddrStr := ""
	if tapIP != nil {
		prefix, _ := tapMask.Size()
		tapAddrStr = fmt.Sprintf("%s/%d", tapIP, prefix)
	}
	m.mu.Lock()
	m.tapIface = tapIface
	m.tapSession = sessionID
	m.tapCancel = tapCancel
	m.tapAddr = tapAddrStr
	m.mu.Unlock()
	releaseOnFail = false

	go m.tapRelayToStream(tapCtx, tapIface, ac)
	go m.tapRelayFromStream(tapCtx, tapIface, ac)

	if tapIP != nil {
		prefix, _ := tapMask.Size()
		fmt.Printf("[*] TAP active on session %s — %s assigned %s/%d\n", sessionID, tapIface.Name, tapIP, prefix)
	} else {
		fmt.Printf("[*] TAP active on session %s — %s is up (no suitable subnet found, assign IP manually)\n", sessionID, tapIface.Name)
	}
	return nil
}

// parseTAPAddr parses a user-supplied CIDR (e.g. "10.10.10.200/24") into IP and mask.
func parseTAPAddr(cidr string) (net.IP, net.IPMask, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, nil, fmt.Errorf("IPv6 not supported for TAP: %s", cidr)
	}
	return ip4, ipnet.Mask, nil
}

// StopTap deactivates TAP mode.
func (m *Manager) StopTap(sessionID string) error {
	m.mu.Lock()
	if m.tapSession == "" {
		m.mu.Unlock()
		return nil
	}
	if m.tapSession != sessionID {
		m.mu.Unlock()
		return fmt.Errorf("TAP not active on session %s", sessionID)
	}
	iface := m.tapIface
	tapCancel := m.tapCancel
	m.tapIface = nil
	m.tapSession = ""
	m.tapCancel = nil
	m.mu.Unlock()

	if tapCancel != nil {
		tapCancel()
	}
	if iface != nil {
		iface.Close()
	}

	ac := m.getConn(sessionID)
	if ac != nil {
		ac.mu.Lock()
		if ac.tapStream != nil {
			ac.tapStream.Close()
			ac.tapStream = nil
		}
		ac.tapActive = false
		ac.tapReady = nil
		ac.mu.Unlock()

		if ac.Ctrl != nil {
			stopMsg := protocol.EncodeTapStop()
			ac.writeMu.Lock()
			err := ac.writeCtrlMsg(stopMsg)
			ac.writeMu.Unlock()
			if err != nil {
				return fmt.Errorf("send TAP stop: %w", err)
			}
		}
	}
	return nil
}

// IsTapActive returns whether TAP mode is active for the given session.
func (m *Manager) IsTapActive(sessionID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tapSession == sessionID && m.tapIface != nil
}

// TapAddr returns the assigned TAP IP address (e.g. "10.10.10.200/24").
func (m *Manager) TapAddr() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tapAddr
}

// HandleTapAck processes a TapStartAck from the agent.
func (m *Manager) HandleTapAck(sessionID, errStr string) {
	ac := m.getConn(sessionID)
	if ac == nil {
		return
	}
	ac.mu.RLock()
	ch := ac.tapReady
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
}

// HandleTapDataStream stores the agent's TAP data stream and signals readiness.
func (m *Manager) HandleTapDataStream(sessionID string, stream net.Conn) {
	ac := m.getConn(sessionID)
	if ac == nil {
		stream.Close()
		return
	}
	ac.mu.Lock()
	if ac.tapStream != nil {
		ac.tapStream.Close()
	}
	ac.tapStream = stream
	ac.tapActive = true
	ch := ac.tapReady
	ac.mu.Unlock()
	if ch != nil {
		select {
		case ch <- nil:
		default:
		}
	}
}

// tapRelayToStream reads Ethernet frames from the TAP interface and sends
// them through the yamux stream to the agent.
// A 30-second write deadline is applied per-frame so a stalled yamux
// stream cannot block this goroutine indefinitely after agent disconnect.
const relayWriteTimeout = 30 * time.Second

func (m *Manager) tapRelayToStream(ctx context.Context, iface *tun.TAPInterface, ac *AgentConn) {
	buf := make([]byte, tun.MaxFrameSize+64)
	ac.mu.RLock()
	stream := ac.tapStream
	ac.mu.RUnlock()
	for {
		if ctx.Err() != nil {
			return
		}
		n, err := iface.Read(buf[4:])
		if err != nil {
			if ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "[!] TAP read error: %v\n", err)
			}
			return
		}
		if stream == nil {
			ac.mu.RLock()
			stream = ac.tapStream
			ac.mu.RUnlock()
			if stream == nil {
				continue
			}
		}
		binary.BigEndian.PutUint32(buf[:4], uint32(n))
		_ = stream.SetWriteDeadline(time.Now().Add(relayWriteTimeout))
		_, writeErr := stream.Write(buf[:4+n])
		_ = stream.SetWriteDeadline(time.Time{})
		if writeErr != nil {
			if ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "[!] TAP write-to-stream error (skipping frame): %v\n", writeErr)
			}
			continue
		}
		ac.bytesOut.Add(int64(n))
	}
}

// tapRelayFromStream reads Ethernet frames from the yamux stream and writes
// them to the TAP interface.
func (m *Manager) tapRelayFromStream(ctx context.Context, iface *tun.TAPInterface, ac *AgentConn) {
	var stream net.Conn
	for stream == nil {
		if ctx.Err() != nil {
			return
		}
		ac.mu.RLock()
		stream = ac.tapStream
		ac.mu.RUnlock()
		if stream == nil {
			select {
			case <-time.After(50 * time.Millisecond):
			case <-ctx.Done():
				return
			}
		}
	}
	for {
		if ctx.Err() != nil {
			return
		}
		// Agent sends raw IP packets — prepend Ethernet header with TAP's MAC.
		pkt, err := protocol.ReadRawPacket(stream)
		if err != nil {
			if ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "[!] TAP read-from-stream error: %v\n", err)
				go m.StopTap(ac.Info.ID)
			}
			return
		}
		frameLen := tun.EthHeaderLen + len(pkt)
		frame := protocol.GetPacketBuf(frameLen)[:frameLen]
		// dst MAC = TAP interface's own MAC (so kernel accepts as PACKET_HOST)
		if len(iface.MAC) >= 6 {
			copy(frame[0:6], iface.MAC)
		} else {
			// Zero first 6 bytes to be safe.
			frame[0], frame[1], frame[2], frame[3], frame[4], frame[5] = 0, 0, 0, 0, 0, 0
		}
		// src MAC = locally-administered unicast (zero MAC rejected by some kernels)
		frame[6] = 0x02 // locally administered bit set
		frame[7], frame[8], frame[9], frame[10], frame[11] = 0, 0, 0, 0, 0
		// EtherType
		if len(pkt) > 0 && (pkt[0]>>4) == 6 {
			frame[12] = 0x86
			frame[13] = 0xDD
		} else {
			frame[12] = 0x08
			frame[13] = 0x00
		}
		copy(frame[tun.EthHeaderLen:], pkt)
		protocol.PutPacketBuf(pkt)
		_, writeErr := iface.Write(frame)
		protocol.PutPacketBuf(frame) // return frame to pool
		if writeErr != nil {
			if ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "[!] TAP write-to-iface error: %v\n", writeErr)
				go m.StopTap(ac.Info.ID)
			}
			return
		}
		ac.bytesIn.Add(int64(len(pkt)))
	}
}

// --- Agent control methods ---

// SleepAgent sends a sleep command to the agent. The agent disconnects and
// reconnects after the specified duration.
func (m *Manager) SleepAgent(sessionID string, duration time.Duration) error {
	msg, err := protocol.EncodeSleep(int64(duration.Seconds()))
	if err != nil {
		return fmt.Errorf("encode sleep: %w", err)
	}
	return m.WriteCtrl(sessionID, msg)
}

// UpgradeAgent pushes a new binary to the agent/stager for in-memory execution.
func (m *Manager) UpgradeAgent(sessionID string, binary []byte, args []string) error {
	msg, err := protocol.EncodeUpgrade(binary, args)
	if err != nil {
		return fmt.Errorf("encode upgrade: %w", err)
	}
	return m.WriteCtrl(sessionID, msg)
}

// --- Network scan methods ---

// ScanSubnet runs a port scan on a CIDR through the given session's yamux.
// Results are stored on the manager and returned. The onFound callback is called
// for each discovered host during the scan (for TUI streaming).
// Existing results are merged by IP — re-scanning the same subnet will update
// known hosts rather than duplicating them.
func (m *Manager) ScanSubnet(ctx context.Context, sessionID, cidr, ports string, onFound func(*discovery.Target)) ([]*discovery.Target, error) {
	ac := m.getConn(sessionID)
	if ac == nil {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}
	if ac.Mux == nil {
		return nil, fmt.Errorf("session %s has no mux session", sessionID)
	}

	portList := discovery.ParsePortRange(ports)
	scanner := discovery.NewScanner(portList, 2*time.Second, 128)
	scanner.SetDialer(proxy.NewSessionDialer(ac.Mux))
	scanner.OnHostFound = onFound

	targets, err := scanner.ScanSubnet(ctx, cidr)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.scanResults[sessionID] = targets
	m.mu.Unlock()

	return targets, nil
}

// GetScanResults returns stored scan results for a session.
func (m *Manager) GetScanResults(sessionID string) []*discovery.Target {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.scanResults[sessionID]
}

// ClearScanResults clears stored scan results for a session.
func (m *Manager) ClearScanResults(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.scanResults, sessionID)
}

// SetHostNote sets a user note on a discovered host IP.
func (m *Manager) SetHostNote(ip, note string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if note == "" {
		delete(m.hostNotes, ip)
	} else {
		m.hostNotes[ip] = note
	}
}

// GetHostNote returns the user note for a host IP.
func (m *Manager) GetHostNote(ip string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.hostNotes[ip]
}

// GetAllHostNotes returns all host notes.
func (m *Manager) GetAllHostNotes() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cp := make(map[string]string, len(m.hostNotes))
	for k, v := range m.hostNotes {
		cp[k] = v
	}
	return cp
}

// SuggestRoutes analyzes scan results and suggests CIDR routes to add.
func (m *Manager) SuggestRoutes(sessionID string) []string {
	m.mu.RLock()
	results := m.scanResults[sessionID]
	m.mu.RUnlock()

	if len(results) == 0 {
		return nil
	}

	// Group IPs by /24 subnet.
	subnets := make(map[string]int) // "x.x.x" prefix -> count
	for _, t := range results {
		parts := strings.Split(t.IP, ".")
		if len(parts) == 4 {
			prefix := parts[0] + "." + parts[1] + "." + parts[2]
			subnets[prefix]++
		}
	}

	var suggestions []string
	for prefix, count := range subnets {
		if count >= 1 {
			suggestions = append(suggestions, prefix+".0/24")
		}
	}
	sort.Strings(suggestions)
	return suggestions
}

// BuildTopology returns an ASCII network topology showing sessions, tunnels,
// and discovered hosts grouped by subnet.
func (m *Manager) BuildTopology() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var b strings.Builder
	b.WriteString("[Infrastructure]\n")
	b.WriteString("└── Burrow Server\n")

	// Collect and sort sessions for consistent topology output
	var sids []string
	for sid := range m.sessions {
		sids = append(sids, sid)
	}
	sort.Strings(sids)

	for i, sid := range sids {
		ac := m.sessions[sid]
		isLastSession := i == len(sids)-1
		sessionPrefix := "    ├── "
		sessionLinePrefix := "    │   "
		if isLastSession {
			sessionPrefix = "    └── "
			sessionLinePrefix = "        "
		}

		label := ""
		if l, ok := m.labels[ac.Info.ID]; ok && l != "" {
			label = " [" + l + "]"
		}
		tunMark := ""
		if m.tunSession == ac.Info.ID {
			tunMark = " (TUN)"
		}
		tapMark := ""
		if m.tapSession == ac.Info.ID {
			tapMark = " (TAP)"
		}
		
		b.WriteString(fmt.Sprintf("%sAgent %s%s%s%s\n",
			sessionPrefix, ac.Info.Hostname, label, tunMark, tapMark))
		b.WriteString(fmt.Sprintf("%sIPs: %s | OS: %s | RTT: %dus\n",
			sessionLinePrefix, strings.Join(ac.Info.IPs, ", "), ac.Info.OS, ac.rtt.Load()))

		// Collect items to display
		type topoItem struct {
			text string
		}
		var items []topoItem

		// Show tunnels
		ac.mu.RLock()
		for _, t := range ac.tunnels {
			status := "●"
			if !t.Active {
				status = "○"
			}
			items = append(items, topoItem{fmt.Sprintf("tunnel %s %s %s → %s", status, t.Direction, t.ListenAddr, t.RemoteAddr)})
		}

		// Show routes
		for cidr := range ac.routes {
			items = append(items, topoItem{fmt.Sprintf("route %s", cidr)})
		}
		ac.mu.RUnlock()

		// Show scan results grouped by subnet
		if results, ok := m.scanResults[ac.Info.ID]; ok && len(results) > 0 {
			subnets := make(map[string][]*discovery.Target)
			for _, t := range results {
				parts := strings.Split(t.IP, ".")
				if len(parts) == 4 {
					prefix := parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
					subnets[prefix] = append(subnets[prefix], t)
				}
			}
			for subnet, hosts := range subnets {
				items = append(items, topoItem{fmt.Sprintf("subnet [%s] (%d hosts)", subnet, len(hosts))})
				for _, h := range hosts {
					svcs := strings.Join(h.Services, ",")
					if len(svcs) > 30 {
						svcs = svcs[:27] + "..."
					}
					items = append(items, topoItem{fmt.Sprintf("  host %s [%s]", h.IP, svcs)})
				}
			}
		}

		for j, item := range items {
			itemPrefix := "├── "
			if j == len(items)-1 {
				itemPrefix = "└── "
			}
			b.WriteString(fmt.Sprintf("%s%s%s\n", sessionLinePrefix, itemPrefix, item.text))
		}
	}

	if len(m.sessions) == 0 {
		b.WriteString("    └── (no active agents)\n")
	}
	return b.String()
}

// --- SOCKS5 proxy methods ---

// StartSOCKS5 starts a SOCKS5 proxy on the operator's machine that routes
// connections through the given session's yamux mux to the remote agent.
// Optional username/password authentication can be set with StartSOCKS5WithAuth.
func (m *Manager) StartSOCKS5(sessionID, listenAddr string) error {
	return m.StartSOCKS5WithAuth(sessionID, listenAddr, "", "")
}

// StartSOCKS5WithAuth starts a SOCKS5 proxy with optional per-session credentials.
// Empty username disables authentication.
func (m *Manager) StartSOCKS5WithAuth(sessionID, listenAddr, username, password string) error {
	ac := m.getConn(sessionID)
	if ac == nil {
		return fmt.Errorf("session %s not found", sessionID)
	}
	if ac.Mux == nil {
		return fmt.Errorf("session %s has no mux session", sessionID)
	}

	ac.mu.Lock()
	if ac.socksServer != nil {
		ac.mu.Unlock()
		return fmt.Errorf("SOCKS5 already active on session %s", sessionID)
	}
	cfg := proxy.DefaultConfig()
	cfg.ListenAddr = listenAddr
	cfg.Username = username
	cfg.Password = password
	cfg.Dialer = proxy.NewSessionDialer(ac.Mux)
	cfg.UDPRelay = func(target string, payload []byte) ([]byte, error) {
		return proxy.UDPRelayViaSession(ac.Mux, target, payload, 5*time.Second)
	}

	srv := proxy.NewSOCKS5WithConfig(cfg)
	ctx, cancel := context.WithCancel(context.Background())

	ac.socksServer = srv
	ac.socksCancel = cancel
	ac.mu.Unlock()

	go func() {
		if err := srv.StartWithContext(ctx); err != nil {
			if ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "[!] SOCKS5 error on session %s: %v\n", sessionID, err)
			}
		}
	}()

	return nil
}

// StartSOCKS5Chained starts a SOCKS5 proxy that chains through multiple sessions.
// Traffic flows through each session in order: sessionIDs[0] → [1] → ... → target.
func (m *Manager) StartSOCKS5Chained(sessionIDs []string, listenAddr string) error {
	if len(sessionIDs) == 0 {
		return fmt.Errorf("no sessions specified")
	}
	if len(sessionIDs) == 1 {
		return m.StartSOCKS5(sessionIDs[0], listenAddr)
	}

	var sessions []*mux.Session
	for _, sid := range sessionIDs {
		ac := m.getConn(sid)
		if ac == nil {
			return fmt.Errorf("session %s not found", sid)
		}
		if ac.Mux == nil {
			return fmt.Errorf("session %s has no mux session", sid)
		}
		sessions = append(sessions, ac.Mux)
	}

	firstID := sessionIDs[0]
	ac := m.getConn(firstID)
	ac.mu.Lock()
	if ac.socksServer != nil {
		ac.mu.Unlock()
		return fmt.Errorf("SOCKS5 already active on session %s", firstID)
	}
	cfg := proxy.DefaultConfig()
	cfg.ListenAddr = listenAddr
	cfg.Dialer = proxy.NewChainedSessionDialer(sessions)
	cfg.UDPRelay = func(target string, payload []byte) ([]byte, error) {
		return proxy.UDPRelayViaSession(sessions[len(sessions)-1], target, payload, 5*time.Second)
	}

	srv := proxy.NewSOCKS5WithConfig(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	ac.socksServer = srv
	ac.socksCancel = cancel
	ac.mu.Unlock()

	go func() {
		if err := srv.StartWithContext(ctx); err != nil {
			if ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "[!] SOCKS5 chained error: %v\n", err)
			}
		}
	}()

	return nil
}

// StopSOCKS5 stops the SOCKS5 proxy on the given session.
func (m *Manager) StopSOCKS5(sessionID string) error {
	ac := m.getConn(sessionID)
	if ac == nil {
		return fmt.Errorf("session %s not found", sessionID)
	}

	ac.mu.Lock()
	srv := ac.socksServer
	cancel := ac.socksCancel
	ac.socksServer = nil
	ac.socksCancel = nil
	ac.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if srv != nil {
		srv.Stop()
	}
	return nil
}

// IsSOCKS5Active returns whether SOCKS5 is active on the given session.
func (m *Manager) IsSOCKS5Active(sessionID string) bool {
	ac := m.getConn(sessionID)
	if ac == nil {
		return false
	}
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	return ac.socksServer != nil
}

// SOCKS5Addr returns the SOCKS5 listener address, or empty string if not active.
func (m *Manager) SOCKS5Addr(sessionID string) string {
	ac := m.getConn(sessionID)
	if ac == nil {
		return ""
	}
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	if ac.socksServer != nil {
		return ac.socksServer.Addr()
	}
	return ""
}

// tunRelayToStream reads packets from the TUN interface and writes them to the data stream.
// A per-packet write deadline prevents this goroutine from blocking indefinitely
// if the yamux stream stalls after agent disconnect.
func (m *Manager) tunRelayToStream(ctx context.Context, iface *tun.Interface, ac *AgentConn) {
	buf := make([]byte, tun.DefaultMTU+64)
	ac.mu.RLock()
	stream := ac.tunStream
	ac.mu.RUnlock()
	for {
		if ctx.Err() != nil {
			return
		}
		// Read into buf[4:] to reserve room for the 4-byte length prefix.
		// This eliminates per-packet pool allocation from WriteRawPacket.
		n, err := iface.Read(buf[4:])
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
		// Write length prefix + packet data in a single syscall.
		binary.BigEndian.PutUint32(buf[:4], uint32(n))
		_ = stream.SetWriteDeadline(time.Now().Add(relayWriteTimeout))
		_, writeErr := stream.Write(buf[:4+n])
		_ = stream.SetWriteDeadline(time.Time{})
		if writeErr != nil {
			if ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "[!] TUN write-to-stream error (skipping packet): %v\n", writeErr)
			}
			continue
		}
		ac.bytesOut.Add(int64(n))
	}
}

// tunRelayFromStream reads packets from the data stream and writes them to the TUN interface.
func (m *Manager) tunRelayFromStream(ctx context.Context, iface *tun.Interface, ac *AgentConn) {
	// Wait for stream to become available (matches tunRelayToStream behavior)
	var stream net.Conn
	for stream == nil {
		if ctx.Err() != nil {
			return
		}
		ac.mu.RLock()
		stream = ac.tunStream
		ac.mu.RUnlock()
		if stream == nil {
			select {
			case <-time.After(50 * time.Millisecond):
			case <-ctx.Done():
				return
			}
		}
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

// --- Command Execution ---

// ExecCommand sends a command to the agent and waits for the response.
// Returns the command output or an error. Timeout is 60 seconds.
func (m *Manager) ExecCommand(sessionID, command string) (string, error) {
	ac := m.getConn(sessionID)
	if ac == nil {
		return "", fmt.Errorf("session %s not found", sessionID)
	}
	if ac.Ctrl == nil {
		return "", fmt.Errorf("session %s has no control stream", sessionID)
	}

	execID := genID()
	resultCh := make(chan *protocol.ExecResponsePayload, 1)

	ac.mu.Lock()
	if ac.execResults == nil {
		ac.execResults = make(map[string]chan *protocol.ExecResponsePayload)
	}
	ac.execResults[execID] = resultCh
	ac.mu.Unlock()

	defer func() {
		ac.mu.Lock()
		delete(ac.execResults, execID)
		ac.mu.Unlock()
	}()

	req := &protocol.ExecRequestPayload{
		ID:      execID,
		Command: command,
	}
	msg, err := protocol.EncodeExecRequest(req)
	if err != nil {
		return "", fmt.Errorf("encode exec request: %w", err)
	}
	ac.writeMu.Lock()
	err = ac.writeCtrlMsg(msg)
	ac.writeMu.Unlock()
	if err != nil {
		return "", fmt.Errorf("send exec request: %w", err)
	}

	select {
	case resp, ok := <-resultCh:
		if !ok || resp == nil {
			return "", fmt.Errorf("session disconnected")
		}
		if resp.Error != "" {
			return resp.Output, fmt.Errorf("%s", resp.Error)
		}
		return resp.Output, nil
	case <-time.After(60 * time.Second):
		return "", fmt.Errorf("exec timeout after 60s")
	}
}

// HandleExecResponse routes an exec response to the waiting caller.
func (m *Manager) HandleExecResponse(sessionID string, resp *protocol.ExecResponsePayload) {
	ac := m.getConn(sessionID)
	if ac == nil {
		return
	}
	ac.mu.RLock()
	ch, ok := ac.execResults[resp.ID]
	ac.mu.RUnlock()
	if ok {
		select {
		case ch <- resp:
		default:
		}
	}
}

// --- File Transfer ---

// DownloadFile sends a file download request to the agent and waits for the response.
// Returns the file data or an error. Timeout is 120 seconds.
func (m *Manager) DownloadFile(sessionID, filePath string) (*protocol.FileDownloadResponsePayload, error) {
	ac := m.getConn(sessionID)
	if ac == nil {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}
	if ac.Ctrl == nil {
		return nil, fmt.Errorf("session %s has no control stream", sessionID)
	}

	dlID := genID()
	resultCh := make(chan *protocol.FileDownloadResponsePayload, 1)

	ac.mu.Lock()
	if ac.downloadResults == nil {
		ac.downloadResults = make(map[string]chan *protocol.FileDownloadResponsePayload)
	}
	ac.downloadResults[dlID] = resultCh
	ac.mu.Unlock()

	defer func() {
		ac.mu.Lock()
		delete(ac.downloadResults, dlID)
		ac.mu.Unlock()
	}()

	req := &protocol.FileDownloadRequestPayload{
		ID:       dlID,
		FilePath: filePath,
	}
	msg, err := protocol.EncodeFileDownloadRequest(req)
	if err != nil {
		return nil, fmt.Errorf("encode file download request: %w", err)
	}
	ac.writeMu.Lock()
	err = ac.writeCtrlMsg(msg)
	ac.writeMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("send file download request: %w", err)
	}

	select {
	case resp, ok := <-resultCh:
		if !ok || resp == nil {
			return nil, fmt.Errorf("session disconnected")
		}
		if resp.Error != "" {
			return resp, fmt.Errorf("%s", resp.Error)
		}
		return resp, nil
	case <-time.After(120 * time.Second):
		return nil, fmt.Errorf("file download timeout after 120s")
	}
}

// HandleDownloadResponse routes a file download response to the waiting caller.
func (m *Manager) HandleDownloadResponse(sessionID string, resp *protocol.FileDownloadResponsePayload) {
	ac := m.getConn(sessionID)
	if ac == nil {
		return
	}
	ac.mu.RLock()
	ch, ok := ac.downloadResults[resp.ID]
	ac.mu.RUnlock()
	if ok {
		select {
		case ch <- resp:
		default:
		}
	}
}

// UploadFile sends a file upload request to the agent and waits for the response.
// Returns the response or an error. Timeout is 120 seconds.
func (m *Manager) UploadFile(sessionID, filePath string, data []byte) (*protocol.FileUploadResponsePayload, error) {
	ac := m.getConn(sessionID)
	if ac == nil {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}
	if ac.Ctrl == nil {
		return nil, fmt.Errorf("session %s has no control stream", sessionID)
	}

	ulID := genID()
	resultCh := make(chan *protocol.FileUploadResponsePayload, 1)

	ac.mu.Lock()
	if ac.uploadResults == nil {
		ac.uploadResults = make(map[string]chan *protocol.FileUploadResponsePayload)
	}
	ac.uploadResults[ulID] = resultCh
	ac.mu.Unlock()

	defer func() {
		ac.mu.Lock()
		delete(ac.uploadResults, ulID)
		ac.mu.Unlock()
	}()

	req := &protocol.FileUploadRequestPayload{
		ID:       ulID,
		FilePath: filePath,
		Data:     data,
	}
	msg, err := protocol.EncodeFileUploadRequest(req)
	if err != nil {
		return nil, fmt.Errorf("encode file upload request: %w", err)
	}
	ac.writeMu.Lock()
	err = ac.writeCtrlMsg(msg)
	ac.writeMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("send file upload request: %w", err)
	}

	select {
	case resp, ok := <-resultCh:
		if !ok || resp == nil {
			return nil, fmt.Errorf("session disconnected")
		}
		if resp.Error != "" {
			return resp, fmt.Errorf("%s", resp.Error)
		}
		return resp, nil
	case <-time.After(120 * time.Second):
		return nil, fmt.Errorf("file upload timeout after 120s")
	}
}

// HandleUploadResponse routes a file upload response to the waiting caller.
func (m *Manager) HandleUploadResponse(sessionID string, resp *protocol.FileUploadResponsePayload) {
	ac := m.getConn(sessionID)
	if ac == nil {
		return
	}
	ac.mu.RLock()
	ch, ok := ac.uploadResults[resp.ID]
	ac.mu.RUnlock()
	if ok {
		select {
		case ch <- resp:
		default:
		}
	}
}
