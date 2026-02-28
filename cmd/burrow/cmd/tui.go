package cmd

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/loudmumble/burrow/internal/session"
	"github.com/loudmumble/burrow/internal/web"
)

// ── Styles ──────────────────────────────────────────────────────────────────

var (
	// Primary palette
	stAccent   = lipgloss.NewStyle().Foreground(lipgloss.Color("205")) // pink
	stGreen    = lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	stYellow   = lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
	stRed      = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	stDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	stDimmer   = lipgloss.NewStyle().Foreground(lipgloss.Color("237"))
	stWhite    = lipgloss.NewStyle().Foreground(lipgloss.Color("255"))
	stBold     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("255"))
	stCyan     = lipgloss.NewStyle().Foreground(lipgloss.Color("86"))
	stHeader   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("244"))
	stError    = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	stConfirm  = lipgloss.NewStyle().Foreground(lipgloss.Color("226")).Bold(true)
	stFieldCtr = lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Italic(true)
	stFormBdr  = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))

	// Panel borders
	stPanel = lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("240"))

	// Status bar
	stStatusBar = lipgloss.NewStyle().
			Background(lipgloss.Color("236")).
			Foreground(lipgloss.Color("252")).
			Padding(0, 1)

	// Selected row
	stSelRow = lipgloss.NewStyle().
			Background(lipgloss.Color("236")).
			Bold(true).
			Foreground(lipgloss.Color("86"))

	// Active tab
	stActiveTab = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205")).Underline(true)
	stInactTab  = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
)

// ── View Modes ──────────────────────────────────────────────────────────────

type tuiViewMode int

const (
	tuiViewSessions tuiViewMode = iota
	tuiViewSessionDetail
	tuiViewAddTunnel
	tuiViewAddRoute
	tuiViewConfirmDelete
)

type tuiDetailTab int

const (
	tuiTabTunnels tuiDetailTab = iota
	tuiTabRoutes
)

// ── Log Ring Buffer ─────────────────────────────────────────────────────────

type logEntry struct {
	ts   time.Time
	text string
}

type logRing struct {
	mu      sync.Mutex
	entries []logEntry
	maxSize int
}

func newLogRing(size int) *logRing {
	return &logRing{entries: make([]logEntry, 0, size), maxSize: size}
}

func (r *logRing) add(text string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) >= r.maxSize {
		r.entries = r.entries[1:]
	}
	r.entries = append(r.entries, logEntry{ts: time.Now(), text: text})
}

func (r *logRing) all() []logEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]logEntry, len(r.entries))
	copy(cp, r.entries)
	return cp
}

// ── Rate Tracker ────────────────────────────────────────────────────────────

type rateSnapshot struct {
	prevIn, prevOut int64
	rateIn, rateOut float64 // bytes per second
}

// ── Messages ────────────────────────────────────────────────────────────────

type tuiTickMsg time.Time
type tuiActionDoneMsg string
type tuiActionErrMsg struct{ err error }
type tuiSpinnerTickMsg struct{} // unused, spinner handled internally

// ── Model ───────────────────────────────────────────────────────────────────

type tuiModel struct {
	mgr *session.Manager

	sessions []web.SessionInfo
	tunnels  []web.TunnelInfo
	routes   []web.RouteInfo

	cursor      int
	view        tuiViewMode
	selected    string // selected session ID
	selectedIdx int
	err         error
	errExpiry   time.Time
	width       int
	height      int
	detailTab   tuiDetailTab
	inputFields []string
	inputCursor int
	inputValues []string
	statusMsg   string
	confirmType string
	confirmID   string

	// HUD state
	rates     map[string]*rateSnapshot // session ID -> rate
	logs      *logRing
	startTime time.Time
	spinner   spinner.Model
	spinning  bool // whether a spinner-worthy operation is in progress

	// Viewports for scrollable lists
	sessVP   viewport.Model
	detailVP viewport.Model
}

// ── Init ────────────────────────────────────────────────────────────────────

func (m tuiModel) Init() tea.Cmd {
	return tea.Batch(
		tuiTickCmd(),
		m.spinner.Tick,
	)
}

func tuiTickCmd() tea.Cmd {
	return tea.Tick(5*time.Second, func(t time.Time) tea.Msg {
		return tuiTickMsg(t)
	})
}

// ── Update ──────────────────────────────────────────────────────────────────

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.sessVP.Width = msg.Width
		m.sessVP.Height = max(msg.Height-16, 5)
		m.detailVP.Width = msg.Width
		m.detailVP.Height = max(msg.Height-20, 5)
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case tuiTickMsg:
		m.clearExpiredError()
		m.refreshData()
		return m, tuiTickCmd()

	case tuiActionDoneMsg:
		m.statusMsg = string(msg)
		m.err = nil
		m.errExpiry = time.Time{}
		m.spinning = false
		m.logs.add(string(msg))
		m.refreshData()
		return m, nil

	case tuiActionErrMsg:
		m.err = msg.err
		m.errExpiry = time.Now().Add(10 * time.Second)
		m.statusMsg = ""
		m.spinning = false
		m.logs.add("ERROR: " + msg.err.Error())
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m *tuiModel) refreshData() {
	m.sessions = m.mgr.ListSessions()
	if m.view == tuiViewSessions && m.cursor >= len(m.sessions) && len(m.sessions) > 0 {
		m.cursor = len(m.sessions) - 1
	}

	// Update rates
	for _, s := range m.sessions {
		r, ok := m.rates[s.ID]
		if !ok {
			r = &rateSnapshot{}
			m.rates[s.ID] = r
		}
		deltaIn := s.BytesIn - r.prevIn
		deltaOut := s.BytesOut - r.prevOut
		if deltaIn < 0 {
			deltaIn = 0
		}
		if deltaOut < 0 {
			deltaOut = 0
		}
		r.rateIn = float64(deltaIn) / 5.0
		r.rateOut = float64(deltaOut) / 5.0
		r.prevIn = s.BytesIn
		r.prevOut = s.BytesOut
	}

	if m.view == tuiViewSessionDetail && m.selected != "" {
		m.tunnels = m.mgr.GetTunnels(m.selected)
		m.routes = m.mgr.GetRoutes(m.selected)
		if m.detailTab == tuiTabTunnels && m.cursor >= len(m.tunnels) && len(m.tunnels) > 0 {
			m.cursor = len(m.tunnels) - 1
		}
		if m.detailTab == tuiTabRoutes && m.cursor >= len(m.routes) && len(m.routes) > 0 {
			m.cursor = len(m.routes) - 1
		}
	}
}

func (m *tuiModel) clearExpiredError() {
	if m.err != nil && !m.errExpiry.IsZero() && time.Now().After(m.errExpiry) {
		m.err = nil
		m.errExpiry = time.Time{}
	}
}

// ── Key Handlers ────────────────────────────────────────────────────────────

func (m tuiModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "ctrl+c" {
		return m, tea.Quit
	}
	switch m.view {
	case tuiViewSessions:
		return m.handleSessionsKey(msg)
	case tuiViewSessionDetail:
		return m.handleDetailKey(msg)
	case tuiViewAddTunnel:
		return m.handleFormKey(msg, true)
	case tuiViewAddRoute:
		return m.handleFormKey(msg, false)
	case tuiViewConfirmDelete:
		return m.handleConfirmKey(msg)
	}
	return m, nil
}

func (m tuiModel) handleSessionsKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q":
		return m, tea.Quit
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.sessions)-1 {
			m.cursor++
		}
	case "enter":
		if len(m.sessions) > 0 && m.cursor < len(m.sessions) {
			m.selected = m.sessions[m.cursor].ID
			m.selectedIdx = m.cursor
			m.view = tuiViewSessionDetail
			m.cursor = 0
			m.detailTab = tuiTabTunnels
			m.statusMsg = ""
			m.err = nil
			m.errExpiry = time.Time{}
			m.refreshData()
		}
	case "ctrl+t":
		if len(m.sessions) > 0 && m.cursor < len(m.sessions) {
			s := m.sessions[m.cursor]
			if s.TunActive {
				m.statusMsg = fmt.Sprintf("Stopping TUN on %s...", tuiTruncate(s.ID, 12))
				m.spinning = true
				return m, m.doToggleTUN(s.ID, true)
			}
			m.statusMsg = fmt.Sprintf("Starting TUN on %s...", tuiTruncate(s.ID, 12))
			m.spinning = true
			return m, m.doToggleTUN(s.ID, false)
		}
	case "ctrl+r":
		m.statusMsg = "Refreshing..."
		m.refreshData()
		m.statusMsg = ""
	}
	return m, nil
}

func (m tuiModel) handleDetailKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		m.view = tuiViewSessions
		m.cursor = m.selectedIdx
		m.selected = ""
		m.tunnels = nil
		m.routes = nil
		m.statusMsg = ""
		m.err = nil
		m.errExpiry = time.Time{}
	case "tab":
		if m.detailTab == tuiTabTunnels {
			m.detailTab = tuiTabRoutes
		} else {
			m.detailTab = tuiTabTunnels
		}
		m.cursor = 0
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		maxIdx := m.detailLen() - 1
		if m.cursor < maxIdx {
			m.cursor++
		}
	case "t":
		m.view = tuiViewAddTunnel
		m.inputFields = []string{"Direction", "Listen Address", "Remote Address", "Protocol"}
		m.inputValues = []string{"local", "", "", "tcp"}
		m.inputCursor = 1
		m.statusMsg = ""
		m.err = nil
		m.errExpiry = time.Time{}
	case "r":
		m.view = tuiViewAddRoute
		m.inputFields = []string{"CIDR (e.g. 10.0.0.0/24)"}
		m.inputValues = []string{""}
		m.inputCursor = 0
		m.statusMsg = ""
		m.err = nil
		m.errExpiry = time.Time{}
	case "d", "delete":
		return m.handleDelete()
	case "u":
		if m.detailTab == tuiTabTunnels && m.cursor < len(m.tunnels) {
			t := m.tunnels[m.cursor]
			if !t.Active {
				m.statusMsg = fmt.Sprintf("Starting tunnel %s...", tuiTruncate(t.ID, 12))
				m.spinning = true
				return m, m.doStartTunnel(m.selected, t.ID)
			}
			m.statusMsg = "Tunnel already active"
		}
	case "n":
		if m.detailTab == tuiTabTunnels && m.cursor < len(m.tunnels) {
			t := m.tunnels[m.cursor]
			if t.Active {
				m.statusMsg = fmt.Sprintf("Stopping tunnel %s...", tuiTruncate(t.ID, 12))
				m.spinning = true
				return m, m.doStopTunnel(m.selected, t.ID)
			}
			m.statusMsg = "Tunnel already stopped"
		}
	case "s":
		if m.selected != "" {
			if m.mgr.IsSOCKS5Active(m.selected) {
				m.statusMsg = "Stopping SOCKS5..."
				m.spinning = true
				return m, m.doToggleSOCKS5(m.selected, true)
			}
			m.statusMsg = "Starting SOCKS5 on 127.0.0.1:1080..."
			m.spinning = true
			return m, m.doToggleSOCKS5(m.selected, false)
		}
	case "ctrl+t":
		if m.selected != "" {
			var active bool
			for _, s := range m.sessions {
				if s.ID == m.selected {
					active = s.TunActive
					break
				}
			}
			action := "Starting"
			if active {
				action = "Stopping"
			}
			m.statusMsg = fmt.Sprintf("%s TUN on %s...", action, tuiTruncate(m.selected, 12))
			m.spinning = true
			return m, m.doToggleTUN(m.selected, active)
		}
	case "ctrl+r":
		m.refreshData()
	}
	return m, nil
}

func (m tuiModel) detailLen() int {
	if m.detailTab == tuiTabTunnels {
		return len(m.tunnels)
	}
	return len(m.routes)
}

func (m tuiModel) handleDelete() (tea.Model, tea.Cmd) {
	if m.detailTab == tuiTabTunnels && m.cursor < len(m.tunnels) {
		m.confirmType = "tunnel"
		m.confirmID = m.tunnels[m.cursor].ID
		m.view = tuiViewConfirmDelete
		return m, nil
	}
	if m.detailTab == tuiTabRoutes && m.cursor < len(m.routes) {
		m.confirmType = "route"
		m.confirmID = m.routes[m.cursor].CIDR
		m.view = tuiViewConfirmDelete
		return m, nil
	}
	return m, nil
}

func (m tuiModel) handleConfirmKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y", "Y":
		m.view = tuiViewSessionDetail
		m.statusMsg = ""
		if m.confirmType == "tunnel" {
			return m, m.doRemoveTunnel(m.selected, m.confirmID)
		}
		return m, m.doRemoveRoute(m.selected, m.confirmID)
	case "n", "N", "esc":
		m.view = tuiViewSessionDetail
		m.confirmType = ""
		m.confirmID = ""
	}
	return m, nil
}

func (m tuiModel) handleFormKey(msg tea.KeyMsg, isTunnel bool) (tea.Model, tea.Cmd) {
	key := msg.String()
	switch key {
	case "esc":
		m.view = tuiViewSessionDetail
		m.cursor = 0
		m.err = nil
		m.errExpiry = time.Time{}
		return m, nil
	case "tab", "down":
		m.inputCursor = (m.inputCursor + 1) % len(m.inputFields)
		return m, nil
	case "shift+tab", "up":
		m.inputCursor--
		if m.inputCursor < 0 {
			m.inputCursor = len(m.inputFields) - 1
		}
		return m, nil
	case "enter":
		if isTunnel {
			return m.submitTunnel()
		}
		return m.submitRoute()
	}

	// Toggle fields: Direction (0) and Protocol (3)
	if isTunnel && (m.inputCursor == 0 || m.inputCursor == 3) {
		if key == " " || key == "left" || key == "right" {
			if m.inputCursor == 0 {
				if m.inputValues[0] == "local" {
					m.inputValues[0] = "remote"
				} else {
					m.inputValues[0] = "local"
				}
			} else {
				if m.inputValues[3] == "tcp" {
					m.inputValues[3] = "udp"
				} else {
					m.inputValues[3] = "tcp"
				}
			}
		}
		return m, nil
	}

	// Text input
	switch key {
	case "backspace":
		v := m.inputValues[m.inputCursor]
		if len(v) > 0 {
			m.inputValues[m.inputCursor] = v[:len(v)-1]
		}
	default:
		if len(key) == 1 && key[0] >= 32 && key[0] <= 126 {
			m.inputValues[m.inputCursor] += key
		}
	}
	return m, nil
}

func (m tuiModel) submitTunnel() (tea.Model, tea.Cmd) {
	direction := strings.TrimSpace(m.inputValues[0])
	listen := strings.TrimSpace(m.inputValues[1])
	remote := strings.TrimSpace(m.inputValues[2])
	proto := strings.TrimSpace(m.inputValues[3])
	if direction == "" || listen == "" || remote == "" {
		m.err = fmt.Errorf("direction, listen address, and remote address are required")
		m.errExpiry = time.Now().Add(10 * time.Second)
		return m, nil
	}
	if proto == "" {
		proto = "tcp"
	}
	m.view = tuiViewSessionDetail
	m.cursor = 0
	m.detailTab = tuiTabTunnels
	m.spinning = true
	return m, m.doAddTunnel(m.selected, direction, listen, remote, proto)
}

func (m tuiModel) submitRoute() (tea.Model, tea.Cmd) {
	cidr := strings.TrimSpace(m.inputValues[0])
	if cidr == "" {
		m.err = fmt.Errorf("CIDR is required")
		m.errExpiry = time.Now().Add(10 * time.Second)
		return m, nil
	}
	m.view = tuiViewSessionDetail
	m.cursor = 0
	m.detailTab = tuiTabRoutes
	m.spinning = true
	return m, m.doAddRoute(m.selected, cidr)
}

// ── Tea Commands (in-process, no HTTP) ──────────────────────────────────────

func (m *tuiModel) doAddTunnel(sessionID, direction, listen, remote, proto string) tea.Cmd {
	mgr := m.mgr
	return func() tea.Msg {
		info, err := mgr.AddTunnel(sessionID, direction, listen, remote, proto)
		if err != nil {
			return tuiActionErrMsg{err}
		}
		return tuiActionDoneMsg(fmt.Sprintf("Tunnel %s created (%s)", tuiTruncate(info.ID, 12), direction))
	}
}

func (m *tuiModel) doRemoveTunnel(sessionID, tunnelID string) tea.Cmd {
	mgr := m.mgr
	return func() tea.Msg {
		if err := mgr.RemoveTunnel(sessionID, tunnelID); err != nil {
			return tuiActionErrMsg{err}
		}
		return tuiActionDoneMsg(fmt.Sprintf("Tunnel %s removed", tuiTruncate(tunnelID, 12)))
	}
}

func (m *tuiModel) doStopTunnel(sessionID, tunnelID string) tea.Cmd {
	mgr := m.mgr
	return func() tea.Msg {
		if err := mgr.StopTunnel(sessionID, tunnelID); err != nil {
			return tuiActionErrMsg{err}
		}
		return tuiActionDoneMsg(fmt.Sprintf("Tunnel %s stopped", tuiTruncate(tunnelID, 12)))
	}
}

func (m *tuiModel) doStartTunnel(sessionID, tunnelID string) tea.Cmd {
	mgr := m.mgr
	return func() tea.Msg {
		if err := mgr.StartTunnel(sessionID, tunnelID); err != nil {
			return tuiActionErrMsg{err}
		}
		return tuiActionDoneMsg(fmt.Sprintf("Tunnel %s started", tuiTruncate(tunnelID, 12)))
	}
}

func (m *tuiModel) doAddRoute(sessionID, cidr string) tea.Cmd {
	mgr := m.mgr
	return func() tea.Msg {
		if _, err := mgr.AddRoute(sessionID, cidr); err != nil {
			return tuiActionErrMsg{err}
		}
		return tuiActionDoneMsg(fmt.Sprintf("Route %s added", cidr))
	}
}

func (m *tuiModel) doRemoveRoute(sessionID, cidr string) tea.Cmd {
	mgr := m.mgr
	return func() tea.Msg {
		if err := mgr.RemoveRoute(sessionID, cidr); err != nil {
			return tuiActionErrMsg{err}
		}
		return tuiActionDoneMsg(fmt.Sprintf("Route %s removed", cidr))
	}
}

func (m *tuiModel) doToggleTUN(sessionID string, active bool) tea.Cmd {
	mgr := m.mgr
	return func() tea.Msg {
		if active {
			if err := mgr.StopTun(sessionID); err != nil {
				return tuiActionErrMsg{err}
			}
			return tuiActionDoneMsg("TUN stopped")
		}
		if err := mgr.StartTun(sessionID); err != nil {
			return tuiActionErrMsg{err}
		}
		return tuiActionDoneMsg("TUN started — add routes with 'r'")
	}
}

func (m *tuiModel) doToggleSOCKS5(sessionID string, active bool) tea.Cmd {
	mgr := m.mgr
	return func() tea.Msg {
		if active {
			if err := mgr.StopSOCKS5(sessionID); err != nil {
				return tuiActionErrMsg{err}
			}
			return tuiActionDoneMsg("SOCKS5 stopped")
		}
		if err := mgr.StartSOCKS5(sessionID, "127.0.0.1:1080"); err != nil {
			return tuiActionErrMsg{err}
		}
		addr := mgr.SOCKS5Addr(sessionID)
		return tuiActionDoneMsg(fmt.Sprintf("SOCKS5 started on %s", addr))
	}
}

// ── View ────────────────────────────────────────────────────────────────────

func (m tuiModel) View() string {
	if m.width == 0 {
		return "Loading..."
	}
	var b strings.Builder
	switch m.view {
	case tuiViewSessions:
		m.viewSessions(&b)
	case tuiViewSessionDetail:
		m.viewDetail(&b)
	case tuiViewAddTunnel:
		m.viewForm(&b, "Add Tunnel")
	case tuiViewAddRoute:
		m.viewForm(&b, "Add Route")
	case tuiViewConfirmDelete:
		m.viewConfirm(&b)
	}

	// Status bar at bottom
	b.WriteString("\n")
	b.WriteString(m.renderStatusBar())

	return b.String()
}

// ── Banner ──────────────────────────────────────────────────────────────────

func (m tuiModel) renderBanner(b *strings.Builder) {
	title := stAccent.Bold(true).Render("  ╔══╗ ╦ ╦ ╦═╗ ╦═╗ ╔══╗ ╦   ╦")
	title2 := stAccent.Bold(true).Render("  ╠══╣ ║ ║ ╠╦╝ ╠╦╝ ║  ║ ║ ╦ ║")
	title3 := stAccent.Bold(true).Render("  ╚══╝ ╚═╝ ╩╚═ ╩╚═ ╚══╝ ╚═╝═╝")
	b.WriteString(title + "\n")
	b.WriteString(title2 + "\n")
	b.WriteString(title3 + "  " + stDim.Render("v"+version+" │ pentest pivoting") + "\n")
}

// ── Status Bar ──────────────────────────────────────────────────────────────

func (m tuiModel) renderStatusBar() string {
	uptime := time.Since(m.startTime)
	uptimeStr := fmt.Sprintf("%02d:%02d:%02d", int(uptime.Hours()), int(uptime.Minutes())%60, int(uptime.Seconds())%60)

	agentCount := 0
	activeCount := 0
	var totalIn, totalOut int64
	socksCount := 0
	socksAddr := "--"
	tunCount := 0

	for _, s := range m.sessions {
		agentCount++
		if s.Active {
			activeCount++
		}
		totalIn += s.BytesIn
		totalOut += s.BytesOut
		if s.TunActive {
			tunCount++
		}
		if s.SocksAddr != "" {
			socksCount++
			socksAddr = s.SocksAddr
		}
	}

	parts := []string{
		stAccent.Render("burrow"),
		stDim.Render(uptimeStr),
		fmt.Sprintf("%d agents", activeCount),
		fmt.Sprintf("TUN: %s", func() string {
			if tunCount > 0 {
				return stGreen.Render("active")
			}
			return stDim.Render("--")
		}()),
		fmt.Sprintf("SOCKS: %s", func() string {
			if socksCount > 0 {
				return stGreen.Render(socksAddr)
			}
			return stDim.Render("--")
		}()),
		stGreen.Render("▲"+tuiFormatBytes(totalOut)) + " " + stCyan.Render("▼"+tuiFormatBytes(totalIn)),
	}

	spinStr := ""
	if m.spinning {
		spinStr = " " + m.spinner.View() + " "
	}

	bar := "  " + strings.Join(parts, stDim.Render(" │ ")) + spinStr
	pad := max(0, m.width-lipgloss.Width(bar))
	return stStatusBar.Width(m.width).Render(bar + strings.Repeat(" ", pad))
}

// ── Session List View ───────────────────────────────────────────────────────

func (m tuiModel) viewSessions(b *strings.Builder) {
	m.renderBanner(b)
	b.WriteString("\n")

	if m.err != nil {
		b.WriteString(stError.Render("  ✗ "+m.err.Error()) + "\n\n")
	}

	if len(m.sessions) == 0 {
		b.WriteString(stDim.Render("  No sessions. Waiting for agents to connect...") + "\n")
	} else {
		// Header
		hdr := fmt.Sprintf("  %-18s %-12s %-6s %-18s %-7s %-6s %-7s %12s %12s  %-10s  %-6s",
			"ID", "HOST", "OS", "IPs", "TUN", "SOCKS", "STATUS", "▲ OUT", "▼ IN", "RATE", "UPTIME")
		b.WriteString(stHeader.Render(hdr) + "\n")
		b.WriteString(renderSep(m.width) + "\n")

		for i, s := range m.sessions {
			ips := strings.Join(s.IPs, ",")
			if len(ips) > 16 {
				ips = ips[:13] + "..."
			}

			statusStr := stRed.Render("dead  ")
			if s.Active {
				statusStr = stGreen.Render("active")
			}

			tunStr := stDim.Render("── ")
			if s.TunActive {
				tunStr = stGreen.Bold(true).Render("TUN")
			}

			socksStr := stDim.Render("── ")
			if s.SocksAddr != "" {
				socksStr = stGreen.Render("SOC")
			}

			// Health indicator (green dot = active)
			healthDot := stGreen.Render("●")
			if !s.Active {
				healthDot = stRed.Render("●")
			}

			// Rate
			rate := m.rates[s.ID]
			rateStr := ""
			if rate != nil && (rate.rateIn > 0 || rate.rateOut > 0) {
				rateStr = fmt.Sprintf("▲%s ▼%s",
					tuiFormatRate(rate.rateOut), tuiFormatRate(rate.rateIn))
			}

			cols := fmt.Sprintf("%-18s %-12s %-6s %-18s",
				tuiTruncate(s.ID, 16),
				tuiTruncate(s.Hostname, 10),
				tuiTruncate(s.OS, 4),
				ips)

			bwOut := tuiColorBytes(s.BytesOut)
			bwIn := tuiColorBytes(s.BytesIn)

			uptime := tuiFormatUptime(s.CreatedAt)

			// Bandwidth bar
			bwBar := renderBwBar(m.rates[s.ID])

			line := fmt.Sprintf("%s %s %s %s %12s %12s  %-10s  %-6s %s",
				cols, tunStr, socksStr, statusStr, bwOut, bwIn,
				rateStr, uptime, bwBar)

			if i == m.cursor {
				// Full-width highlight on selected row
				highlighted := stSelRow.Width(m.width).Render("▸ " + healthDot + " " + line)
				b.WriteString(highlighted + "\n")
			} else {
				b.WriteString("  " + healthDot + " " + line + "\n")
			}
		}
	}

	// Log panel
	b.WriteString("\n")
	m.renderLogPanel(b)

	if m.statusMsg != "" {
		b.WriteString("\n" + stGreen.Render("  "+m.statusMsg))
	}

	b.WriteString("\n\n")
	b.WriteString(renderHelpBar([]string{
		"↑/k up", "↓/j down", "enter select", "^T toggle TUN", "^R refresh", "q quit",
	}))
}

// ── Session Detail View ─────────────────────────────────────────────────────

func (m tuiModel) viewDetail(b *strings.Builder) {
	var sess *web.SessionInfo
	for i := range m.sessions {
		if m.sessions[i].ID == m.selected {
			sess = &m.sessions[i]
			break
		}
	}

	m.renderBanner(b)
	b.WriteString("\n")

	if sess != nil {
		// Info panel
		boxW := min(m.width-4, 65)
		if boxW < 30 {
			boxW = 30
		}

		statusStr := stRed.Render("inactive")
		healthDot := stRed.Render("●")
		if sess.Active {
			statusStr = stGreen.Render("active")
			healthDot = stGreen.Render("●")
		}

		tunStr := stDim.Render("TUN --")
		if sess.TunActive {
			tunStr = stGreen.Bold(true).Render("TUN UP")
		}

		socksStr := stDim.Render("SOCKS --")
		if sess.SocksAddr != "" {
			socksStr = stGreen.Bold(true).Render("SOCKS " + sess.SocksAddr)
		}

		rate := m.rates[sess.ID]
		rateStr := ""
		if rate != nil {
			rateStr = fmt.Sprintf("▲ %s/s  ▼ %s/s", tuiFormatRate(rate.rateOut), tuiFormatRate(rate.rateIn))
		}

		bwBar := renderBwBar(rate)

		infoContent := strings.Join([]string{
			fmt.Sprintf("  %s Session:   %s", healthDot, sess.ID),
			fmt.Sprintf("  Hostname:  %s", sess.Hostname),
			fmt.Sprintf("  OS:        %s", sess.OS),
			fmt.Sprintf("  IPs:       %s", strings.Join(sess.IPs, ", ")),
			fmt.Sprintf("  Status:    %s  %s  %s", statusStr, tunStr, socksStr),
			fmt.Sprintf("  Created:   %s (%s ago)", sess.CreatedAt, tuiFormatUptime(sess.CreatedAt)),
			fmt.Sprintf("  Bandwidth: %s in / %s out  %s", tuiColorBytes(sess.BytesIn), tuiColorBytes(sess.BytesOut), rateStr),
			fmt.Sprintf("  Rate:      %s", bwBar),
		}, "\n")

		panel := stPanel.Width(boxW).Render(infoContent)
		b.WriteString(panel + "\n")
	} else {
		b.WriteString(stDim.Render("  Session data not available") + "\n")
	}

	b.WriteString("\n")

	// Tabs
	var tunnelTab, routeTab string
	if m.detailTab == tuiTabTunnels {
		tunnelTab = stActiveTab.Render(" Tunnels ")
		routeTab = stInactTab.Render(" Routes ")
	} else {
		tunnelTab = stInactTab.Render(" Tunnels ")
		routeTab = stActiveTab.Render(" Routes ")
	}
	b.WriteString("  " + tunnelTab + "  " + routeTab + "\n")
	b.WriteString(renderSep(m.width) + "\n")

	if m.detailTab == tuiTabTunnels {
		m.viewTunnels(b)
	} else {
		m.viewRoutes(b)
	}

	if m.err != nil {
		b.WriteString("\n" + stError.Render("  ✗ "+m.err.Error()))
	}
	if m.statusMsg != "" {
		b.WriteString("\n" + stGreen.Render("  "+m.statusMsg))
	}

	// Log panel
	b.WriteString("\n")
	m.renderLogPanel(b)

	b.WriteString("\n\n")
	b.WriteString(renderHelpBar([]string{
		"↑/k up", "↓/j down", "^T TUN", "s SOCKS5", "t tunnel", "r route",
		"u start", "n stop", "d delete", "tab switch", "esc back",
	}))
}

func (m tuiModel) viewTunnels(b *strings.Builder) {
	if len(m.tunnels) == 0 {
		b.WriteString(stDim.Render("  (no tunnels)") + "\n")
		return
	}

	hdr := fmt.Sprintf("  %-16s  %-7s  %-22s  %-22s  %-5s  %10s  %10s  %-7s",
		"ID", "DIR", "LISTEN", "REMOTE", "PROTO", "▲ OUT", "▼ IN", "STATUS")
	b.WriteString(stHeader.Render(hdr) + "\n")

	for i, t := range m.tunnels {
		statusStr := stRed.Render("dead  ")
		if t.Active {
			statusStr = stGreen.Render("active")
		} else if t.Error != "" {
			statusStr = stRed.Render("error ")
		}

		cols := fmt.Sprintf("%-16s  %-7s  %-22s  %-22s  %-5s",
			tuiTruncate(t.ID, 16),
			t.Direction,
			tuiTruncate(t.ListenAddr, 22),
			tuiTruncate(t.RemoteAddr, 22),
			t.Protocol)

		bwStr := fmt.Sprintf("  %10s  %10s", tuiColorBytes(t.BytesOut), tuiColorBytes(t.BytesIn))

		errSuffix := ""
		if t.Error != "" {
			errSuffix = " " + stError.Render(tuiTruncate(t.Error, 30))
		}

		if i == m.cursor {
			b.WriteString(stSelRow.Width(m.width).Render("▸ "+cols+bwStr+" "+lipgloss.NewStyle().Render(statusStr)+errSuffix) + "\n")
		} else {
			b.WriteString("  " + cols + bwStr + " " + statusStr + errSuffix + "\n")
		}
	}
}

func (m tuiModel) viewRoutes(b *strings.Builder) {
	if len(m.routes) == 0 {
		b.WriteString(stDim.Render("  (no routes)") + "\n")
		return
	}

	hdr := fmt.Sprintf("  %-30s %-7s", "CIDR", "STATUS")
	b.WriteString(stHeader.Render(hdr) + "\n")

	for i, r := range m.routes {
		statusStr := stRed.Render("dead  ")
		if r.Active {
			statusStr = stGreen.Render("active")
		}

		if i == m.cursor {
			b.WriteString(stSelRow.Width(m.width).Render(fmt.Sprintf("▸ %-30s %s", r.CIDR, statusStr)) + "\n")
		} else {
			b.WriteString(fmt.Sprintf("  %-30s %s", r.CIDR, statusStr) + "\n")
		}
	}
}

// ── Confirm Delete ──────────────────────────────────────────────────────────

func (m tuiModel) viewConfirm(b *strings.Builder) {
	m.renderBanner(b)
	b.WriteString("\n")

	boxW := min(m.width-4, 50)
	if boxW < 30 {
		boxW = 30
	}

	content := strings.Join([]string{
		"",
		stConfirm.Render(fmt.Sprintf("  Delete %s %s?", m.confirmType, tuiTruncate(m.confirmID, boxW-20))),
		"",
		stDim.Render("  Press y to confirm, n or esc to cancel"),
		"",
	}, "\n")

	panel := stPanel.Width(boxW).Render(content)
	b.WriteString(panel + "\n\n")
	b.WriteString(renderHelpBar([]string{"y confirm", "n cancel", "esc cancel"}))
}

// ── Form View ───────────────────────────────────────────────────────────────

func (m tuiModel) viewForm(b *strings.Builder, title string) {
	m.renderBanner(b)
	b.WriteString("\n")
	b.WriteString(stAccent.Bold(true).Render(fmt.Sprintf("  %s", title)))
	b.WriteString(stFieldCtr.Render(fmt.Sprintf("  (Field %d/%d)", m.inputCursor+1, len(m.inputFields))))
	b.WriteString("\n")
	b.WriteString(stDim.Render(fmt.Sprintf("  Session: %s", m.selected)) + "\n")
	b.WriteString(renderSep(m.width) + "\n\n")

	if m.err != nil {
		b.WriteString(stError.Render("  ✗ "+m.err.Error()) + "\n\n")
	}

	isTunnelForm := title == "Add Tunnel"
	boxW := min(m.width-8, 50)
	if boxW < 20 {
		boxW = 20
	}

	for i, field := range m.inputFields {
		label := field + ":"
		value := m.inputValues[i]
		isToggle := isTunnelForm && (i == 0 || i == 3)
		focused := i == m.inputCursor

		if focused {
			b.WriteString(stCyan.Bold(true).Render("▸ ") + stCyan.Bold(true).Render(label) + "\n")
		} else {
			b.WriteString("  " + stDim.Render(label) + "\n")
		}

		if isToggle {
			var options []string
			if i == 0 {
				options = []string{"local", "remote"}
			} else {
				options = []string{"tcp", "udp"}
			}
			var parts []string
			for _, opt := range options {
				if opt == value {
					if focused {
						parts = append(parts, stCyan.Bold(true).Render(" ["+opt+"] "))
					} else {
						parts = append(parts, " ["+opt+"] ")
					}
				} else {
					parts = append(parts, stDim.Render("  "+opt+"  "))
				}
			}
			optStr := strings.Join(parts, "")
			if focused {
				b.WriteString("    ┌" + strings.Repeat("─", boxW) + "┐\n")
				b.WriteString("    │ " + optStr + strings.Repeat(" ", max(0, boxW-1-len(optStr)/2)) + "│\n")
				b.WriteString("    └" + strings.Repeat("─", boxW) + "┘\n")
			} else {
				b.WriteString(stFormBdr.Render("    ┌"+strings.Repeat("─", boxW)+"┐") + "\n")
				b.WriteString(stFormBdr.Render("    │ ") + optStr + stFormBdr.Render(strings.Repeat(" ", max(0, boxW-1-len(optStr)/2))+"│") + "\n")
				b.WriteString(stFormBdr.Render("    └"+strings.Repeat("─", boxW)+"┘") + "\n")
			}
		} else {
			cursor := ""
			if focused {
				cursor = stCyan.Bold(true).Render("█")
			}
			displayVal := value + cursor
			valWidth := len(value)
			if focused {
				valWidth++
			}
			padding := max(0, boxW-2-valWidth)

			if focused {
				b.WriteString("    ┌" + strings.Repeat("─", boxW) + "┐\n")
				b.WriteString("    │ " + displayVal + strings.Repeat(" ", padding) + " │\n")
				b.WriteString("    └" + strings.Repeat("─", boxW) + "┘\n")
			} else {
				b.WriteString(stFormBdr.Render("    ┌"+strings.Repeat("─", boxW)+"┐") + "\n")
				b.WriteString(stFormBdr.Render("    │ ") + value + stFormBdr.Render(strings.Repeat(" ", padding+1)+"│") + "\n")
				b.WriteString(stFormBdr.Render("    └"+strings.Repeat("─", boxW)+"┘") + "\n")
			}
		}
		b.WriteString("\n")
	}

	b.WriteString(renderHelpBar([]string{
		"enter submit", "tab/↓ next", "shift+tab/↑ prev", "space toggle", "esc cancel",
	}))
}

// ── Log Panel ───────────────────────────────────────────────────────────────

func (m tuiModel) renderLogPanel(b *strings.Builder) {
	entries := m.logs.all()
	if len(entries) == 0 {
		return
	}

	maxLines := 5
	start := 0
	if len(entries) > maxLines {
		start = len(entries) - maxLines
	}

	b.WriteString(stDim.Render("  ── log ") + stDimmer.Render(strings.Repeat("─", max(0, min(m.width-13, 60)))) + "\n")
	for _, e := range entries[start:] {
		ts := e.ts.Format("15:04:05")
		b.WriteString(stDimmer.Render("  "+ts+" ") + stDim.Render(tuiTruncate(e.text, m.width-14)) + "\n")
	}
}

// ── Bandwidth Bar ───────────────────────────────────────────────────────────

func renderBwBar(rate *rateSnapshot) string {
	if rate == nil {
		return ""
	}
	// Scale: 10 blocks, max 10MB/s
	const maxRate = 10 * 1024 * 1024
	const barLen = 10
	total := rate.rateIn + rate.rateOut
	filled := int(total / maxRate * barLen)
	if filled > barLen {
		filled = barLen
	}
	if total > 0 && filled == 0 {
		filled = 1
	}

	bar := ""
	for i := 0; i < barLen; i++ {
		if i < filled {
			switch {
			case i < barLen/3:
				bar += stGreen.Render("▰")
			case i < 2*barLen/3:
				bar += stYellow.Render("▰")
			default:
				bar += stRed.Render("▰")
			}
		} else {
			bar += stDimmer.Render("▱")
		}
	}
	return bar
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func renderSep(width int) string {
	w := min(width-4, 100)
	if w < 10 {
		w = 10
	}
	return stDim.Render("  " + strings.Repeat("─", w))
}

func renderHelpBar(items []string) string {
	return stDim.Render("  " + strings.Join(items, " │ "))
}

func tuiFormatBytes(b int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.1fG", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1fM", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1fK", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

func tuiFormatRate(bytesPerSec float64) string {
	const (
		KB = 1024.0
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case bytesPerSec >= GB:
		return fmt.Sprintf("%.1fG/s", bytesPerSec/GB)
	case bytesPerSec >= MB:
		return fmt.Sprintf("%.1fM/s", bytesPerSec/MB)
	case bytesPerSec >= KB:
		return fmt.Sprintf("%.1fK/s", bytesPerSec/KB)
	case bytesPerSec > 0:
		return fmt.Sprintf("%.0fB/s", bytesPerSec)
	default:
		return "0B/s"
	}
}

func tuiColorBytes(b int64) string {
	text := tuiFormatBytes(b)
	const MB = 1024 * 1024
	switch {
	case b >= 100*MB:
		return stRed.Render(text)
	case b >= MB:
		return stYellow.Render(text)
	default:
		return stGreen.Render(text)
	}
}

func tuiFormatUptime(createdAt string) string {
	t, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return "?"
	}
	d := time.Since(t)
	if d < 0 {
		d = 0
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, minutes)
	case minutes > 0:
		return fmt.Sprintf("%dm", minutes)
	default:
		return "< 1m"
	}
}

func tuiTruncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// ── RunTUI ──────────────────────────────────────────────────────────────────

// RunTUI launches the interactive TUI dashboard, talking directly to the
// session.Manager in-process (no HTTP). Blocks until the user exits.
func RunTUI(mgr *session.Manager) error {
	sp := spinner.New()
	sp.Spinner = spinner.Spinner{
		Frames: []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		FPS:    100 * time.Millisecond,
	}
	sp.Style = stCyan

	m := tuiModel{
		mgr:       mgr,
		rates:     make(map[string]*rateSnapshot),
		logs:      newLogRing(20),
		startTime: time.Now(),
		spinner:   sp,
		sessVP:    viewport.New(80, 20),
		detailVP:  viewport.New(80, 20),
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
