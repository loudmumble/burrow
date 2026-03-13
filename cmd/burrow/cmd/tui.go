package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
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
	tuiViewExec
	tuiViewDownload
	tuiViewUpload
	tuiViewHelp
	tuiViewExecHistory
	tuiViewConfirmKill
	tuiViewLabelInput
	tuiViewProfileMenu
	tuiViewProfileName
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

// ── Rate Tracker (Feature 8: EMA smoothing) ─────────────────────────────────

type rateSnapshot struct {
	prevIn, prevOut int64
	rateIn, rateOut float64 // EMA-smoothed bytes per second
}

// ── Sparkline Data (Feature 10) ─────────────────────────────────────────────

type sparkData struct {
	samples [30]float64
	idx     int
	count   int
}

func (s *sparkData) push(val float64) {
	s.samples[s.idx] = val
	s.idx = (s.idx + 1) % 30
	if s.count < 30 {
		s.count++
	}
}

func (s *sparkData) render(width int) string {
	if s.count == 0 {
		return strings.Repeat(" ", width)
	}
	blocks := []rune("▁▂▃▄▅▆▇█")
	// Find max for scaling
	maxVal := 0.0
	for i := 0; i < s.count; i++ {
		idx := (s.idx - s.count + i + 30) % 30
		if s.samples[idx] > maxVal {
			maxVal = s.samples[idx]
		}
	}
	if maxVal == 0 {
		maxVal = 1
	}

	// Take last 'width' samples
	start := 0
	if s.count > width {
		start = s.count - width
	}
	var sb strings.Builder
	for i := start; i < s.count; i++ {
		idx := (s.idx - s.count + i + 30) % 30
		level := int(s.samples[idx] / maxVal * 7)
		if level > 7 {
			level = 7
		}
		if level < 0 {
			level = 0
		}
		sb.WriteRune(blocks[level])
	}
	// Pad to width
	for sb.Len() < width {
		sb.WriteString(" ")
	}
	return sb.String()
}

// ── Exec History (Feature 4) ────────────────────────────────────────────────

type execEntry struct {
	ts      time.Time
	command string
	output  string
	err     string
}

// ── Profile Entry (Feature 12) ──────────────────────────────────────────────

type profileEntry struct {
	Direction  string `json:"direction"`
	ListenAddr string `json:"listen_addr"`
	RemoteAddr string `json:"remote_addr"`
	Protocol   string `json:"protocol"`
}

// ── Messages ────────────────────────────────────────────────────────────────

type tuiTickMsg time.Time
type tuiActionDoneMsg string
type tuiActionErrMsg struct{ err error }
type tuiExecResultMsg struct {
	output  string
	err     error
	command string
}
type tuiDownloadResultMsg struct {
	fileName string
	size     int64
	err      error
}
type tuiUploadResultMsg struct {
	size int64
	err  error
}
type tuiEventMsg struct{ event web.Event }

// ── Model ───────────────────────────────────────────────────────────────────

type tuiModel struct {
	mgr *session.Manager

	sessions []web.SessionInfo
	tunnels  []web.TunnelInfo
	routes   []web.RouteInfo

	cursor       int
	scrollOffset int // Feature 1: viewport scrolling
	view         tuiViewMode
	selected     string // selected session ID
	selectedIdx  int
	err          error
	errExpiry    time.Time
	width        int
	height       int
	detailTab    tuiDetailTab
	inputFields  []string
	inputCursor  int
	inputValues  []string
	statusMsg    string
	statusExpiry time.Time // Feature 9: auto-clear
	confirmType  string
	confirmID    string

	// HUD state
	rates     map[string]*rateSnapshot // session ID -> rate
	sparks    map[string]*sparkData    // Feature 10: session ID -> sparkline
	logs      *logRing
	startTime time.Time
	spinner   spinner.Model
	spinning  bool // whether a spinner-worthy operation is in progress
	tickCount int  // used for rate interval calculation

	// Feature 4: exec history
	execHistory []execEntry
	execScroll  int

	// Feature 12: profiles
	profiles    map[string][]profileEntry
	profileList []string // sorted profile names for display
	profileIdx  int

	// Feature 6: label input
	labelInput string

	serverFingerprint string
	serverLogBuf      *tuiLogCapture
}

// ── Init ────────────────────────────────────────────────────────────────────

func (m tuiModel) Init() tea.Cmd {
	return tea.Batch(
		tuiTickCmd(),
		m.spinner.Tick,
	)
}

func tuiTickCmd() tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg { // Feature 2: 2s tick
		return tuiTickMsg(t)
	})
}

// ── Update ──────────────────────────────────────────────────────────────────

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = min(msg.Width, 100)
		m.height = min(msg.Height, 30)
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case tuiTickMsg:
		m.clearExpiredError()
		m.clearExpiredStatus() // Feature 9
		if m.serverLogBuf != nil {
			for _, entry := range m.serverLogBuf.drain() {
				m.logs.add(entry)
			}
		}
		m.refreshData()
		return m, tuiTickCmd()

	case tuiActionDoneMsg:
		m.statusMsg = string(msg)
		m.statusExpiry = time.Now().Add(5 * time.Second)
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

	case tuiExecResultMsg:
		m.spinning = false
		// Feature 4: store in exec history
		entry := execEntry{
			ts:      time.Now(),
			command: msg.command,
		}
		if msg.output != "" {
			entry.output = msg.output
			for _, line := range strings.Split(msg.output, "\n") {
				line = strings.TrimRight(line, "\r")
				if line != "" {
					m.logs.add("  " + line)
				}
			}
		}
		if msg.err != nil {
			entry.err = msg.err.Error()
			m.logs.add("exec error: " + msg.err.Error())
			m.err = msg.err
			m.errExpiry = time.Now().Add(10 * time.Second)
		} else if msg.output == "" {
			m.statusMsg = "Command executed (no output)"
			m.statusExpiry = time.Now().Add(5 * time.Second)
			m.logs.add("exec: (no output)")
		} else {
			m.statusMsg = fmt.Sprintf("Exec done (%d bytes)", len(msg.output))
			m.statusExpiry = time.Now().Add(5 * time.Second)
		}
		// Store in ring buffer (max 50)
		if len(m.execHistory) >= 50 {
			m.execHistory = m.execHistory[1:]
		}
		m.execHistory = append(m.execHistory, entry)
		m.refreshData()
		return m, nil

	case tuiDownloadResultMsg:
		m.spinning = false
		if msg.err != nil {
			m.logs.add("download error: " + msg.err.Error())
			m.err = msg.err
			m.errExpiry = time.Now().Add(10 * time.Second)
		} else {
			m.statusMsg = fmt.Sprintf("Downloaded %s (%s)", msg.fileName, tuiFormatBytes(msg.size))
			m.statusExpiry = time.Now().Add(5 * time.Second)
			m.logs.add(fmt.Sprintf("download: %s (%s)", msg.fileName, tuiFormatBytes(msg.size)))
		}
		m.refreshData()
		return m, nil

	case tuiUploadResultMsg:
		m.spinning = false
		if msg.err != nil {
			m.logs.add("upload error: " + msg.err.Error())
			m.err = msg.err
			m.errExpiry = time.Now().Add(10 * time.Second)
		} else {
			m.statusMsg = fmt.Sprintf("Uploaded (%s)", tuiFormatBytes(msg.size))
			m.statusExpiry = time.Now().Add(5 * time.Second)
			m.logs.add(fmt.Sprintf("upload: %s written", tuiFormatBytes(msg.size)))
		}
		m.refreshData()
		return m, nil

	case tuiEventMsg:
		// Feature 2: instant refresh on EventBus events
		m.refreshData()
		evtType := string(msg.event.Type)
		m.logs.add("event: " + evtType)
		return m, nil
	}

	return m, nil
}

func (m *tuiModel) refreshData() {
	m.sessions = m.mgr.ListSessions()
	if m.view == tuiViewSessions && m.cursor >= len(m.sessions) && len(m.sessions) > 0 {
		m.cursor = len(m.sessions) - 1
	}

	interval := 2.0 // tick interval in seconds
	const emaAlpha = 0.3

	// Update rates with EMA smoothing (Feature 8)
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
		instantIn := float64(deltaIn) / interval
		instantOut := float64(deltaOut) / interval
		if r.prevIn == 0 && r.prevOut == 0 {
			// First sample: use instant rate
			r.rateIn = instantIn
			r.rateOut = instantOut
		} else {
			r.rateIn = (1-emaAlpha)*r.rateIn + emaAlpha*instantIn
			r.rateOut = (1-emaAlpha)*r.rateOut + emaAlpha*instantOut
		}
		r.prevIn = s.BytesIn
		r.prevOut = s.BytesOut

		// Feature 10: push rate sample into sparkline
		sp, ok := m.sparks[s.ID]
		if !ok {
			sp = &sparkData{}
			m.sparks[s.ID] = sp
		}
		sp.push(r.rateIn + r.rateOut)
	}
	// Clean stale rates/sparks for sessions no longer present
	for id := range m.rates {
		found := false
		for _, s := range m.sessions {
			if s.ID == id {
				found = true
				break
			}
		}
		if !found {
			delete(m.rates, id)
			delete(m.sparks, id)
		}
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

// Feature 9: auto-clear status message
func (m *tuiModel) clearExpiredStatus() {
	if m.statusMsg != "" && !m.statusExpiry.IsZero() && time.Now().After(m.statusExpiry) {
		// Don't auto-clear persistent warnings (start with "!")
		if !strings.HasPrefix(m.statusMsg, "!") {
			m.statusMsg = ""
			m.statusExpiry = time.Time{}
		}
	}
}

// ── Visible Rows Calculation (Feature 1) ────────────────────────────────────

// visibleSessionRows returns how many session rows fit in the terminal
// considering banner (3) + header (2) + log panel (5) + help bar (1) + status bar (2) + error/status (1)
func (m tuiModel) visibleSessionRows() int {
	overhead := 15 // banner(3) + err(1) + hdr(2) + log(6) + status_msg(1) + help(1) + status_bar(2)
	rows := m.height - overhead
	if rows < 3 {
		rows = 3
	}
	return rows
}

// visibleDetailRows for tunnels/routes list in detail view
func (m tuiModel) visibleDetailRows() int {
	overhead := 20 // compact_banner(1) + nl(1) + info(4) + nl(1) + tabs(2) + hdr(1) + err/status(2) + log(5) + help(2) + status_bar(2)
	rows := m.height - overhead
	if rows < 3 {
		rows = 3
	}
	return rows
}

// ensureCursorVisible adjusts scrollOffset so cursor is always in the visible window
func (m *tuiModel) ensureCursorVisible(totalItems, visRows int) {
	if m.cursor < m.scrollOffset {
		m.scrollOffset = m.cursor
	}
	if m.cursor >= m.scrollOffset+visRows {
		m.scrollOffset = m.cursor - visRows + 1
	}
	if m.scrollOffset < 0 {
		m.scrollOffset = 0
	}
	maxOffset := totalItems - visRows
	if maxOffset < 0 {
		maxOffset = 0
	}
	if m.scrollOffset > maxOffset {
		m.scrollOffset = maxOffset
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
	case tuiViewExec:
		return m.handleExecKey(msg)
	case tuiViewDownload:
		return m.handleDownloadKey(msg)
	case tuiViewUpload:
		return m.handleUploadKey(msg)
	case tuiViewHelp:
		return m.handleHelpKey(msg)
	case tuiViewExecHistory:
		return m.handleExecHistoryKey(msg)
	case tuiViewConfirmKill:
		return m.handleConfirmKillKey(msg)
	case tuiViewLabelInput:
		return m.handleLabelInputKey(msg)
	case tuiViewProfileMenu:
		return m.handleProfileMenuKey(msg)
	case tuiViewProfileName:
		return m.handleProfileNameKey(msg)
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
			m.scrollOffset = 0
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
	case "G", "end":
		if len(m.sessions) > 0 {
			m.cursor = len(m.sessions) - 1
		}
	case "g", "home":
		m.cursor = 0
		m.scrollOffset = 0
	case "?":
		m.view = tuiViewHelp
	case "ctrl+r":
		m.statusMsg = "Refreshing..."
		m.statusExpiry = time.Now().Add(3 * time.Second)
		m.refreshData()
		m.statusMsg = ""

	// Feature 3: OSC 52 clipboard — copy session ID
	case "y":
		if len(m.sessions) > 0 && m.cursor < len(m.sessions) {
			sid := m.sessions[m.cursor].ID
			m.oscCopy(sid)
			m.statusMsg = fmt.Sprintf("Copied: %s", tuiTruncate(sid, 20))
			m.statusExpiry = time.Now().Add(3 * time.Second)
		}
	// Feature 3: copy full fingerprint
	case "Y":
		if m.serverFingerprint != "" {
			m.oscCopy(m.serverFingerprint)
			m.statusMsg = "Copied: server fingerprint"
			m.statusExpiry = time.Now().Add(3 * time.Second)
		}

	// Feature 6: session label
	case "l":
		if len(m.sessions) > 0 && m.cursor < len(m.sessions) {
			m.selected = m.sessions[m.cursor].ID
			m.selectedIdx = m.cursor
			m.labelInput = m.mgr.GetLabel(m.selected)
			m.view = tuiViewLabelInput
		}

	// Feature 13: engagement export
	case "E":
		return m, m.doExport()
	}
	return m, nil
}

func (m tuiModel) handleDetailKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		m.view = tuiViewSessions
		m.cursor = m.selectedIdx
		m.scrollOffset = 0
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
		m.scrollOffset = 0
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		maxIdx := m.detailLen() - 1
		if m.cursor < maxIdx {
			m.cursor++
		}
	case "G", "end":
		maxIdx := m.detailLen() - 1
		if maxIdx >= 0 {
			m.cursor = maxIdx
		}
	case "g", "home":
		m.cursor = 0
		m.scrollOffset = 0
	case "?":
		m.view = tuiViewHelp
	case "t":
		m.view = tuiViewAddTunnel
		m.inputFields = []string{"Direction", "Listen Address", "Remote Address", "Protocol"}
		m.inputValues = []string{"local", "", "", "tcp"}
		m.inputCursor = 0
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
			m.statusExpiry = time.Now().Add(3 * time.Second)
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
			m.statusExpiry = time.Now().Add(3 * time.Second)
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
	case "x":
		if m.selected != "" {
			m.view = tuiViewExec
			m.inputFields = []string{"Command"}
			m.inputValues = []string{""}
			m.inputCursor = 0
			m.statusMsg = ""
			m.err = nil
			m.errExpiry = time.Time{}
		}
	case "w":
		if m.selected != "" {
			m.view = tuiViewDownload
			m.inputFields = []string{"Remote Path"}
			m.inputValues = []string{""}
			m.inputCursor = 0
			m.statusMsg = ""
			m.err = nil
			m.errExpiry = time.Time{}
		}
	case "p":
		if m.selected != "" {
			m.view = tuiViewUpload
			m.inputFields = []string{"Local Path", "Remote Path"}
			m.inputValues = []string{"", ""}
			m.inputCursor = 0
			m.statusMsg = ""
			m.err = nil
			m.errExpiry = time.Time{}
		}

	// Feature 3: copy tunnel/route data
	case "y":
		if m.detailTab == tuiTabTunnels && m.cursor < len(m.tunnels) {
			t := m.tunnels[m.cursor]
			data := fmt.Sprintf("%s %s %s→%s", t.Direction, t.Protocol, t.ListenAddr, t.RemoteAddr)
			m.oscCopy(data)
			m.statusMsg = fmt.Sprintf("Copied: %s", tuiTruncate(data, 30))
			m.statusExpiry = time.Now().Add(3 * time.Second)
		} else if m.detailTab == tuiTabRoutes && m.cursor < len(m.routes) {
			r := m.routes[m.cursor]
			m.oscCopy(r.CIDR)
			m.statusMsg = fmt.Sprintf("Copied: %s", r.CIDR)
			m.statusExpiry = time.Now().Add(3 * time.Second)
		}
	case "Y":
		if m.serverFingerprint != "" {
			m.oscCopy(m.serverFingerprint)
			m.statusMsg = "Copied: server fingerprint"
			m.statusExpiry = time.Now().Add(3 * time.Second)
		}

	// Feature 4: exec history
	case "o":
		m.view = tuiViewExecHistory
		m.execScroll = 0
		if len(m.execHistory) > 0 {
			m.cursor = len(m.execHistory) - 1
		}

	// Feature 5: kill switch
	case "K":
		if m.selected != "" {
			m.view = tuiViewConfirmKill
		}

	// Feature 12: tunnel profiles
	case "P":
		if m.selected != "" {
			m.profileList = m.sortedProfileNames()
			m.profileIdx = 0
			m.view = tuiViewProfileMenu
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

// Feature 5: Kill confirm
func (m tuiModel) handleConfirmKillKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y", "Y":
		m.view = tuiViewSessionDetail
		m.spinning = true
		m.statusMsg = "Killing session..."
		return m, m.doKillSession(m.selected)
	case "n", "N", "esc":
		m.view = tuiViewSessionDetail
	}
	return m, nil
}

// Feature 4: exec history keys
func (m tuiModel) handleExecHistoryKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.view = tuiViewSessionDetail
		m.cursor = 0
		m.scrollOffset = 0
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.execHistory)-1 {
			m.cursor++
		}
	case "g", "home":
		m.cursor = 0
	case "G", "end":
		if len(m.execHistory) > 0 {
			m.cursor = len(m.execHistory) - 1
		}
	}
	return m, nil
}

// Feature 6: label input keys
func (m tuiModel) handleLabelInputKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	switch key {
	case "esc":
		m.view = tuiViewSessions
		m.selected = ""
		m.labelInput = ""
	case "enter":
		m.mgr.SetLabel(m.selected, m.labelInput)
		if m.labelInput != "" {
			m.statusMsg = fmt.Sprintf("Label set: %s", m.labelInput)
		} else {
			m.statusMsg = "Label cleared"
		}
		m.statusExpiry = time.Now().Add(3 * time.Second)
		m.view = tuiViewSessions
		m.selected = ""
		m.labelInput = ""
		m.refreshData()
	case "backspace":
		if len(m.labelInput) > 0 {
			m.labelInput = m.labelInput[:len(m.labelInput)-1]
		}
	default:
		if len(key) == 1 && key[0] >= 32 && key[0] <= 126 && len(m.labelInput) < 16 {
			m.labelInput += key
		}
	}
	return m, nil
}

// Feature 12: profile menu keys
func (m tuiModel) handleProfileMenuKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.view = tuiViewSessionDetail
	case "s":
		// Save current tunnels as profile
		m.view = tuiViewProfileName
		m.inputValues = []string{""}
		m.inputCursor = 0
		m.inputFields = []string{"Profile Name"}
	case "up", "k":
		if m.profileIdx > 0 {
			m.profileIdx--
		}
	case "down", "j":
		if m.profileIdx < len(m.profileList)-1 {
			m.profileIdx++
		}
	case "enter":
		// Load selected profile
		if len(m.profileList) > 0 && m.profileIdx < len(m.profileList) {
			name := m.profileList[m.profileIdx]
			entries := m.profiles[name]
			m.view = tuiViewSessionDetail
			m.spinning = true
			m.statusMsg = fmt.Sprintf("Loading profile: %s (%d tunnels)...", name, len(entries))
			return m, m.doLoadProfile(m.selected, entries)
		}
	}
	return m, nil
}

// Feature 12: profile name input
func (m tuiModel) handleProfileNameKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	switch key {
	case "esc":
		m.view = tuiViewProfileMenu
	case "enter":
		name := strings.TrimSpace(m.inputValues[0])
		if name == "" {
			m.err = fmt.Errorf("profile name is required")
			m.errExpiry = time.Now().Add(5 * time.Second)
			return m, nil
		}
		// Save current tunnels as profile
		var entries []profileEntry
		for _, t := range m.tunnels {
			entries = append(entries, profileEntry{
				Direction:  t.Direction,
				ListenAddr: t.ListenAddr,
				RemoteAddr: t.RemoteAddr,
				Protocol:   t.Protocol,
			})
		}
		if m.profiles == nil {
			m.profiles = make(map[string][]profileEntry)
		}
		m.profiles[name] = entries
		m.saveProfiles()
		m.statusMsg = fmt.Sprintf("Profile '%s' saved (%d tunnels)", name, len(entries))
		m.statusExpiry = time.Now().Add(5 * time.Second)
		m.view = tuiViewSessionDetail
	case "backspace":
		v := m.inputValues[0]
		if len(v) > 0 {
			m.inputValues[0] = v[:len(v)-1]
		}
	default:
		if len(key) == 1 && key[0] >= 32 && key[0] <= 126 {
			m.inputValues[0] += key
		}
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

// Feature 5: kill session command
func (m *tuiModel) doKillSession(sessionID string) tea.Cmd {
	mgr := m.mgr
	return func() tea.Msg {
		if err := mgr.KillSession(sessionID); err != nil {
			return tuiActionErrMsg{err}
		}
		return tuiActionDoneMsg("Session killed — all infrastructure torn down")
	}
}

// Feature 12: load profile tunnels
func (m *tuiModel) doLoadProfile(sessionID string, entries []profileEntry) tea.Cmd {
	mgr := m.mgr
	return func() tea.Msg {
		count := 0
		for _, e := range entries {
			_, err := mgr.AddTunnel(sessionID, e.Direction, e.ListenAddr, e.RemoteAddr, e.Protocol)
			if err != nil {
				return tuiActionErrMsg{fmt.Errorf("profile tunnel %s: %w", e.ListenAddr, err)}
			}
			count++
		}
		return tuiActionDoneMsg(fmt.Sprintf("Loaded %d tunnels from profile", count))
	}
}

// Feature 13: engagement export
func (m *tuiModel) doExport() tea.Cmd {
	sessions := m.sessions
	execHist := make([]execEntry, len(m.execHistory))
	copy(execHist, m.execHistory)
	fp := m.serverFingerprint
	start := m.startTime
	return func() tea.Msg {
		now := time.Now()
		fname := fmt.Sprintf("burrow-export-%s.json", now.Format("20060102-150405"))
		uptime := now.Sub(start)
		uptimeStr := fmt.Sprintf("%dh %dm", int(uptime.Hours()), int(uptime.Minutes())%60)

		type exportExec struct {
			Timestamp string `json:"timestamp"`
			Command   string `json:"command"`
			Output    string `json:"output,omitempty"`
			Error     string `json:"error,omitempty"`
		}

		var execs []exportExec
		for _, e := range execHist {
			execs = append(execs, exportExec{
				Timestamp: e.ts.Format(time.RFC3339),
				Command:   e.command,
				Output:    e.output,
				Error:     e.err,
			})
		}

		export := struct {
			ExportedAt        string            `json:"exported_at"`
			ServerUptime      string            `json:"server_uptime"`
			ServerFingerprint string            `json:"server_fingerprint,omitempty"`
			Sessions          []web.SessionInfo `json:"sessions"`
			ExecHistory       []exportExec      `json:"exec_history,omitempty"`
		}{
			ExportedAt:        now.Format(time.RFC3339),
			ServerUptime:      uptimeStr,
			ServerFingerprint: fp,
			Sessions:          sessions,
			ExecHistory:       execs,
		}

		data, err := json.MarshalIndent(export, "", "  ")
		if err != nil {
			return tuiActionErrMsg{fmt.Errorf("marshal export: %w", err)}
		}
		if err := os.WriteFile(fname, data, 0644); err != nil {
			return tuiActionErrMsg{fmt.Errorf("write export: %w", err)}
		}
		return tuiActionDoneMsg(fmt.Sprintf("Exported to %s", fname))
	}
}

func (m tuiModel) handleExecKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	switch key {
	case "esc":
		m.view = tuiViewSessionDetail
		m.cursor = 0
		m.err = nil
		m.errExpiry = time.Time{}
		return m, nil
	case "enter":
		command := strings.TrimSpace(m.inputValues[0])
		if command == "" {
			m.err = fmt.Errorf("command is required")
			m.errExpiry = time.Now().Add(5 * time.Second)
			return m, nil
		}
		m.view = tuiViewSessionDetail
		m.spinning = true
		m.statusMsg = fmt.Sprintf("Executing: %s", tuiTruncate(command, 40))
		return m, m.doExecCommand(m.selected, command)
	case "backspace":
		v := m.inputValues[0]
		if len(v) > 0 {
			m.inputValues[0] = v[:len(v)-1]
		}
	default:
		if len(key) == 1 && key[0] >= 32 && key[0] <= 126 {
			m.inputValues[0] += key
		}
	}
	return m, nil
}

func (m *tuiModel) doExecCommand(sessionID, command string) tea.Cmd {
	mgr := m.mgr
	return func() tea.Msg {
		output, err := mgr.ExecCommand(sessionID, command)
		return tuiExecResultMsg{output: output, err: err, command: command}
	}
}

func (m tuiModel) viewExecForm(b *strings.Builder) {
	m.renderCompactBanner(b)
	b.WriteString("\n")
	b.WriteString(stAccent.Bold(true).Render("  Execute Command"))
	b.WriteString("\n")
	b.WriteString(stDim.Render(fmt.Sprintf("  Session: %s", m.selected)) + "\n")
	b.WriteString(renderSep(m.width) + "\n\n")

	if m.err != nil {
		b.WriteString(stError.Render("  ✗ "+m.err.Error()) + "\n\n")
	}

	boxW := min(m.width-8, 60)
	if boxW < 20 {
		boxW = 20
	}

	b.WriteString(stCyan.Bold(true).Render("▸ ") + stCyan.Bold(true).Render("Command:") + "\n")
	cursor := stCyan.Bold(true).Render("█")
	value := m.inputValues[0]
	displayVal := value + cursor
	padding := max(0, boxW-2-len(value)-1)
	b.WriteString("    ┌" + strings.Repeat("─", boxW) + "┐\n")
	b.WriteString("    │ " + displayVal + strings.Repeat(" ", padding) + " │\n")
	b.WriteString("    └" + strings.Repeat("─", boxW) + "┘\n")

	b.WriteString("\n")
	b.WriteString(stDim.Render("  Examples: whoami, net stop lanmanserver /y, dir C:\\") + "\n")

	b.WriteString("\n")
	b.WriteString(renderHelpBar([]string{"enter execute", "esc cancel"}))
}

func (m tuiModel) handleDownloadKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	switch key {
	case "esc":
		m.view = tuiViewSessionDetail
		m.cursor = 0
		m.err = nil
		m.errExpiry = time.Time{}
		return m, nil
	case "enter":
		remotePath := strings.TrimSpace(m.inputValues[0])
		if remotePath == "" {
			m.err = fmt.Errorf("remote path is required")
			m.errExpiry = time.Now().Add(5 * time.Second)
			return m, nil
		}
		m.view = tuiViewSessionDetail
		m.spinning = true
		m.statusMsg = fmt.Sprintf("Downloading: %s", tuiTruncate(remotePath, 40))
		return m, m.doDownloadFile(m.selected, remotePath)
	case "backspace":
		v := m.inputValues[0]
		if len(v) > 0 {
			m.inputValues[0] = v[:len(v)-1]
		}
	default:
		if len(key) == 1 && key[0] >= 32 && key[0] <= 126 {
			m.inputValues[0] += key
		}
	}
	return m, nil
}

func (m tuiModel) handleUploadKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
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
		localPath := strings.TrimSpace(m.inputValues[0])
		remotePath := strings.TrimSpace(m.inputValues[1])
		if localPath == "" || remotePath == "" {
			m.err = fmt.Errorf("both local path and remote path are required")
			m.errExpiry = time.Now().Add(5 * time.Second)
			return m, nil
		}
		m.view = tuiViewSessionDetail
		m.spinning = true
		m.statusMsg = fmt.Sprintf("Uploading: %s", tuiTruncate(localPath, 40))
		return m, m.doUploadFile(m.selected, localPath, remotePath)
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

func (m *tuiModel) doDownloadFile(sessionID, remotePath string) tea.Cmd {
	mgr := m.mgr
	return func() tea.Msg {
		resp, err := mgr.DownloadFile(sessionID, remotePath)
		if err != nil {
			return tuiDownloadResultMsg{err: err}
		}
		// Write file to current working directory
		fileName := resp.FileName
		if fileName == "" {
			fileName = filepath.Base(remotePath)
		}
		if writeErr := os.WriteFile(fileName, resp.Data, 0644); writeErr != nil {
			return tuiDownloadResultMsg{err: writeErr}
		}
		return tuiDownloadResultMsg{fileName: fileName, size: resp.Size}
	}
}

func (m *tuiModel) doUploadFile(sessionID, localPath, remotePath string) tea.Cmd {
	mgr := m.mgr
	return func() tea.Msg {
		data, err := os.ReadFile(localPath)
		if err != nil {
			return tuiUploadResultMsg{err: err}
		}
		resp, err := mgr.UploadFile(sessionID, remotePath, data)
		if err != nil {
			return tuiUploadResultMsg{err: err}
		}
		return tuiUploadResultMsg{size: resp.Size}
	}
}

func (m tuiModel) viewDownloadForm(b *strings.Builder) {
	m.renderCompactBanner(b)
	b.WriteString("\n")
	b.WriteString(stAccent.Bold(true).Render("  Download File"))
	b.WriteString("\n")
	b.WriteString(stDim.Render(fmt.Sprintf("  Session: %s", m.selected)) + "\n")
	b.WriteString(renderSep(m.width) + "\n\n")

	if m.err != nil {
		b.WriteString(stError.Render("  ✗ "+m.err.Error()) + "\n\n")
	}

	boxW := min(m.width-8, 60)
	if boxW < 20 {
		boxW = 20
	}

	b.WriteString(stCyan.Bold(true).Render("▸ ") + stCyan.Bold(true).Render("Remote Path:") + "\n")
	cursor := stCyan.Bold(true).Render("█")
	value := m.inputValues[0]
	displayVal := value + cursor
	padding := max(0, boxW-2-len(value)-1)
	b.WriteString("    ┌" + strings.Repeat("─", boxW) + "┐\n")
	b.WriteString("    │ " + displayVal + strings.Repeat(" ", padding) + " │\n")
	b.WriteString("    └" + strings.Repeat("─", boxW) + "┘\n")

	b.WriteString("\n")
	b.WriteString(stDim.Render("  File will be saved to server's current directory") + "\n")

	b.WriteString("\n")
	b.WriteString(renderHelpBar([]string{"enter download", "esc cancel"}))
}

func (m tuiModel) viewUploadForm(b *strings.Builder) {
	m.renderCompactBanner(b)
	b.WriteString("\n")
	b.WriteString(stAccent.Bold(true).Render("  Upload File"))
	b.WriteString(stFieldCtr.Render(fmt.Sprintf("  (Field %d/%d)", m.inputCursor+1, len(m.inputFields))))
	b.WriteString("\n")
	b.WriteString(stDim.Render(fmt.Sprintf("  Session: %s", m.selected)) + "\n")
	b.WriteString(renderSep(m.width) + "\n\n")

	if m.err != nil {
		b.WriteString(stError.Render("  ✗ "+m.err.Error()) + "\n\n")
	}

	boxW := min(m.width-8, 60)
	if boxW < 20 {
		boxW = 20
	}

	for i, field := range m.inputFields {
		label := field + ":"
		value := m.inputValues[i]
		focused := i == m.inputCursor

		if focused {
			b.WriteString(stCyan.Bold(true).Render("▸ ") + stCyan.Bold(true).Render(label) + "\n")
		} else {
			b.WriteString("  " + stDim.Render(label) + "\n")
		}

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
		b.WriteString("\n")
	}

	b.WriteString(renderHelpBar([]string{"enter upload", "tab/↓ next", "shift+tab/↑ prev", "esc cancel"}))
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
	case tuiViewExec:
		m.viewExecForm(&b)
	case tuiViewDownload:
		m.viewDownloadForm(&b)
	case tuiViewUpload:
		m.viewUploadForm(&b)
	case tuiViewHelp:
		m.viewHelpOverlay(&b)
	case tuiViewExecHistory:
		m.viewExecHistory(&b)
	case tuiViewConfirmKill:
		m.viewConfirmKill(&b)
	case tuiViewLabelInput:
		m.viewLabelInput(&b)
	case tuiViewProfileMenu:
		m.viewProfileMenu(&b)
	case tuiViewProfileName:
		m.viewProfileNameForm(&b)
	}

	// Status bar at bottom
	b.WriteString("\n" + m.renderStatusBar())

	return b.String()
}

// ── Banner ──────────────────────────────────────────────────────────────────

func (m tuiModel) renderBanner(b *strings.Builder) {
	title := stAccent.Bold(true).Render("  ╔══╗ ╦ ╦ ╦═╗ ╦═╗ ╔══╗ ╦   ╦")
	title2 := stAccent.Bold(true).Render("  ╠══╣ ║ ║ ╠╦╝ ╠╦╝ ║  ║ ║ ╦ ║")
	title3 := stAccent.Bold(true).Render("  ╚══╝ ╚═╝ ╩╚═ ╩╚═ ╚══╝ ╚═╝═╝")
	fpStr := stDim.Render("(no TLS)")
	if m.serverFingerprint != "" {
		fpStr = stCyan.Render(tuiShortFingerprint(m.serverFingerprint, 8))
	}
	b.WriteString(title + "\n")
	b.WriteString(title2 + "\n")
	b.WriteString(title3 + "  " + stDim.Render("v"+version) + stDim.Render(" │ ") + fpStr + "\n")
}

func (m tuiModel) renderCompactBanner(b *strings.Builder) {
	fpStr := stDim.Render("(no TLS)")
	if m.serverFingerprint != "" {
		fpStr = stCyan.Render(tuiShortFingerprint(m.serverFingerprint, 8))
	}
	b.WriteString(stAccent.Bold(true).Render("  BURROW v"+version) + stDim.Render(" │ ") + fpStr + "\n")
}

// ── Status Bar ──────────────────────────────────────────────────────────────

func (m tuiModel) renderStatusBar() string {
	uptime := time.Since(m.startTime)
	uptimeStr := fmt.Sprintf("%02d:%02d:%02d", int(uptime.Hours()), int(uptime.Minutes())%60, int(uptime.Seconds())%60)

	activeCount := 0
	var totalIn, totalOut int64
	socksCount := 0
	socksAddr := ""
	tunCount := 0

	for _, s := range m.sessions {
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

	sep := stDim.Render(" │ ")

	tunStr := stDim.Render("--")
	if tunCount > 0 {
		tunStr = stGreen.Render("active")
	}
	socksStr := stDim.Render("--")
	if socksCount > 0 {
		socksStr = stGreen.Render(socksAddr)
	}
	spinStr := ""
	if m.spinning {
		spinStr = " " + m.spinner.View()
	}

	bar := " " + stAccent.Render("burrow") + sep + stDim.Render(uptimeStr) +
		sep + fmt.Sprintf("%d agents", activeCount) +
		sep + "TUN: " + tunStr +
		sep + "SOCKS: " + socksStr +
		sep + stGreen.Render("▲"+tuiFormatBytes(totalOut)) + " " + stCyan.Render("▼"+tuiFormatBytes(totalIn)) +
		spinStr

	// Match log panel width
	barWidth := m.width - 4
	if barWidth < 40 {
		barWidth = 40
	}

	// Append status message if space allows
	if m.statusMsg != "" {
		contentWidth := barWidth - 2 // stStatusBar Padding(0, 1)
		visWidth := lipgloss.Width(bar)
		remaining := contentWidth - visWidth - 3
		if remaining > 4 {
			msg := m.statusMsg
			if len(msg) > remaining {
				msg = msg[:remaining-3] + "..."
			}
			bar += sep + stDim.Render(msg)
		}
	}

	return stStatusBar.Width(barWidth).Render(bar)
}

// ── Session List View ───────────────────────────────────────────────────────

func (m tuiModel) viewSessions(b *strings.Builder) {
	m.renderBanner(b)

	if m.err != nil {
		b.WriteString(stError.Render("  ✗ "+m.err.Error()) + "\n\n")
	}

	if len(m.sessions) == 0 {
		b.WriteString(stDim.Render("  No sessions. Waiting for agents to connect...") + "\n")
	} else {
		// Feature 7: updated header with T/R counts
		hdr := fmt.Sprintf("  %-8s  %-10s  %-14s       %6s  %6s             %-6s",
			"ID", "HOST", "IPs", "▲ OUT", "▼ IN", "UP")
		b.WriteString(stHeader.Render(hdr) + "\n")
		b.WriteString(renderSep(m.width) + "\n")

		// Feature 1: viewport scrolling
		visRows := m.visibleSessionRows()
		m.ensureCursorVisible(len(m.sessions), visRows)

		endIdx := m.scrollOffset + visRows
		if endIdx > len(m.sessions) {
			endIdx = len(m.sessions)
		}

		for i := m.scrollOffset; i < endIdx; i++ {
			s := m.sessions[i]
			ips := strings.Join(s.IPs, ",")
			if len(ips) > 14 {
				ips = ips[:11] + "..."
			}

			// FLAGS: TUN(T/·) + SOCKS(S/·) + tunnel/route counts (Feature 7)
			var flagT, flagS string
			if s.TunActive {
				flagT = stGreen.Render("T")
			} else {
				flagT = stDim.Render("·")
			}
			if s.SocksAddr != "" {
				flagS = stGreen.Render("S")
			} else {
				flagS = stDim.Render("·")
			}
			flags := flagT + flagS

			// Feature 7: tunnel/route counts
			trCounts := stDim.Render(fmt.Sprintf("%dT%dR", s.Tunnels, s.Routes))

			// Feature 11: 3-tier health dot
			healthDot := m.healthDot(s)

			// Feature 6: session label
			label := m.mgr.GetLabel(s.ID)
			labelStr := ""
			if label != "" {
				labelStr = stCyan.Render(tuiTruncate(label, 8)) + " "
			}

			bwOutRaw := tuiFormatBytes(s.BytesOut)
			bwInRaw := tuiFormatBytes(s.BytesIn)
			bwOut := strings.Repeat(" ", max(0, 6-len(bwOutRaw))) + tuiColorBytes(s.BytesOut)
			bwIn := strings.Repeat(" ", max(0, 6-len(bwInRaw))) + tuiColorBytes(s.BytesIn)
			uptime := tuiFormatUptime(s.CreatedAt)

			// Feature 10: sparkline
			sp := m.sparks[s.ID]
			sparkStr := ""
			if sp != nil && sp.count > 0 {
				sparkStr = stCyan.Render(sp.render(8))
			} else {
				sparkStr = stDimmer.Render("        ")
			}

			cols := fmt.Sprintf("  %-8s  %-10s  %-14s",
				tuiTruncate(s.ID, 8),
				tuiTruncate(s.Hostname, 10),
				ips)
			line := cols + " " + flags + " " + trCounts + " " + healthDot + " " + labelStr + bwOut + "  " + bwIn + "  " + sparkStr + " " + fmt.Sprintf("%-6s", uptime)

			if i == m.cursor {
				highlighted := stSelRow.Width(m.width).Render("▸ " + line[2:])
				b.WriteString(highlighted + "\n")
			} else {
				b.WriteString(line + "\n")
			}
		}

		// Feature 1: scroll indicator
		if len(m.sessions) > visRows {
			b.WriteString(stDim.Render(fmt.Sprintf("  (%d/%d)", m.cursor+1, len(m.sessions))))
			if endIdx < len(m.sessions) {
				b.WriteString(stDim.Render(" ▼ more"))
			}
			b.WriteString("\n")
		}
	}

	// Log panel
	b.WriteString("\n")
	m.renderLogPanel(b)


	b.WriteString("\n")
	b.WriteString(renderHelpBar([]string{
		"↑/k up", "↓/j down", "g/G top/end", "enter select", "^T TUN", "y copy", "l label", "E export", "? help", "q quit",
	}))
}

// ── Session Detail View ─────────────────────────────────────────────────────

func (m tuiModel) viewDetail(b *strings.Builder) {
	m.renderCompactBanner(b)
	b.WriteString("\n")
	var sess *web.SessionInfo
	for i := range m.sessions {
		if m.sessions[i].ID == m.selected {
			sess = &m.sessions[i]
			break
		}
	}

	if sess != nil {
		// Feature 11: 3-tier health dot
		healthDot := m.healthDot(*sess)
		sep := stDim.Render(" │ ")

		// Feature 6: label display
		label := m.mgr.GetLabel(sess.ID)
		labelStr := ""
		if label != "" {
			labelStr = sep + stCyan.Render(label)
		}

		// Feature 7: info line 1 with PID
		pidStr := ""
		if sess.PID > 0 {
			pidStr = sep + stBold.Render("PID:") + " " + fmt.Sprintf("%d", sess.PID)
		}
		b.WriteString("  " + healthDot + " " + stBold.Render("Session:") + " " + tuiTruncate(sess.ID, 12) +
			sep + stBold.Render("Host:") + " " + tuiTruncate(sess.Hostname, 12) +
			sep + stBold.Render("OS:") + " " + tuiTruncate(sess.OS, 10) +
			pidStr + labelStr + "\n")

		// Info line 2: network status
		tunStr := stDim.Render("TUN --")
		if sess.TunActive {
			tunStr = stGreen.Bold(true).Render("TUN ▲")
		}
		socksStr := stDim.Render("SOCKS --")
		if sess.SocksAddr != "" {
			socksStr = stGreen.Bold(true).Render("SOCKS " + sess.SocksAddr)
		}
		ipsStr := tuiTruncate(strings.Join(sess.IPs, ", "), 28)
		b.WriteString("  " + tunStr + sep + socksStr +
			sep + stDim.Render("IPs:") + " " + ipsStr + "\n")

		// Info line 3: bandwidth + rate + RTT + uptime (Feature 7, 11)
		rate := m.rates[sess.ID]
		rateStr := stDim.Render("--")
		if rate != nil && (rate.rateIn > 0 || rate.rateOut > 0) {
			rateStr = stCyan.Render(fmt.Sprintf("%s/s", tuiFormatRate(rate.rateOut+rate.rateIn)))
		}
		rttStr := stDim.Render("--")
		if sess.RTTMicros > 0 {
			rttMs := float64(sess.RTTMicros) / 1000.0
			if rttMs >= 1 {
				rttStr = stCyan.Render(fmt.Sprintf("%.0fms", rttMs))
			} else {
				rttStr = stCyan.Render(fmt.Sprintf("%.1fms", rttMs))
			}
		}
		b.WriteString("  " + stGreen.Render("▲") + " " + tuiColorBytes(sess.BytesOut) + "  " + stCyan.Render("▼") + " " + tuiColorBytes(sess.BytesIn) +
			sep + stDim.Render("Rate:") + " " + rateStr +
			sep + stDim.Render("RTT:") + " " + rttStr +
			sep + tuiFormatUptime(sess.CreatedAt) + "\n")

		// Feature 7: info line 4 — Transport, Agent Version
		transportStr := stDim.Render("--")
		if sess.Transport != "" {
			transportStr = stCyan.Render(sess.Transport)
		}
		agentStr := stDim.Render("--")
		if sess.AgentVersion != "" {
			agentStr = stCyan.Render(sess.AgentVersion)
		}
		b.WriteString("  " + stDim.Render("Transport:") + " " + transportStr +
			sep + stDim.Render("Agent:") + " " + agentStr + "\n")
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

	// Log panel
	b.WriteString("\n")
	m.renderLogPanel(b)

	b.WriteString("\n")
	b.WriteString(renderHelpBar([]string{"↑/k up", "↓/j down", "esc back", "^T TUN", "s SOCKS5", "y copy", "K kill", "o output", "P profile", "? help"}) + "\n")
	b.WriteString(renderHelpBar([]string{"t tunnel", "r route", "u start", "n stop", "d delete", "x exec", "w download", "p upload"}))
}

func (m tuiModel) viewTunnels(b *strings.Builder) {
	if len(m.tunnels) == 0 {
		b.WriteString(stDim.Render("  (no tunnels)") + "\n")
		return
	}

	hdr := fmt.Sprintf("  %-10s %-5s %-18s %-18s %-3s %6s %6s %-6s",
		"ID", "DIR", "LISTEN", "REMOTE", "PRT", "▲OUT", "▼IN", "STATUS")
	b.WriteString(stHeader.Render(hdr) + "\n")

	// Feature 1: scrolling for tunnel list
	visRows := m.visibleDetailRows()
	m.ensureCursorVisible(len(m.tunnels), visRows)
	endIdx := m.scrollOffset + visRows
	if endIdx > len(m.tunnels) {
		endIdx = len(m.tunnels)
	}

	for i := m.scrollOffset; i < endIdx; i++ {
		t := m.tunnels[i]
		statusStr := stRed.Render("dead  ")
		if t.Active {
			statusStr = stGreen.Render("active")
		} else if t.Error != "" {
			statusStr = stRed.Render("error ")
		}

		cols := fmt.Sprintf("%-10s %-5s %-18s %-18s %-3s",
			tuiTruncate(t.ID, 10),
			tuiTruncate(t.Direction, 5),
			tuiTruncate(t.ListenAddr, 18),
			tuiTruncate(t.RemoteAddr, 18),
			t.Protocol)

		bwStr := fmt.Sprintf(" %6s %6s", tuiColorBytes(t.BytesOut), tuiColorBytes(t.BytesIn))

		errSuffix := ""
		if t.Error != "" {
			errSuffix = " " + stError.Render(tuiTruncate(t.Error, 15))
		}

		if i == m.cursor {
			b.WriteString(stSelRow.Width(m.width).Render("▸ "+cols+bwStr+" "+lipgloss.NewStyle().Render(statusStr)+errSuffix) + "\n")
		} else {
			b.WriteString("  " + cols + bwStr + " " + statusStr + errSuffix + "\n")
		}
	}

	// Scroll indicator
	if len(m.tunnels) > visRows {
		b.WriteString(stDim.Render(fmt.Sprintf("  (%d/%d)", m.cursor+1, len(m.tunnels))) + "\n")
	}
}

func (m tuiModel) viewRoutes(b *strings.Builder) {
	if len(m.routes) == 0 {
		b.WriteString(stDim.Render("  (no routes)") + "\n")
		return
	}

	hdr := fmt.Sprintf("  %-30s %-7s", "CIDR", "STATUS")
	b.WriteString(stHeader.Render(hdr) + "\n")

	// Feature 1: scrolling for route list
	visRows := m.visibleDetailRows()
	m.ensureCursorVisible(len(m.routes), visRows)
	endIdx := m.scrollOffset + visRows
	if endIdx > len(m.routes) {
		endIdx = len(m.routes)
	}

	for i := m.scrollOffset; i < endIdx; i++ {
		r := m.routes[i]
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

	// Scroll indicator
	if len(m.routes) > visRows {
		b.WriteString(stDim.Render(fmt.Sprintf("  (%d/%d)", m.cursor+1, len(m.routes))) + "\n")
	}
}

// ── Confirm Delete ──────────────────────────────────────────────────────────

func (m tuiModel) viewConfirm(b *strings.Builder) {
	m.renderCompactBanner(b)
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

// Feature 5: kill confirm view
func (m tuiModel) viewConfirmKill(b *strings.Builder) {
	m.renderCompactBanner(b)
	b.WriteString("\n")

	boxW := min(m.width-4, 60)
	if boxW < 30 {
		boxW = 30
	}

	content := strings.Join([]string{
		"",
		stError.Render("  KILL SESSION"),
		"",
		stConfirm.Render("  Tear down ALL tunnels, routes, SOCKS, TUN?"),
		stDim.Render(fmt.Sprintf("  Session: %s", tuiTruncate(m.selected, 20))),
		"",
		stDim.Render("  Press y to confirm, n or esc to cancel"),
		"",
	}, "\n")

	panel := stPanel.Width(boxW).Render(content)
	b.WriteString(panel + "\n\n")
	b.WriteString(renderHelpBar([]string{"y KILL", "n cancel", "esc cancel"}))
}

// Feature 4: exec history view
func (m tuiModel) viewExecHistory(b *strings.Builder) {
	m.renderCompactBanner(b)
	b.WriteString("\n")
	b.WriteString(stAccent.Bold(true).Render("  Exec Output History") + "\n")
	b.WriteString(renderSep(m.width) + "\n")

	if len(m.execHistory) == 0 {
		b.WriteString(stDim.Render("  (no exec history)") + "\n")
	} else {
		// Show list of entries at top, selected entry's output below
		visRows := min(m.height-14, len(m.execHistory))
		if visRows < 2 {
			visRows = 2
		}
		m.ensureCursorVisible(len(m.execHistory), visRows)
		endIdx := m.scrollOffset + visRows
		if endIdx > len(m.execHistory) {
			endIdx = len(m.execHistory)
		}
		for i := m.scrollOffset; i < endIdx; i++ {
			e := m.execHistory[i]
			ts := e.ts.Format("15:04:05")
			cmd := tuiTruncate(e.command, 40)
			status := stGreen.Render("ok")
			if e.err != "" {
				status = stRed.Render("err")
			}
			line := fmt.Sprintf("  %s %s %s", ts, status, cmd)
			if i == m.cursor {
				b.WriteString(stSelRow.Width(m.width).Render("▸ "+line[2:]) + "\n")
			} else {
				b.WriteString(line + "\n")
			}
		}
		if len(m.execHistory) > visRows {
			b.WriteString(stDim.Render(fmt.Sprintf("  (%d/%d)", m.cursor+1, len(m.execHistory))) + "\n")
		}

		// Show selected entry output
		if m.cursor < len(m.execHistory) {
			e := m.execHistory[m.cursor]
			b.WriteString("\n")
			b.WriteString(stDim.Render("  ── output ─────") + "\n")
			outLines := strings.Split(e.output, "\n")
			maxOut := min(5, len(outLines))
			for _, line := range outLines[:maxOut] {
				line = strings.TrimRight(line, "\r")
				b.WriteString(stDim.Render("  ") + tuiTruncate(line, m.width-4) + "\n")
			}
			if len(outLines) > maxOut {
				b.WriteString(stDim.Render(fmt.Sprintf("  ... (%d more lines)", len(outLines)-maxOut)) + "\n")
			}
			if e.err != "" {
				b.WriteString(stError.Render("  err: "+tuiTruncate(e.err, m.width-8)) + "\n")
			}
		}
	}

	b.WriteString("\n")
	b.WriteString(renderHelpBar([]string{"↑/k up", "↓/j down", "esc back"}))
}

// Feature 6: label input view
func (m tuiModel) viewLabelInput(b *strings.Builder) {
	m.renderCompactBanner(b)
	b.WriteString("\n")
	b.WriteString(stAccent.Bold(true).Render("  Set Session Label") + "\n")
	b.WriteString(stDim.Render(fmt.Sprintf("  Session: %s", tuiTruncate(m.selected, 20))) + "\n")
	b.WriteString(renderSep(m.width) + "\n\n")

	boxW := min(m.width-8, 40)
	if boxW < 20 {
		boxW = 20
	}

	b.WriteString(stCyan.Bold(true).Render("▸ ") + stCyan.Bold(true).Render("Label (max 16 chars):") + "\n")
	cursor := stCyan.Bold(true).Render("█")
	displayVal := m.labelInput + cursor
	padding := max(0, boxW-2-len(m.labelInput)-1)
	b.WriteString("    ┌" + strings.Repeat("─", boxW) + "┐\n")
	b.WriteString("    │ " + displayVal + strings.Repeat(" ", padding) + " │\n")
	b.WriteString("    └" + strings.Repeat("─", boxW) + "┘\n")

	b.WriteString("\n")
	b.WriteString(stDim.Render("  Empty to clear label") + "\n\n")
	b.WriteString(renderHelpBar([]string{"enter save", "esc cancel"}))
}

// Feature 12: profile menu view
func (m tuiModel) viewProfileMenu(b *strings.Builder) {
	m.renderCompactBanner(b)
	b.WriteString("\n")
	b.WriteString(stAccent.Bold(true).Render("  Tunnel Profiles") + "\n")
	b.WriteString(renderSep(m.width) + "\n\n")

	b.WriteString("  " + stCyan.Render("s") + stDim.Render(" Save current tunnels as profile") + "\n\n")

	if len(m.profileList) == 0 {
		b.WriteString(stDim.Render("  (no saved profiles)") + "\n")
	} else {
		b.WriteString(stHeader.Render("  Saved profiles (enter to load):") + "\n")
		for i, name := range m.profileList {
			entries := m.profiles[name]
			info := fmt.Sprintf("  %-20s %d tunnels", name, len(entries))
			if i == m.profileIdx {
				b.WriteString(stSelRow.Width(m.width).Render("▸ "+info[2:]) + "\n")
			} else {
				b.WriteString(info + "\n")
			}
		}
	}

	b.WriteString("\n")
	b.WriteString(renderHelpBar([]string{"s save", "enter load", "↑/k ↓/j navigate", "esc back"}))
}

// Feature 12: profile name input view
func (m tuiModel) viewProfileNameForm(b *strings.Builder) {
	m.renderCompactBanner(b)
	b.WriteString("\n")
	b.WriteString(stAccent.Bold(true).Render("  Save Tunnel Profile") + "\n")
	b.WriteString(renderSep(m.width) + "\n\n")

	if m.err != nil {
		b.WriteString(stError.Render("  ✗ "+m.err.Error()) + "\n\n")
	}

	boxW := min(m.width-8, 40)
	if boxW < 20 {
		boxW = 20
	}

	b.WriteString(stCyan.Bold(true).Render("▸ ") + stCyan.Bold(true).Render("Profile Name:") + "\n")
	cursor := stCyan.Bold(true).Render("█")
	value := m.inputValues[0]
	displayVal := value + cursor
	padding := max(0, boxW-2-len(value)-1)
	b.WriteString("    ┌" + strings.Repeat("─", boxW) + "┐\n")
	b.WriteString("    │ " + displayVal + strings.Repeat(" ", padding) + " │\n")
	b.WriteString("    └" + strings.Repeat("─", boxW) + "┘\n")

	b.WriteString("\n")
	b.WriteString(stDim.Render(fmt.Sprintf("  Will save %d tunnels", len(m.tunnels))) + "\n\n")
	b.WriteString(renderHelpBar([]string{"enter save", "esc cancel"}))
}

// ── Form View ───────────────────────────────────────────────────────────────

func (m tuiModel) viewForm(b *strings.Builder, title string) {
	m.renderCompactBanner(b)
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
				b.WriteString("    │ " + optStr + strings.Repeat(" ", max(0, boxW-1-lipgloss.Width(optStr))) + "│\n")
				b.WriteString("    └" + strings.Repeat("─", boxW) + "┘\n")
			} else {
				b.WriteString(stFormBdr.Render("    ┌"+strings.Repeat("─", boxW)+"┐") + "\n")
				b.WriteString(stFormBdr.Render("    │ ") + optStr + stFormBdr.Render(strings.Repeat(" ", max(0, boxW-1-lipgloss.Width(optStr)))+"│") + "\n")
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
	b.WriteString(stDim.Render("  ── log ") + stDimmer.Render(strings.Repeat("─", max(0, m.width-14))) + "\n")
	entries := m.logs.all()
	if len(entries) == 0 {
		b.WriteString(stDimmer.Render("  (no recent activity)") + "\n")
		return
	}

	maxLines := 4
	start := 0
	if len(entries) > maxLines {
		start = len(entries) - maxLines
	}

	for _, e := range entries[start:] {
		ts := e.ts.Format("15:04:05")
		b.WriteString(stDimmer.Render("  "+ts+" ") + stDim.Render(tuiTruncate(e.text, m.width-14)) + "\n")
	}
}

// ── Bandwidth Bar (replaced by sparkline but kept as fallback) ──────────────

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

// ── Help Overlay ─────────────────────────────────────────────────────────

func (m tuiModel) handleHelpKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "?", "esc", "q", "enter":
		// Return to previous view — sessions or detail
		if m.selected != "" {
			m.view = tuiViewSessionDetail
		} else {
			m.view = tuiViewSessions
		}
	}
	return m, nil
}

func (m tuiModel) viewHelpOverlay(b *strings.Builder) {
	m.renderCompactBanner(b)
	b.WriteString("\n")
	b.WriteString(stAccent.Bold(true).Render("  Keyboard Shortcuts") + "\n")
	b.WriteString(renderSep(m.width) + "\n\n")

	sections := []struct {
		title string
		keys  [][2]string
	}{
		{"Navigation", [][2]string{
			{"↑/k", "Move up"},
			{"↓/j", "Move down"},
			{"g/Home", "Jump to top"},
			{"G/End", "Jump to bottom"},
			{"enter", "Select / confirm"},
			{"esc/q", "Back / quit"},
			{"tab", "Switch tab"},
		}},
		{"Session List", [][2]string{
			{"^T", "Toggle TUN interface"},
			{"y", "Copy session ID (OSC 52)"},
			{"Y", "Copy server fingerprint"},
			{"l", "Set session label"},
			{"E", "Export engagement data"},
			{"^R", "Refresh data"},
		}},
		{"Detail Actions", [][2]string{
			{"t", "Add tunnel"},
			{"r", "Add route"},
			{"u", "Start stopped tunnel"},
			{"n", "Stop active tunnel"},
			{"d", "Delete tunnel/route"},
			{"x", "Execute command"},
			{"w", "Download file"},
			{"p", "Upload file"},
			{"s", "Toggle SOCKS5 proxy"},
			{"y", "Copy tunnel/route data"},
			{"o", "Exec output history"},
			{"K", "Kill session (teardown all)"},
			{"P", "Tunnel profiles"},
		}},
	}

	for _, sec := range sections {
		b.WriteString(stBold.Render("  "+sec.title) + "\n")
		for _, kv := range sec.keys {
			b.WriteString(fmt.Sprintf("    %s  %s\n",
				stCyan.Render(fmt.Sprintf("%-8s", kv[0])),
				stDim.Render(kv[1])))
		}
		b.WriteString("\n")
	}

	b.WriteString(renderHelpBar([]string{"? close", "esc close"}))
}

// ── Feature 3: OSC 52 clipboard ─────────────────────────────────────────────

func (m *tuiModel) oscCopy(text string) {
	encoded := base64.StdEncoding.EncodeToString([]byte(text))
	// Write OSC 52 escape sequence directly to stdout
	fmt.Fprintf(os.Stderr, "\x1b]52;c;%s\x07", encoded)
}

// ── Feature 11: Health Score ────────────────────────────────────────────────

func (m tuiModel) healthDot(s web.SessionInfo) string {
	if !s.Active {
		return stRed.Render("●")
	}
	if s.RTTMicros > 0 && s.RTTMicros < 500000 { // < 500ms
		return stGreen.Render("●")
	}
	// Active but RTT unknown or > 500ms
	return stYellow.Render("●")
}

// ── Feature 12: Profile persistence ─────────────────────────────────────────

func (m *tuiModel) loadProfiles() {
	path := profilePath()
	data, err := os.ReadFile(path)
	if err != nil {
		return // File doesn't exist yet
	}
	profiles := make(map[string][]profileEntry)
	if err := json.Unmarshal(data, &profiles); err != nil {
		return
	}
	m.profiles = profiles
}

func (m *tuiModel) saveProfiles() {
	path := profilePath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return
	}
	data, err := json.MarshalIndent(m.profiles, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0600)
}

func (m tuiModel) sortedProfileNames() []string {
	names := make([]string, 0, len(m.profiles))
	for name := range m.profiles {
		names = append(names, name)
	}
	// Simple sort
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[i] > names[j] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	return names
}

func profilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".burrow", "profiles.json")
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

// tuiShortFingerprint returns the first n colon-separated hex pairs from a
// full SHA-256 fingerprint. e.g. tuiShortFingerprint("AB:CD:EF:...", 8)
// returns "AB:CD:EF:01:23:45:67:89" (first 8 bytes, 23 chars).
func tuiShortFingerprint(fp string, pairs int) string {
	count := 0
	for i, c := range fp {
		if c == ':' {
			count++
			if count == pairs {
				return fp[:i]
			}
		}
	}
	return fp
}

// ── RunTUI ──────────────────────────────────────────────────────────────────

// RunTUI launches the interactive TUI dashboard, talking directly to the
// session.Manager in-process (no HTTP). Blocks until the user exits.
// fingerprint is the server TLS certificate SHA-256 fingerprint to display
// in the dashboard header; pass empty string when TLS is disabled.
func RunTUI(mgr *session.Manager, fingerprint string, logBuf *tuiLogCapture) error {
	sp := spinner.New()
	sp.Spinner = spinner.Spinner{
		Frames: []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		FPS:    100 * time.Millisecond,
	}
	sp.Style = stCyan

	m := tuiModel{
		mgr:               mgr,
		rates:             make(map[string]*rateSnapshot),
		sparks:            make(map[string]*sparkData),
		logs:              newLogRing(50),
		startTime:         time.Now(),
		spinner:           sp,
		profiles:          make(map[string][]profileEntry),
		serverFingerprint: fingerprint,
		serverLogBuf:      logBuf,
	}

	// Feature 12: load saved profiles
	m.loadProfiles()

	p := tea.NewProgram(m, tea.WithAltScreen())

	// Feature 2: EventBus wiring — subscribe and forward events as tea.Msg
	if eb := mgr.GetEventBus(); eb != nil {
		ch := eb.Subscribe()
		go func() {
			for evt := range ch {
				p.Send(tuiEventMsg{event: evt})
			}
		}()
		// Note: we don't unsubscribe here because when p.Run() returns,
		// the server is about to shut down anyway.
	}

	_, err := p.Run()
	return err
}
