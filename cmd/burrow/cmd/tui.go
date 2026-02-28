package cmd

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// -- Styles --

var (
	tuiTitleStyle          = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	tuiSelectedStyle       = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86"))
	tuiHeaderStyle         = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("244"))
	tuiStatusActiveStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	tuiStatusInactiveStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	tuiHelpStyle           = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	tuiErrorStyle          = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	tuiFocusedStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true)
	tuiDimStyle            = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	tuiActiveTabStyle      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205")).Underline(true)
	tuiInactiveTabStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))

	// Additional styles for visual polish
	tuiBannerStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true)
	tuiBannerDimStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	tuiSeparatorStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	tuiBwGreenStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	tuiBwYellowStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("226"))
	tuiBwRedStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	tuiTunUpStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Bold(true)
	tuiTunDownStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	tuiBoxBorderStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	tuiConfirmStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("226")).Bold(true)
	tuiUptimeStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	tuiFormBorder     = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	tuiFieldCounter   = lipgloss.NewStyle().Foreground(lipgloss.Color("244")).Italic(true)
)

// -- API types matching web.SessionInfo / TunnelInfo / RouteInfo JSON tags --

type tuiSessionInfo struct {
	ID        string   `json:"id"`
	Hostname  string   `json:"hostname"`
	OS        string   `json:"os"`
	IPs       []string `json:"ips"`
	Active    bool     `json:"active"`
	CreatedAt string   `json:"created_at"`
	Tunnels   int      `json:"tunnel_count"`
	Routes    int      `json:"route_count"`
	BytesIn   int64    `json:"bytes_in"`
	BytesOut  int64    `json:"bytes_out"`
	TunActive bool     `json:"tun_active"`
}

type tuiTunnelInfo struct {
	ID         string `json:"id"`
	SessionID  string `json:"session_id"`
	Direction  string `json:"direction"`
	ListenAddr string `json:"listen_addr"`
	RemoteAddr string `json:"remote_addr"`
	Protocol   string `json:"protocol"`
	Active     bool   `json:"active"`
}

type tuiRouteInfo struct {
	CIDR      string `json:"cidr"`
	SessionID string `json:"session_id"`
	Active    bool   `json:"active"`
}

// -- View modes --

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

// -- Bubbletea model --

type tuiModel struct {
	apiURL      string
	webuiURL    string
	apiToken    string
	client      *http.Client
	sessions    []tuiSessionInfo
	tunnels     []tuiTunnelInfo
	routes      []tuiRouteInfo
	cursor      int
	view        tuiViewMode
	selected    string // selected session ID
	selectedIdx int    // cursor position when entering detail (for restoring)
	err         error
	errExpiry   time.Time // auto-clear error after this time
	width       int
	height      int
	detailTab   tuiDetailTab
	inputFields []string
	inputCursor int
	inputValues []string
	statusMsg   string
	confirmType string // "tunnel" or "route" for delete confirmation
	confirmID   string // tunnel ID or CIDR for delete confirmation
}

// -- Messages --

type tuiSessionsMsg []tuiSessionInfo
type tuiTunnelsMsg []tuiTunnelInfo
type tuiRoutesMsg []tuiRouteInfo
type tuiErrMsg struct{ err error }
type tuiTickMsg time.Time
type tuiActionDoneMsg string
type tuiActionErrMsg struct{ err error }

// -- HTTP helpers --

func tuiNewHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func tuiGet(client *http.Client, fullURL, token string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return client.Do(req)
}

func tuiRequest(client *http.Client, method, fullURL, token string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, fullURL, body)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return client.Do(req)
}

// -- Tea commands --

func tuiFetchSessions(client *http.Client, apiURL, token string) tea.Cmd {
	return func() tea.Msg {
		resp, err := tuiGet(client, apiURL+"/api/sessions", token)
		if err != nil {
			return tuiErrMsg{err}
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			return tuiErrMsg{fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))}
		}
		var sessions []tuiSessionInfo
		if err := json.NewDecoder(resp.Body).Decode(&sessions); err != nil {
			return tuiErrMsg{err}
		}
		return tuiSessionsMsg(sessions)
	}
}

func tuiFetchTunnels(client *http.Client, apiURL, token, sessionID string) tea.Cmd {
	return func() tea.Msg {
		resp, err := tuiGet(client, apiURL+"/api/sessions/"+sessionID+"/tunnels", token)
		if err != nil {
			return tuiErrMsg{err}
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			return tuiErrMsg{fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))}
		}
		var tunnels []tuiTunnelInfo
		if err := json.NewDecoder(resp.Body).Decode(&tunnels); err != nil {
			return tuiErrMsg{err}
		}
		return tuiTunnelsMsg(tunnels)
	}
}

func tuiFetchRoutes(client *http.Client, apiURL, token, sessionID string) tea.Cmd {
	return func() tea.Msg {
		resp, err := tuiGet(client, apiURL+"/api/sessions/"+sessionID+"/routes", token)
		if err != nil {
			return tuiErrMsg{err}
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			return tuiErrMsg{fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))}
		}
		var routes []tuiRouteInfo
		if err := json.NewDecoder(resp.Body).Decode(&routes); err != nil {
			return tuiErrMsg{err}
		}
		return tuiRoutesMsg(routes)
	}
}

func tuiDoAddTunnel(client *http.Client, apiURL, token, sessionID, direction, listen, remote, proto string) tea.Cmd {
	return func() tea.Msg {
		body := fmt.Sprintf(`{"direction":%q,"listen":%q,"remote":%q,"protocol":%q}`,
			direction, listen, remote, proto)
		resp, err := tuiRequest(client, http.MethodPost,
			apiURL+"/api/sessions/"+sessionID+"/tunnels",
			token, strings.NewReader(body))
		if err != nil {
			return tuiActionErrMsg{err}
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resp.Body)
			return tuiActionErrMsg{fmt.Errorf("%s", strings.TrimSpace(string(b)))}
		}
		var result tuiTunnelInfo
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return tuiActionErrMsg{fmt.Errorf("tunnel created but failed to parse response: %v", err)}
		}
		return tuiActionDoneMsg(fmt.Sprintf("Tunnel %s created", result.ID))
	}
}

func tuiDoRemoveTunnel(client *http.Client, apiURL, token, sessionID, tunnelID string) tea.Cmd {
	return func() tea.Msg {
		resp, err := tuiRequest(client, http.MethodDelete,
			apiURL+"/api/sessions/"+sessionID+"/tunnels/"+tunnelID,
			token, nil)
		if err != nil {
			return tuiActionErrMsg{err}
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			return tuiActionErrMsg{fmt.Errorf("delete failed (HTTP %d)", resp.StatusCode)}
		}
		return tuiActionDoneMsg(fmt.Sprintf("Tunnel %s removed", tunnelID))
	}
}

func tuiDoAddRoute(client *http.Client, apiURL, token, sessionID, cidr string) tea.Cmd {
	return func() tea.Msg {
		body := fmt.Sprintf(`{"cidr":%q}`, cidr)
		resp, err := tuiRequest(client, http.MethodPost,
			apiURL+"/api/sessions/"+sessionID+"/routes",
			token, strings.NewReader(body))
		if err != nil {
			return tuiActionErrMsg{err}
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resp.Body)
			return tuiActionErrMsg{fmt.Errorf("%s", strings.TrimSpace(string(b)))}
		}
		return tuiActionDoneMsg(fmt.Sprintf("Route %s added", cidr))
	}
}

func tuiDoRemoveRoute(client *http.Client, apiURL, token, sessionID, cidr string) tea.Cmd {
	return func() tea.Msg {
		escaped := url.PathEscape(cidr)
		resp, err := tuiRequest(client, http.MethodDelete,
			apiURL+"/api/sessions/"+sessionID+"/routes/"+escaped,
			token, nil)
		if err != nil {
			return tuiActionErrMsg{err}
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			return tuiActionErrMsg{fmt.Errorf("delete failed (HTTP %d)", resp.StatusCode)}
		}
		return tuiActionDoneMsg(fmt.Sprintf("Route %s removed", cidr))
	}
}

func tuiDoToggleTUN(client *http.Client, apiURL, token, sessionID string, currentlyActive bool) tea.Cmd {
	return func() tea.Msg {
		method := http.MethodPost
		if currentlyActive {
			method = http.MethodDelete
		}
		resp, err := tuiRequest(client, method,
			apiURL+"/api/sessions/"+sessionID+"/tun",
			token, nil)
		if err != nil {
			return tuiActionErrMsg{err}
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			return tuiActionErrMsg{fmt.Errorf("%s", strings.TrimSpace(string(b)))}
		}
		if currentlyActive {
			return tuiActionDoneMsg("TUN stopped")
		}
		return tuiActionDoneMsg("TUN started — routes auto-added from agent IPs")
	}
}

func tuiTickCmd() tea.Cmd {
	return tea.Tick(5*time.Second, func(t time.Time) tea.Msg {
		return tuiTickMsg(t)
	})
}

// -- Init --

func (m tuiModel) Init() tea.Cmd {
	return tea.Batch(
		tuiFetchSessions(m.client, m.apiURL, m.apiToken),
		tuiTickCmd(),
	)
}

// -- Update --

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case tuiSessionsMsg:
		m.sessions = []tuiSessionInfo(msg)
		m.clearExpiredError()
		if m.view == tuiViewSessions && m.cursor >= len(m.sessions) && len(m.sessions) > 0 {
			m.cursor = len(m.sessions) - 1
		}
		return m, nil

	case tuiTunnelsMsg:
		m.tunnels = []tuiTunnelInfo(msg)
		if m.view == tuiViewSessionDetail && m.detailTab == tuiTabTunnels {
			if m.cursor >= len(m.tunnels) && len(m.tunnels) > 0 {
				m.cursor = len(m.tunnels) - 1
			}
		}
		return m, nil

	case tuiRoutesMsg:
		m.routes = []tuiRouteInfo(msg)
		if m.view == tuiViewSessionDetail && m.detailTab == tuiTabRoutes {
			if m.cursor >= len(m.routes) && len(m.routes) > 0 {
				m.cursor = len(m.routes) - 1
			}
		}
		return m, nil

	case tuiErrMsg:
		m.err = msg.err
		m.errExpiry = time.Now().Add(10 * time.Second)
		return m, nil

	case tuiActionDoneMsg:
		m.statusMsg = string(msg)
		m.err = nil
		m.errExpiry = time.Time{}
		if m.view == tuiViewSessions {
			return m, tuiFetchSessions(m.client, m.apiURL, m.apiToken)
		}
		return m, m.refreshDetail()

	case tuiActionErrMsg:
		m.err = msg.err
		m.errExpiry = time.Now().Add(10 * time.Second)
		m.statusMsg = ""
		return m, nil

	case tuiTickMsg:
		m.clearExpiredError()
		cmds := []tea.Cmd{tuiTickCmd()}
		cmds = append(cmds, tuiFetchSessions(m.client, m.apiURL, m.apiToken))
		if m.view == tuiViewSessionDetail && m.selected != "" {
			cmds = append(cmds, m.refreshDetail())
		}
		return m, tea.Batch(cmds...)
	}
	return m, nil
}

// clearExpiredError clears the error if it has passed the expiry time.
func (m *tuiModel) clearExpiredError() {
	if m.err != nil && !m.errExpiry.IsZero() && time.Now().After(m.errExpiry) {
		m.err = nil
		m.errExpiry = time.Time{}
	}
}

func (m tuiModel) refreshDetail() tea.Cmd {
	return tea.Batch(
		tuiFetchSessions(m.client, m.apiURL, m.apiToken),
		tuiFetchTunnels(m.client, m.apiURL, m.apiToken, m.selected),
		tuiFetchRoutes(m.client, m.apiURL, m.apiToken, m.selected),
	)
}

// -- Key handlers --

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
			return m, m.refreshDetail()
		}
	case "t", "T":
		if len(m.sessions) > 0 && m.cursor < len(m.sessions) {
			s := m.sessions[m.cursor]
			action := "Starting"
			if s.TunActive {
				action = "Stopping"
			}
			m.statusMsg = fmt.Sprintf("%s TUN on %s...", action, s.ID)
			return m, tuiDoToggleTUN(m.client, m.apiURL, m.apiToken, s.ID, s.TunActive)
		}
	case "ctrl+r":
		m.statusMsg = "Refreshing..."
		return m, tuiFetchSessions(m.client, m.apiURL, m.apiToken)
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
	case "T":
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
			m.statusMsg = fmt.Sprintf("%s TUN on %s...", action, m.selected)
			return m, tuiDoToggleTUN(m.client, m.apiURL, m.apiToken, m.selected, active)
		}
	case "ctrl+r":
		m.statusMsg = "Refreshing..."
		return m, m.refreshDetail()
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
			return m, tuiDoRemoveTunnel(m.client, m.apiURL, m.apiToken, m.selected, m.confirmID)
		}
		return m, tuiDoRemoveRoute(m.client, m.apiURL, m.apiToken, m.selected, m.confirmID)
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

	// Toggle fields: Direction (0) and Protocol (3) in tunnel form
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

	// Text input fields
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
	return m, tuiDoAddTunnel(m.client, m.apiURL, m.apiToken, m.selected, direction, listen, remote, proto)
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
	return m, tuiDoAddRoute(m.client, m.apiURL, m.apiToken, m.selected, cidr)
}

// -- View --

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
	return b.String()
}

// tuiRenderBanner renders the top banner box with API info and session count.
func (m tuiModel) tuiRenderBanner(b *strings.Builder) {
	innerWidth := min(m.width-4, 60)
	if innerWidth < 30 {
		innerWidth = 30
	}
	topLine := "┌" + strings.Repeat("─", innerWidth) + "┐"
	botLine := "└" + strings.Repeat("─", innerWidth) + "┘"

	title := "  BURROW  ─  Tunnel Operations"
	titlePadded := title + strings.Repeat(" ", max(0, innerWidth-2-len(title)))

	apiInfo := fmt.Sprintf("  API: %s", m.apiURL)
	sessCount := fmt.Sprintf("%d sessions", len(m.sessions))
	midSep := "  │  "
	infoLine := apiInfo + midSep + sessCount
	if len(infoLine) > innerWidth-2 {
		infoLine = infoLine[:innerWidth-5] + "..."
	}
	infoPadded := infoLine + strings.Repeat(" ", max(0, innerWidth-2-len(infoLine)))

	b.WriteString(tuiBoxBorderStyle.Render(topLine) + "\n")
	b.WriteString(tuiBoxBorderStyle.Render("│") + tuiBannerStyle.Render(titlePadded) + tuiBoxBorderStyle.Render("│") + "\n")
	b.WriteString(tuiBoxBorderStyle.Render("│") + tuiBannerDimStyle.Render(infoPadded) + tuiBoxBorderStyle.Render("│") + "\n")
	b.WriteString(tuiBoxBorderStyle.Render(botLine) + "\n")
}

// tuiRenderHelpBar renders a structured help bar with │ separators.
func tuiRenderHelpBar(items []string) string {
	return tuiHelpStyle.Render("  " + strings.Join(items, " │ "))
}

// tuiRenderSeparator renders a dim horizontal separator line.
func tuiRenderSeparator(width int) string {
	w := min(width-4, 80)
	if w < 10 {
		w = 10
	}
	return tuiSeparatorStyle.Render("  " + strings.Repeat("─", w))
}

func (m tuiModel) viewSessions(b *strings.Builder) {
	m.tuiRenderBanner(b)
	if m.webuiURL != "" {
		b.WriteString(tuiDimStyle.Render(fmt.Sprintf("  WebUI: %s", m.webuiURL)) + "\n")
	}
	b.WriteString("\n")

	if m.err != nil {
		b.WriteString(tuiErrorStyle.Render("  ✗ "+m.err.Error()) + "\n\n")
	}

	if len(m.sessions) == 0 {
		b.WriteString(tuiHelpStyle.Render("  No sessions. Waiting for agents to connect...") + "\n")
	} else {
		hdr := fmt.Sprintf("  %-18s %-14s %-7s %-20s %-6s %4s %4s %-7s %9s %9s  %-8s",
			"ID", "HOSTNAME", "OS", "IPs", "TUN", "T", "R", "STATUS", "IN", "OUT", "UPTIME")
		b.WriteString(tuiHeaderStyle.Render(hdr) + "\n")
		b.WriteString(tuiRenderSeparator(m.width) + "\n")

		for i, s := range m.sessions {
			ips := strings.Join(s.IPs, ",")
			if len(ips) > 18 {
				ips = ips[:15] + "..."
			}

			var statusStr string
			if s.Active {
				statusStr = tuiStatusActiveStyle.Render("active")
			} else {
				statusStr = tuiStatusInactiveStyle.Render("dead  ")
			}

			var tunStr string
			if s.TunActive {
				tunStr = tuiTunUpStyle.Render("TUN UP")
			} else {
				tunStr = tuiTunDownStyle.Render("TUN --")
			}

			cols := fmt.Sprintf("%-18s %-14s %-7s %-20s",
				tuiTruncate(s.ID, 16),
				tuiTruncate(s.Hostname, 12),
				tuiTruncate(s.OS, 5),
				ips)
			nums := fmt.Sprintf(" %4d %4d", s.Tunnels, s.Routes)

			bwIn := tuiColorBytes(s.BytesIn)
			bwOut := tuiColorBytes(s.BytesOut)
			bwStr := fmt.Sprintf(" %9s %9s", bwIn, bwOut)

			uptime := "  " + tuiFormatUptime(s.CreatedAt)

			if i == m.cursor {
				b.WriteString(tuiSelectedStyle.Render("▸ "+cols) + " " + tunStr + tuiSelectedStyle.Render(nums) + " " + statusStr + bwStr + tuiUptimeStyle.Render(uptime) + "\n")
			} else {
				b.WriteString("  " + cols + " " + tunStr + nums + " " + statusStr + bwStr + tuiUptimeStyle.Render(uptime) + "\n")
			}
		}
	}

	if m.statusMsg != "" {
		b.WriteString("\n" + tuiStatusActiveStyle.Render("  "+m.statusMsg))
	}

	b.WriteString("\n\n")
	b.WriteString(tuiRenderHelpBar([]string{
		"↑/k up", "↓/j down", "enter select", "T toggle TUN", "^R refresh", "q quit",
	}))
}

func (m tuiModel) viewDetail(b *strings.Builder) {
	var sess *tuiSessionInfo
	for i := range m.sessions {
		if m.sessions[i].ID == m.selected {
			sess = &m.sessions[i]
			break
		}
	}

	m.tuiRenderBanner(b)
	b.WriteString("\n")

	if sess != nil {
		// Bordered info box for session metadata
		boxWidth := min(m.width-4, 60)
		if boxWidth < 30 {
			boxWidth = 30
		}
		topBorder := "  ┌" + strings.Repeat("─", boxWidth) + "┐"
		botBorder := "  └" + strings.Repeat("─", boxWidth) + "┘"

		var statusStr string
		if sess.Active {
			statusStr = tuiStatusActiveStyle.Render("active")
		} else {
			statusStr = tuiStatusInactiveStyle.Render("inactive")
		}

		var tunStatusStr string
		if sess.TunActive {
			tunStatusStr = tuiTunUpStyle.Render("TUN UP")
		} else {
			tunStatusStr = tuiTunDownStyle.Render("TUN --")
		}

		uptime := tuiFormatUptime(sess.CreatedAt)
		bwIn := tuiColorBytes(sess.BytesIn)
		bwOut := tuiColorBytes(sess.BytesOut)

		infoLines := []string{
			fmt.Sprintf("  Session:   %s", sess.ID),
			fmt.Sprintf("  Hostname:  %s", sess.Hostname),
			fmt.Sprintf("  OS:        %s", sess.OS),
			fmt.Sprintf("  IPs:       %s", strings.Join(sess.IPs, ", ")),
		}

		b.WriteString(tuiBoxBorderStyle.Render(topBorder) + "\n")
		for _, line := range infoLines {
			padded := line + strings.Repeat(" ", max(0, boxWidth-len(line)))
			b.WriteString(tuiBoxBorderStyle.Render("  │") + padded + tuiBoxBorderStyle.Render("│") + "\n")
		}
		// Status line (rendered separately due to ANSI color codes)
		statusLine := "  Status:    "
		b.WriteString(tuiBoxBorderStyle.Render("  │") + statusLine + statusStr + strings.Repeat(" ", max(0, boxWidth-len(statusLine)-len("active   "))) + tunStatusStr + " " + tuiBoxBorderStyle.Render("│") + "\n")
		// Created + uptime line
		createdLine := fmt.Sprintf("  Created:   %s (%s ago)", sess.CreatedAt, uptime)
		createdPad := createdLine + strings.Repeat(" ", max(0, boxWidth-len(createdLine)))
		b.WriteString(tuiBoxBorderStyle.Render("  │") + createdPad + tuiBoxBorderStyle.Render("│") + "\n")
		// Bandwidth line
		bwLabel := "  Bandwidth: "
		b.WriteString(tuiBoxBorderStyle.Render("  │") + bwLabel + bwIn + " in / " + bwOut + " out" + strings.Repeat(" ", max(0, boxWidth-len(bwLabel)-len(tuiFormatBytes(sess.BytesIn)+" in / "+tuiFormatBytes(sess.BytesOut)+" out"))) + tuiBoxBorderStyle.Render("│") + "\n")
		b.WriteString(tuiBoxBorderStyle.Render(botBorder) + "\n")
	} else {
		b.WriteString(tuiDimStyle.Render("  Session data not available (may have disconnected)") + "\n")
	}

	b.WriteString("\n")

	var tunnelTab, routeTab string
	if m.detailTab == tuiTabTunnels {
		tunnelTab = tuiActiveTabStyle.Render(" Tunnels ")
		routeTab = tuiInactiveTabStyle.Render(" Routes ")
	} else {
		tunnelTab = tuiInactiveTabStyle.Render(" Tunnels ")
		routeTab = tuiActiveTabStyle.Render(" Routes ")
	}
	b.WriteString("  " + tunnelTab + "  " + routeTab + "\n")

	b.WriteString(tuiRenderSeparator(m.width) + "\n")

	if m.detailTab == tuiTabTunnels {
		m.viewTunnels(b)
	} else {
		m.viewRoutes(b)
	}

	if m.err != nil {
		b.WriteString("\n" + tuiErrorStyle.Render("  ✗ "+m.err.Error()))
	}
	if m.statusMsg != "" {
		b.WriteString("\n" + tuiStatusActiveStyle.Render("  "+m.statusMsg))
	}

	b.WriteString("\n\n")
	b.WriteString(tuiRenderHelpBar([]string{
		"↑/k up", "↓/j down", "T toggle TUN", "t tunnel", "r route", "d delete", "^R refresh", "tab switch", "esc back",
	}))
}

func (m tuiModel) viewTunnels(b *strings.Builder) {
	if len(m.tunnels) == 0 {
		b.WriteString(tuiDimStyle.Render("  (no tunnels)") + "\n")
		return
	}

	hdr := fmt.Sprintf("  %-18s %-8s %-22s %-22s %-6s %-7s",
		"ID", "DIR", "LISTEN", "REMOTE", "PROTO", "STATUS")
	b.WriteString(tuiHeaderStyle.Render(hdr) + "\n")

	for i, t := range m.tunnels {
		var statusStr string
		if t.Active {
			statusStr = tuiStatusActiveStyle.Render("active")
		} else {
			statusStr = tuiStatusInactiveStyle.Render("dead  ")
		}

		cols := fmt.Sprintf("%-18s %-8s %-22s %-22s %-6s",
			tuiTruncate(t.ID, 16),
			t.Direction,
			tuiTruncate(t.ListenAddr, 20),
			tuiTruncate(t.RemoteAddr, 20),
			t.Protocol)

		if i == m.cursor {
			b.WriteString(tuiSelectedStyle.Render("▸ "+cols) + " " + statusStr + "\n")
		} else {
			b.WriteString("  " + cols + " " + statusStr + "\n")
		}
	}
}

func (m tuiModel) viewRoutes(b *strings.Builder) {
	if len(m.routes) == 0 {
		b.WriteString(tuiDimStyle.Render("  (no routes)") + "\n")
		return
	}

	hdr := fmt.Sprintf("  %-30s %-7s", "CIDR", "STATUS")
	b.WriteString(tuiHeaderStyle.Render(hdr) + "\n")

	for i, r := range m.routes {
		var statusStr string
		if r.Active {
			statusStr = tuiStatusActiveStyle.Render("active")
		} else {
			statusStr = tuiStatusInactiveStyle.Render("dead  ")
		}

		if i == m.cursor {
			b.WriteString(tuiSelectedStyle.Render(fmt.Sprintf("▸ %-30s", r.CIDR)) + " " + statusStr + "\n")
		} else {
			b.WriteString(fmt.Sprintf("  %-30s", r.CIDR) + " " + statusStr + "\n")
		}
	}
}

func (m tuiModel) viewConfirm(b *strings.Builder) {
	m.tuiRenderBanner(b)
	b.WriteString("\n")

	boxWidth := min(m.width-4, 50)
	if boxWidth < 30 {
		boxWidth = 30
	}
	topBorder := "  ┌" + strings.Repeat("─", boxWidth) + "┐"
	botBorder := "  └" + strings.Repeat("─", boxWidth) + "┘"

	idDisplay := m.confirmID
	if len(idDisplay) > boxWidth-20 {
		idDisplay = idDisplay[:boxWidth-23] + "..."
	}
	prompt := fmt.Sprintf("  Delete %s %s?", m.confirmType, idDisplay)
	promptPad := prompt + strings.Repeat(" ", max(0, boxWidth-len(prompt)))
	hint := "  Press y to confirm, n or esc to cancel"
	hintPad := hint + strings.Repeat(" ", max(0, boxWidth-len(hint)))
	blankLine := strings.Repeat(" ", boxWidth)

	b.WriteString(topBorder + "\n")
	b.WriteString(tuiBoxBorderStyle.Render("  │") + blankLine + tuiBoxBorderStyle.Render("│") + "\n")
	b.WriteString(tuiBoxBorderStyle.Render("  │") + tuiConfirmStyle.Render(promptPad) + tuiBoxBorderStyle.Render("│") + "\n")
	b.WriteString(tuiBoxBorderStyle.Render("  │") + blankLine + tuiBoxBorderStyle.Render("│") + "\n")
	b.WriteString(tuiBoxBorderStyle.Render("  │") + tuiDimStyle.Render(hintPad) + tuiBoxBorderStyle.Render("│") + "\n")
	b.WriteString(tuiBoxBorderStyle.Render("  │") + blankLine + tuiBoxBorderStyle.Render("│") + "\n")
	b.WriteString(botBorder + "\n")

	b.WriteString("\n")
	b.WriteString(tuiRenderHelpBar([]string{"y confirm", "n cancel", "esc cancel"}))
}

func (m tuiModel) viewForm(b *strings.Builder, title string) {
	m.tuiRenderBanner(b)
	b.WriteString("\n")
	b.WriteString(tuiTitleStyle.Render(fmt.Sprintf("  %s", title)))
	b.WriteString(tuiFieldCounter.Render(fmt.Sprintf("  (Field %d/%d)", m.inputCursor+1, len(m.inputFields))))
	b.WriteString("\n")
	b.WriteString(tuiDimStyle.Render(fmt.Sprintf("  Session: %s", m.selected)) + "\n")
	b.WriteString(tuiRenderSeparator(m.width) + "\n\n")

	if m.err != nil {
		b.WriteString(tuiErrorStyle.Render("  ✗ "+m.err.Error()) + "\n\n")
	}

	isTunnelForm := title == "Add Tunnel"

	boxWidth := min(m.width-8, 50)
	if boxWidth < 20 {
		boxWidth = 20
	}

	for i, field := range m.inputFields {
		label := field + ":"
		value := m.inputValues[i]
		isToggle := isTunnelForm && (i == 0 || i == 3)
		focused := i == m.inputCursor

		if focused {
			b.WriteString(tuiSelectedStyle.Render("▸ ") + tuiFocusedStyle.Render(label) + "\n")
		} else {
			b.WriteString("  " + tuiDimStyle.Render(label) + "\n")
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
						parts = append(parts, tuiFocusedStyle.Render(" ["+opt+"] "))
					} else {
						parts = append(parts, " ["+opt+"] ")
					}
				} else {
					parts = append(parts, tuiDimStyle.Render("  "+opt+"  "))
				}
			}
			optStr := strings.Join(parts, "")
			if focused {
				b.WriteString("    ┌" + strings.Repeat("─", boxWidth) + "┐\n")
				b.WriteString("    │ " + optStr + strings.Repeat(" ", max(0, boxWidth-1-len(optStr)/2)) + "│\n")
				b.WriteString("    └" + strings.Repeat("─", boxWidth) + "┘\n")
			} else {
				b.WriteString(tuiFormBorder.Render("    ┌"+strings.Repeat("─", boxWidth)+"┐") + "\n")
				b.WriteString(tuiFormBorder.Render("    │ ") + optStr + tuiFormBorder.Render(strings.Repeat(" ", max(0, boxWidth-1-len(optStr)/2))+"│") + "\n")
				b.WriteString(tuiFormBorder.Render("    └"+strings.Repeat("─", boxWidth)+"┘") + "\n")
			}
		} else {
			cursor := ""
			if focused {
				cursor = tuiFocusedStyle.Render("█")
			}
			displayVal := value + cursor
			valWidth := len(value)
			if focused {
				valWidth++ // for cursor block
			}
			padding := max(0, boxWidth-2-valWidth)

			if focused {
				b.WriteString("    ┌" + strings.Repeat("─", boxWidth) + "┐\n")
				b.WriteString("    │ " + displayVal + strings.Repeat(" ", padding) + " │\n")
				b.WriteString("    └" + strings.Repeat("─", boxWidth) + "┘\n")
			} else {
				b.WriteString(tuiFormBorder.Render("    ┌"+strings.Repeat("─", boxWidth)+"┐") + "\n")
				b.WriteString(tuiFormBorder.Render("    │ ") + value + tuiFormBorder.Render(strings.Repeat(" ", padding+1)+"│") + "\n")
				b.WriteString(tuiFormBorder.Render("    └"+strings.Repeat("─", boxWidth)+"┘") + "\n")
			}
		}
		b.WriteString("\n")
	}

	b.WriteString(tuiRenderHelpBar([]string{
		"enter submit", "tab/↓ next", "shift+tab/↑ prev", "space toggle", "esc cancel",
	}))
}

// -- Helpers --

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

// tuiColorBytes returns the formatted byte string with color based on thresholds.
// Green < 1MB, Yellow 1-100MB, Red > 100MB.
func tuiColorBytes(b int64) string {
	text := tuiFormatBytes(b)
	const (
		MB = 1024 * 1024
	)
	switch {
	case b >= 100*MB:
		return tuiBwRedStyle.Render(text)
	case b >= MB:
		return tuiBwYellowStyle.Render(text)
	default:
		return tuiBwGreenStyle.Render(text)
	}
}

// tuiFormatUptime parses an RFC3339 CreatedAt string and returns human-readable duration.
// Returns "2h 14m", "3d 5h", "< 1m", etc.
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


// RunTUI launches the interactive TUI dashboard, connecting to the given API URL.
// It blocks until the user exits the TUI.
func RunTUI(apiURL, webuiURL string) error {
	m := tuiModel{
		apiURL:   strings.TrimRight(apiURL, "/"),
		webuiURL: webuiURL,
		client:   tuiNewHTTPClient(),
	}
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
