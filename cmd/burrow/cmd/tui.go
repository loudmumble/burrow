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
	"github.com/spf13/cobra"
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
)

type tuiDetailTab int

const (
	tuiTabTunnels tuiDetailTab = iota
	tuiTabRoutes
)

// -- Bubbletea model --

type tuiModel struct {
	apiURL      string
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
	width       int
	height      int
	detailTab   tuiDetailTab
	inputFields []string
	inputCursor int
	inputValues []string
	statusMsg   string
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
		m.err = nil
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
		return m, nil

	case tuiActionDoneMsg:
		m.statusMsg = string(msg)
		m.err = nil
		return m, m.refreshDetail()

	case tuiActionErrMsg:
		m.err = msg.err
		m.statusMsg = ""
		return m, nil

	case tuiTickMsg:
		cmds := []tea.Cmd{tuiTickCmd()}
		cmds = append(cmds, tuiFetchSessions(m.client, m.apiURL, m.apiToken))
		if m.view == tuiViewSessionDetail && m.selected != "" {
			cmds = append(cmds, m.refreshDetail())
		}
		return m, tea.Batch(cmds...)
	}
	return m, nil
}

func (m tuiModel) refreshDetail() tea.Cmd {
	return tea.Batch(
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
			return m, m.refreshDetail()
		}
	case "r":
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
		m.inputFields = []string{"Direction (local/remote)", "Listen Address", "Remote Address", "Protocol"}
		m.inputValues = []string{"local", "", "", "tcp"}
		m.inputCursor = 1
		m.statusMsg = ""
		m.err = nil
	case "r":
		m.view = tuiViewAddRoute
		m.inputFields = []string{"CIDR (e.g. 10.0.0.0/24)"}
		m.inputValues = []string{""}
		m.inputCursor = 0
		m.statusMsg = ""
		m.err = nil
	case "d", "delete":
		return m.handleDelete()
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
		tid := m.tunnels[m.cursor].ID
		m.statusMsg = ""
		return m, tuiDoRemoveTunnel(m.client, m.apiURL, m.apiToken, m.selected, tid)
	}
	if m.detailTab == tuiTabRoutes && m.cursor < len(m.routes) {
		cidr := m.routes[m.cursor].CIDR
		m.statusMsg = ""
		return m, tuiDoRemoveRoute(m.client, m.apiURL, m.apiToken, m.selected, cidr)
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
	case "backspace":
		v := m.inputValues[m.inputCursor]
		if len(v) > 0 {
			m.inputValues[m.inputCursor] = v[:len(v)-1]
		}
		return m, nil
	case "enter":
		if isTunnel {
			return m.submitTunnel()
		}
		return m.submitRoute()
	default:
		if len(key) == 1 && key[0] >= 32 && key[0] <= 126 {
			m.inputValues[m.inputCursor] += key
		}
		return m, nil
	}
}

func (m tuiModel) submitTunnel() (tea.Model, tea.Cmd) {
	direction := strings.TrimSpace(m.inputValues[0])
	listen := strings.TrimSpace(m.inputValues[1])
	remote := strings.TrimSpace(m.inputValues[2])
	proto := strings.TrimSpace(m.inputValues[3])
	if direction == "" || listen == "" || remote == "" {
		m.err = fmt.Errorf("direction, listen address, and remote address are required")
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
	}
	return b.String()
}

func (m tuiModel) viewSessions(b *strings.Builder) {
	b.WriteString(tuiTitleStyle.Render("  BURROW Dashboard") + "\n")
	b.WriteString(tuiDimStyle.Render(fmt.Sprintf("  %s  |  %d session(s)  |  auto-refresh 5s",
		m.apiURL, len(m.sessions))) + "\n\n")

	if m.err != nil {
		b.WriteString(tuiErrorStyle.Render("  Error: "+m.err.Error()) + "\n\n")
	}

	if len(m.sessions) == 0 {
		b.WriteString(tuiHelpStyle.Render("  No sessions. Waiting for agents to connect...") + "\n")
	} else {
		hdr := fmt.Sprintf("  %-18s %-14s %-7s %-20s %4s %4s %-7s %9s %9s",
			"ID", "HOSTNAME", "OS", "IPs", "T", "R", "STATUS", "IN", "OUT")
		b.WriteString(tuiHeaderStyle.Render(hdr) + "\n")

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

			cols := fmt.Sprintf("%-18s %-14s %-7s %-20s %4d %4d",
				tuiTruncate(s.ID, 16),
				tuiTruncate(s.Hostname, 12),
				tuiTruncate(s.OS, 5),
				ips, s.Tunnels, s.Routes)

			bw := fmt.Sprintf(" %9s %9s",
				tuiFormatBytes(s.BytesIn), tuiFormatBytes(s.BytesOut))

			if i == m.cursor {
				b.WriteString(tuiSelectedStyle.Render("▸ "+cols) + " " + statusStr + tuiSelectedStyle.Render(bw) + "\n")
			} else {
				b.WriteString("  " + cols + " " + statusStr + bw + "\n")
			}
		}
	}

	if m.statusMsg != "" {
		b.WriteString("\n" + tuiStatusActiveStyle.Render("  "+m.statusMsg))
	}

	b.WriteString("\n\n")
	b.WriteString(tuiHelpStyle.Render("  ↑/k up  ↓/j down  enter select  r refresh  q quit"))
}

func (m tuiModel) viewDetail(b *strings.Builder) {
	var sess *tuiSessionInfo
	for i := range m.sessions {
		if m.sessions[i].ID == m.selected {
			sess = &m.sessions[i]
			break
		}
	}

	b.WriteString(tuiTitleStyle.Render(fmt.Sprintf("  Session: %s", m.selected)) + "\n\n")

	if sess != nil {
		var statusStr string
		if sess.Active {
			statusStr = tuiStatusActiveStyle.Render("active")
		} else {
			statusStr = tuiStatusInactiveStyle.Render("inactive")
		}

		b.WriteString(fmt.Sprintf("  Hostname:  %s\n", sess.Hostname))
		b.WriteString(fmt.Sprintf("  OS:        %s\n", sess.OS))
		b.WriteString(fmt.Sprintf("  IPs:       %s\n", strings.Join(sess.IPs, ", ")))
		b.WriteString(fmt.Sprintf("  Status:    %s\n", statusStr))
		b.WriteString(fmt.Sprintf("  Created:   %s\n", sess.CreatedAt))
		b.WriteString(fmt.Sprintf("  Bytes:     %s in / %s out\n",
			tuiFormatBytes(sess.BytesIn), tuiFormatBytes(sess.BytesOut)))
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

	lineWidth := min(m.width-4, 80)
	if lineWidth < 20 {
		lineWidth = 20
	}
	b.WriteString("  " + strings.Repeat("─", lineWidth) + "\n")

	if m.detailTab == tuiTabTunnels {
		m.viewTunnels(b)
	} else {
		m.viewRoutes(b)
	}

	if m.err != nil {
		b.WriteString("\n" + tuiErrorStyle.Render("  Error: "+m.err.Error()))
	}
	if m.statusMsg != "" {
		b.WriteString("\n" + tuiStatusActiveStyle.Render("  "+m.statusMsg))
	}

	b.WriteString("\n\n")
	b.WriteString(tuiHelpStyle.Render("  ↑/k up  ↓/j down  t tunnel  r route  d delete  tab switch  esc back"))
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

func (m tuiModel) viewForm(b *strings.Builder, title string) {
	b.WriteString(tuiTitleStyle.Render(fmt.Sprintf("  %s", title)) + "\n")
	b.WriteString(tuiDimStyle.Render(fmt.Sprintf("  Session: %s", m.selected)) + "\n\n")

	if m.err != nil {
		b.WriteString(tuiErrorStyle.Render("  Error: "+m.err.Error()) + "\n\n")
	}

	for i, field := range m.inputFields {
		label := fmt.Sprintf("%-32s", field+":")
		value := m.inputValues[i]

		if i == m.inputCursor {
			cursor := tuiFocusedStyle.Render("|")
			b.WriteString(tuiSelectedStyle.Render("▸ ") + tuiFocusedStyle.Render(label) + " [" + value + cursor + "]\n")
		} else {
			b.WriteString("  " + tuiDimStyle.Render(label) + " [" + value + "]\n")
		}
	}

	b.WriteString("\n")
	b.WriteString(tuiHelpStyle.Render("  enter submit  tab/↓ next  shift+tab/↑ prev  esc cancel"))
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

func tuiTruncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// -- Cobra command --

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Launch interactive TUI dashboard",
	Long: `Launch an interactive terminal UI for managing Burrow sessions, tunnels, and routes.

The TUI connects to Burrow's REST API (the same API used by the WebUI dashboard)
and provides a keyboard-driven interface for monitoring and managing sessions.

Controls:
  Sessions view:   ↑/k up, ↓/j down, enter select, r refresh, q quit
  Detail view:     tab switch tunnels/routes, t add tunnel, r add route, d delete, esc back
  Form view:       tab/↓ next field, shift+tab/↑ prev field, enter submit, esc cancel

Examples:
  burrow tui
  burrow tui --api-url http://localhost:9090
  burrow tui --api-url https://server:9090 --token <api-token>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		apiURL, _ := cmd.Flags().GetString("api-url")
		apiToken, _ := cmd.Flags().GetString("token")

		m := tuiModel{
			apiURL:   strings.TrimRight(apiURL, "/"),
			apiToken: apiToken,
			client:   tuiNewHTTPClient(),
		}

		p := tea.NewProgram(m, tea.WithAltScreen())
		_, err := p.Run()
		return err
	},
}

func init() {
	tuiCmd.Flags().String("api-url", "http://localhost:8080", "Burrow API URL")
	tuiCmd.Flags().String("token", "", "API authentication token")
	rootCmd.AddCommand(tuiCmd)
}
