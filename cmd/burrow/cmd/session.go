package cmd

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

// sessionHTTPClient returns an HTTP client configured for the session commands.
// When using HTTPS with self-signed certs, TLS verification is skipped.
func sessionHTTPClient(useTLS bool) *http.Client {
	if useTLS {
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}
	return &http.Client{}
}

// sessionBaseURL constructs the base URL from address and TLS mode.
func sessionBaseURL(addr string, noTLS bool) string {
	scheme := "https"
	if noTLS {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s", scheme, addr)
}

// newAuthRequest creates an HTTP request with the Authorization header set.
func newAuthRequest(method, reqURL string, body io.Reader, token string) (*http.Request, error) {
	req, err := http.NewRequest(method, reqURL, body)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req, nil
}

// doAuthGet performs an authenticated GET request.
func doAuthGet(client *http.Client, reqURL, token string) (*http.Response, error) {
	req, err := newAuthRequest(http.MethodGet, reqURL, nil, token)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

var sessionCmd = &cobra.Command{
	Use:   "session",
	Short: "Manage agent sessions",
	Long: `View and interact with connected agent sessions.

These commands query the proxy server's session manager to display
connected agents, their tunnels, and routes.`,
}

var sessionListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all active agent sessions",
	Long: `List all agents currently connected to the proxy server.

Example:
  burrow session list
  burrow session list --webui 0.0.0.0:9090
  burrow session list --token <api-token>`,
	Run: func(cmd *cobra.Command, _ []string) {
		webuiAddr, _ := cmd.Flags().GetString("webui")
		token, _ := cmd.Flags().GetString("token")
		noTLS, _ := cmd.Flags().GetBool("no-tls")

		client := sessionHTTPClient(!noTLS)
		baseURL := sessionBaseURL(webuiAddr, noTLS)
		apiURL := baseURL + "/api/sessions"

		resp, err := doAuthGet(client, apiURL, token)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to connect to server at %s: %v\n", webuiAddr, err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized {
			fmt.Fprintf(os.Stderr, "[!] Authentication failed (401). Check your --token value.\n")
			os.Exit(1)
		}

		var sessions []struct {
			ID        string   `json:"id"`
			Hostname  string   `json:"hostname"`
			OS        string   `json:"os"`
			IPs       []string `json:"ips"`
			Active    bool     `json:"active"`
			CreatedAt string   `json:"created_at"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&sessions); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to parse response: %v\n", err)
			os.Exit(1)
		}

		if len(sessions) == 0 {
			fmt.Println("[*] No active sessions")
			return
		}

		fmt.Println("[*] Active sessions:")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tHostname\tOS\tIPs\tCreated")
		for _, s := range sessions {
			ips := strings.Join(s.IPs, ", ")
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", s.ID, s.Hostname, s.OS, ips, s.CreatedAt)
		}
		w.Flush()
	},
}

var sessionInfoCmd = &cobra.Command{
	Use:   "info [session-id]",
	Short: "Show details for an agent session",
	Long: `Display detailed information about a connected agent session including
hostname, OS, IP addresses, active tunnels, and routes.

Example:
  burrow session info abc123
  burrow session info abc123 --token <api-token>`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		sessionID := args[0]
		webuiAddr, _ := cmd.Flags().GetString("webui")
		token, _ := cmd.Flags().GetString("token")
		noTLS, _ := cmd.Flags().GetBool("no-tls")

		client := sessionHTTPClient(!noTLS)
		baseURL := sessionBaseURL(webuiAddr, noTLS)

		resp, err := doAuthGet(client, baseURL+"/api/sessions/"+sessionID, token)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to connect: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized {
			fmt.Fprintf(os.Stderr, "[!] Authentication failed (401). Check your --token value.\n")
			os.Exit(1)
		}

		if resp.StatusCode == http.StatusNotFound {
			fmt.Fprintf(os.Stderr, "[!] Session %s not found\n", sessionID)
			os.Exit(1)
		}

		var sess struct {
			ID        string   `json:"id"`
			Hostname  string   `json:"hostname"`
			OS        string   `json:"os"`
			IPs       []string `json:"ips"`
			Active    bool     `json:"active"`
			CreatedAt string   `json:"created_at"`
		}
		json.NewDecoder(resp.Body).Decode(&sess)

		fmt.Printf("[*] Session: %s\n", sess.ID)
		fmt.Printf("    Hostname:  %s\n", sess.Hostname)
		fmt.Printf("    OS:        %s\n", sess.OS)
		fmt.Printf("    IPs:       %s\n", strings.Join(sess.IPs, ", "))
		status := "inactive"
		if sess.Active {
			status = "active"
		}
		fmt.Printf("    Status:    %s\n", status)
		fmt.Printf("    Created:   %s\n", sess.CreatedAt)

		printSessionTunnels(client, baseURL, sessionID, token)
		printSessionRoutes(client, baseURL, sessionID, token)
	},
}

var sessionUseCmd = &cobra.Command{
	Use:   "use [session-id]",
	Short: "Select a session for interactive commands",
	Long: `Select an agent session for interactive tunnel and route management.

Commands available in the interactive shell:
  info                              Show session details
  tunnels                           List active tunnels
  routes                            List active routes
  tunnel add <dir> <listen> <remote> Add a tunnel
  tunnel rm <tunnel-id>             Remove a tunnel
  route add <cidr>                  Add a route
  route rm <cidr>                   Remove a route
  help                              Show available commands
  exit                              Exit interactive mode

Example:
  burrow session use abc123
  burrow session use abc123 --token <api-token>`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		sessionID := args[0]
		webuiAddr, _ := cmd.Flags().GetString("webui")
		token, _ := cmd.Flags().GetString("token")
		noTLS, _ := cmd.Flags().GetBool("no-tls")

		client := sessionHTTPClient(!noTLS)
		baseURL := sessionBaseURL(webuiAddr, noTLS)

		resp, err := doAuthGet(client, baseURL+"/api/sessions/"+sessionID, token)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to connect: %v\n", err)
			os.Exit(1)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			fmt.Fprintf(os.Stderr, "[!] Authentication failed (401). Check your --token value.\n")
			os.Exit(1)
		}
		if resp.StatusCode == http.StatusNotFound {
			fmt.Fprintf(os.Stderr, "[!] Session %s not found\n", sessionID)
			os.Exit(1)
		}

		fmt.Printf("[*] Session %s selected. Type 'help' for commands.\n", sessionID)
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Print("burrow> ")
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				fmt.Print("burrow> ")
				continue
			}

			parts := strings.Fields(line)
			switch parts[0] {
			case "exit", "quit":
				return
			case "info":
				replInfo(client, baseURL, sessionID, token)
			case "tunnels":
				printSessionTunnels(client, baseURL, sessionID, token)
			case "routes":
				printSessionRoutes(client, baseURL, sessionID, token)
			case "tunnel":
				handleTunnelCmd(client, baseURL, sessionID, parts[1:], token)
			case "route":
				handleRouteCmd(client, baseURL, sessionID, parts[1:], token)
			case "tun":
				handleTunCmd(client, baseURL, sessionID, parts[1:], token)
			case "help":
				fmt.Println("Commands:")
				fmt.Println("  info                              Session details")
				fmt.Println("  tunnels                           List tunnels")
				fmt.Println("  routes                            List routes")
				fmt.Println("  tunnel add <dir> <listen> <remote> Add tunnel")
				fmt.Println("  tunnel rm <tunnel-id>             Remove tunnel")
				fmt.Println("  route add <cidr>                  Add route")
				fmt.Println("  route rm <cidr>                   Remove route")
				fmt.Println("  tun start                         Start TUN interface (root required)")
				fmt.Println("  tun stop                          Stop TUN interface")
				fmt.Println("  exit                              Exit")
			default:
				fmt.Printf("Unknown command: %s (type 'help')\n", parts[0])
			}
			fmt.Print("burrow> ")
		}
	},
}

func init() {
	rootCmd.AddCommand(sessionCmd)
	sessionCmd.AddCommand(sessionListCmd)
	sessionCmd.AddCommand(sessionInfoCmd)
	sessionCmd.AddCommand(sessionUseCmd)

	sessionCmd.PersistentFlags().String("webui", "0.0.0.0:9090", "WebUI server address")
	sessionCmd.PersistentFlags().String("token", "", "API authentication token")
	sessionCmd.PersistentFlags().Bool("no-tls", false, "Use plain HTTP instead of HTTPS")
}

func printSessionTunnels(client *http.Client, baseURL, sessionID, token string) {
	resp, err := doAuthGet(client, baseURL+"/api/sessions/"+sessionID+"/tunnels", token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to get tunnels: %v\n", err)
		return
	}
	defer resp.Body.Close()

	var tunnels []struct {
		ID         string `json:"id"`
		Direction  string `json:"direction"`
		ListenAddr string `json:"listen_addr"`
		RemoteAddr string `json:"remote_addr"`
		Protocol   string `json:"protocol"`
		Active     bool   `json:"active"`
	}
	json.NewDecoder(resp.Body).Decode(&tunnels)

	if len(tunnels) == 0 {
		fmt.Println("    Tunnels:   (none)")
		return
	}
	fmt.Println("    Tunnels:")
	for _, t := range tunnels {
		status := "inactive"
		if t.Active {
			status = "active"
		}
		fmt.Printf("      [%s] %s %s -> %s (%s) [%s]\n",
			t.ID, t.Direction, t.ListenAddr, t.RemoteAddr, t.Protocol, status)
	}
}

func printSessionRoutes(client *http.Client, baseURL, sessionID, token string) {
	resp, err := doAuthGet(client, baseURL+"/api/sessions/"+sessionID+"/routes", token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to get routes: %v\n", err)
		return
	}
	defer resp.Body.Close()

	var routes []struct {
		CIDR   string `json:"cidr"`
		Active bool   `json:"active"`
	}
	json.NewDecoder(resp.Body).Decode(&routes)

	if len(routes) == 0 {
		fmt.Println("    Routes:    (none)")
		return
	}
	fmt.Println("    Routes:")
	for _, r := range routes {
		status := "inactive"
		if r.Active {
			status = "active"
		}
		fmt.Printf("      %s [%s]\n", r.CIDR, status)
	}
}

func replInfo(client *http.Client, baseURL, sessionID, token string) {
	resp, err := doAuthGet(client, baseURL+"/api/sessions/"+sessionID, token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		return
	}
	defer resp.Body.Close()

	var sess struct {
		ID        string   `json:"id"`
		Hostname  string   `json:"hostname"`
		OS        string   `json:"os"`
		IPs       []string `json:"ips"`
		Active    bool     `json:"active"`
		CreatedAt string   `json:"created_at"`
	}
	json.NewDecoder(resp.Body).Decode(&sess)

	fmt.Printf("  ID:        %s\n", sess.ID)
	fmt.Printf("  Hostname:  %s\n", sess.Hostname)
	fmt.Printf("  OS:        %s\n", sess.OS)
	fmt.Printf("  IPs:       %s\n", strings.Join(sess.IPs, ", "))
	fmt.Printf("  Created:   %s\n", sess.CreatedAt)
}

func handleTunnelCmd(client *http.Client, baseURL, sessionID string, args []string, token string) {
	if len(args) == 0 {
		fmt.Println("Usage: tunnel add <direction> <listen> <remote>  |  tunnel rm <id>")
		return
	}
	switch args[0] {
	case "add":
		if len(args) < 4 {
			fmt.Println("Usage: tunnel add <direction> <listen> <remote> [protocol]")
			return
		}
		proto := "tcp"
		if len(args) >= 5 {
			proto = args[4]
		}
		body := fmt.Sprintf(`{"direction":%q,"listen":%q,"remote":%q,"protocol":%q}`,
			args[1], args[2], args[3], proto)
		req, err := newAuthRequest(http.MethodPost,
			baseURL+"/api/sessions/"+sessionID+"/tunnels",
			strings.NewReader(body), token)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			respBody, _ := io.ReadAll(resp.Body)
			fmt.Fprintf(os.Stderr, "[!] Failed: %s\n", string(respBody))
			return
		}
		var result struct {
			ID string `json:"id"`
		}
		json.NewDecoder(resp.Body).Decode(&result)
		fmt.Printf("[+] Tunnel created: %s\n", result.ID)

	case "rm", "remove", "del":
		if len(args) < 2 {
			fmt.Println("Usage: tunnel rm <tunnel-id>")
			return
		}
		req, err := newAuthRequest(http.MethodDelete,
			baseURL+"/api/sessions/"+sessionID+"/tunnels/"+args[1], nil, token)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusNoContent {
			fmt.Printf("[-] Tunnel %s removed\n", args[1])
		} else {
			fmt.Fprintf(os.Stderr, "[!] Failed (status %d)\n", resp.StatusCode)
		}

	default:
		fmt.Printf("Unknown tunnel subcommand: %s\n", args[0])
	}
}

func handleRouteCmd(client *http.Client, baseURL, sessionID string, args []string, token string) {
	if len(args) == 0 {
		fmt.Println("Usage: route add <cidr>  |  route rm <cidr>")
		return
	}
	switch args[0] {
	case "add":
		if len(args) < 2 {
			fmt.Println("Usage: route add <cidr>")
			return
		}
		body := fmt.Sprintf(`{"cidr":%q}`, args[1])
		req, err := newAuthRequest(http.MethodPost,
			baseURL+"/api/sessions/"+sessionID+"/routes",
			strings.NewReader(body), token)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			respBody, _ := io.ReadAll(resp.Body)
			fmt.Fprintf(os.Stderr, "[!] Failed: %s\n", string(respBody))
			return
		}
		fmt.Printf("[+] Route %s added\n", args[1])

	case "rm", "remove", "del":
		if len(args) < 2 {
			fmt.Println("Usage: route rm <cidr>")
			return
		}
		escaped := url.PathEscape(args[1])
		req, err := newAuthRequest(http.MethodDelete,
			baseURL+"/api/sessions/"+sessionID+"/routes/"+escaped, nil, token)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusNoContent {
			fmt.Printf("[-] Route %s removed\n", args[1])
		} else {
			fmt.Fprintf(os.Stderr, "[!] Failed (status %d)\n", resp.StatusCode)
		}

	default:
		fmt.Printf("Unknown route subcommand: %s\n", args[0])
	}
}

func handleTunCmd(client *http.Client, baseURL, sessionID string, args []string, token string) {
	if len(args) == 0 {
		fmt.Println("Usage: tun start | tun stop")
		return
	}
	switch args[0] {
	case "start":
		req, err := newAuthRequest(http.MethodPost, baseURL+"/api/sessions/"+sessionID+"/tun", nil, token)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			fmt.Fprintf(os.Stderr, "[!] TUN start failed: %s\n", string(body))
			return
		}
		var result map[string]string
		json.NewDecoder(resp.Body).Decode(&result)
		fmt.Printf("[+] TUN interface %s started (magic IP: %s)\n", result["interface"], result["magic_ip"])
		fmt.Println("[*] Routes added via 'route add' will auto-route through TUN")

	case "stop":
		req, err := newAuthRequest(http.MethodDelete, baseURL+"/api/sessions/"+sessionID+"/tun", nil, token)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			fmt.Println("[-] TUN interface stopped")
		} else {
			body, _ := io.ReadAll(resp.Body)
			fmt.Fprintf(os.Stderr, "[!] TUN stop failed: %s\n", string(body))
		}

	default:
		fmt.Printf("Unknown tun subcommand: %s\n", args[0])
	}
}
