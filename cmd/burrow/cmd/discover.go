package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"crypto/tls"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/loudmumble/burrow/internal/discovery"
	"github.com/spf13/cobra"
)

// topologyCmd shows infrastructure view from Burrow server.
var topologyCmd = &cobra.Command{
	Use:   "topology",
	Short: "Show pivot infrastructure topology from Burrow server",
	Long: `Display the current pivot infrastructure including all connected agents,
active tunnels, routes, and discovered hosts from scan results.

This command queries a running Burrow server to show your complete
pivot infrastructure at a glance.

Examples:
  burrow topology                                    # Query localhost
  burrow topology --api-url 10.0.0.1:9091           # Query remote server
  burrow topology --token <api-token>                # With authentication`,
	Run: func(cmd *cobra.Command, args []string) {
		apiUrl, _ := cmd.Flags().GetString("api-url")
		apiToken, _ := cmd.Flags().GetString("api-token")
		noTLS, _ := cmd.Flags().GetBool("no-tls")

		// Auto-detect scheme: http for localhost, https otherwise
		if !strings.HasPrefix(apiUrl, "http") {
			scheme := "https"
			if noTLS || strings.HasPrefix(apiUrl, "127.0.0.1") || strings.HasPrefix(apiUrl, "localhost") {
				scheme = "http"
			}
			apiUrl = scheme + "://" + apiUrl
		}

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

		doRequest := func(url string) (*http.Response, error) {
			req, err := http.NewRequest("GET", url+"/api/topology", nil)
			if err != nil {
				return nil, err
			}
			if apiToken != "" {
				req.Header.Set("Authorization", "Bearer "+apiToken)
			}
			return client.Do(req)
		}

		resp, err := doRequest(apiUrl)

		// Automatic HTTP fallback if HTTPS fails (connection error).
		if err != nil && strings.HasPrefix(apiUrl, "https://") {
			httpUrl := "http://" + strings.TrimPrefix(apiUrl, "https://")
			if fallbackResp, fallbackErr := doRequest(httpUrl); fallbackErr == nil {
				resp = fallbackResp
				err = nil
				apiUrl = httpUrl
			}
		}

		// Automatic HTTPS upgrade if HTTP returns 400 ("Client sent HTTP to HTTPS server").
		// A 400 is a valid HTTP response — it won't appear as err — so we need a second check.
		if err == nil && resp != nil && resp.StatusCode == http.StatusBadRequest {
			var altUrl string
			if strings.HasPrefix(apiUrl, "http://") {
				altUrl = "https://" + strings.TrimPrefix(apiUrl, "http://")
			} else if strings.HasPrefix(apiUrl, "https://") {
				altUrl = "http://" + strings.TrimPrefix(apiUrl, "https://")
			}
			if altUrl != "" {
				if altResp, altErr := doRequest(altUrl); altErr == nil {
					resp.Body.Close()
					resp = altResp
					err = nil
				}
			}
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to connect to server: %v\n", err)
			if strings.Contains(err.Error(), "connection refused") {
				fmt.Fprintf(os.Stderr, "[!] Is the Burrow server running with --webui or --mcp-api?\n")
			}
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			fmt.Fprintf(os.Stderr, "[!] API error (%d): %s\n", resp.StatusCode, string(body))
			os.Exit(1)
		}

		var result struct {
			Topology string `json:"topology"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to parse response: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(result.Topology)
		fmt.Println()
	},
}

// scanCmd performs network enumeration with service detection.
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan network for hosts, open ports, and services",
	Long: `Scan a subnet to discover hosts, open ports, and running services.

Verbosity levels (-v, -vv, -vvv) control detection depth:
  (default)  Port scan + service name from port number
  -v         Banner grabbing for version detection
  -vv        Additional protocol probes (SMB, RDP negotiation)
  -vvv       Full banners with raw output

Examples:
  burrow scan -s 10.0.0.0/24                    # Quick scan
  burrow scan -s 10.0.0.0/24 -v                 # With banners
  burrow scan -s 10.0.0.0/24 -vv                # Full service detection
  burrow scan -s 10.0.0.0/24 -p 22,445,3389 -v  # Specific ports + banners`,
	Run: func(cmd *cobra.Command, args []string) {
		subnet, _ := cmd.Flags().GetString("subnet")
		portsStr, _ := cmd.Flags().GetString("ports")
		timeoutStr, _ := cmd.Flags().GetString("timeout")
		concurrency, _ := cmd.Flags().GetInt("concurrency")
		verbose, _ := cmd.Flags().GetCount("verbose")

		timeout, err := time.ParseDuration(timeoutStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Invalid timeout %q, using default 2s\n", timeoutStr)
			timeout = 2 * time.Second
		}

		var ports []int
		if portsStr != "" {
			ports = parsePorts(portsStr)
		}

		// Set scan mode based on verbosity
		var scanMode string
		switch {
		case verbose >= 3:
			scanMode = "intensive"
		case verbose >= 2:
			scanMode = "detailed"
		case verbose >= 1:
			scanMode = "standard"
		default:
			scanMode = "quick"
		}

		scanner := discovery.NewScanner(ports, timeout, concurrency)
		scanner.SetVerbosity(verbose)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			<-sigChan
			fmt.Println("\n[*] Scan interrupted.")
			cancel()
		}()

		fmt.Printf("[*] Scanning %s [%s mode]\n", subnet, scanMode)
		fmt.Printf("[*] Timeout: %v, Concurrency: %d\n\n", timeout, concurrency)

		start := time.Now()
		targets, err := scanner.ScanSubnet(ctx, subnet)
		elapsed := time.Since(start)

		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Scan error: %v\n", err)
			os.Exit(1)
		}

		if len(targets) == 0 {
			fmt.Printf("[*] No hosts found. (%.1fs)\n", elapsed.Seconds())
			return
		}

		fmt.Printf("[*] Found %d host(s) in %.1fs:\n\n", len(targets), elapsed.Seconds())

		for _, t := range targets {
			pivotMark := ""
			if t.Pivotable {
				pivotMark = " [PIVOT]"
			}
			fmt.Printf("  %-15s Services:%s\n", t.IP, pivotMark)

			for _, svc := range t.ServiceDetails {
				detail := svc.Name
				if svc.Version != "" {
					detail += " (" + svc.Version + ")"
				}
				if verbose >= 3 && svc.Banner != "" {
					banner := svc.Banner
					if len(banner) > 60 {
						banner = banner[:57] + "..."
					}
					detail += "\n        Banner: " + banner
				} else if verbose >= 1 && svc.Banner != "" && svc.Version == "" {
					banner := svc.Banner
					if len(banner) > 40 {
						banner = banner[:37] + "..."
					}
					detail += " [" + banner + "]"
				}
				fmt.Printf("      %d/tcp  open  %s\n", svc.Port, detail)
			}
		}
		fmt.Println()
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(topologyCmd)

	// Scan flags
	scanCmd.Flags().StringP("subnet", "s", "", "Subnet to scan (CIDR or prefix)")
	scanCmd.Flags().StringP("ports", "p", "", "Comma-separated ports (default: top 20)")
	scanCmd.Flags().String("timeout", "2s", "Per-port timeout")
	scanCmd.Flags().Int("concurrency", 256, "Max concurrent connections")
	scanCmd.Flags().CountP("verbose", "v", "Verbosity level (0-3)")
	scanCmd.MarkFlagRequired("subnet")

	// Topology flags (server query only)
	topologyCmd.Flags().String("api-url", "127.0.0.1:9091", "Burrow server URL")
	topologyCmd.Flags().String("api-token", "", "API authentication token")
	topologyCmd.Flags().Bool("no-tls", false, "Use plain HTTP")
}

// detectLocalSubnet finds the first non-loopback IPv4 subnet.
func detectLocalSubnet() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP.IsLoopback() {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				continue
			}
			return fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
		}
	}
	return ""
}

func parsePorts(s string) []int {
	return discovery.ParsePortRange(s)
}
