package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "3.0.0"

// Build info variables — set via ldflags at build time:
//   go build -ldflags "-X cmd.commit=abc123 -X cmd.buildDate=2025-01-01"
var (
	commit    = "dev"
	buildDate = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "burrow",
	Short: "Network pivoting and tunneling tool",
	Long: `Burrow — Network pivoting, tunneling, and agent management.

Part of the Agent-HQ Attack Suite. Provides:
  - SOCKS5 proxy server (RFC 1928) with session routing
  - Local/remote TCP port forwarding
  - Reverse tunnel with keepalive and auto-reconnect
  - Multi-hop pivot chain orchestration
  - Network topology discovery (ping sweep + port scan)
  - Agent mode with reverse-connect to proxy server
  - TUN interface for transparent network pivoting
  - Multiple transports: Raw TCP/TLS, WebSocket, DNS tunnel, ICMP tunnel
  - Socat-style relay for arbitrary endpoint bridging
  - WebUI dashboard for session management`,
	Version: version,
}

func init() {
	rootCmd.SetVersionTemplate(fmt.Sprintf("Burrow v%s (commit: %s, built: %s)\n", version, commit, buildDate))
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
