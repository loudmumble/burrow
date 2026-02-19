package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "2.0.0"

var rootCmd = &cobra.Command{
	Use:   "burrow",
	Short: "Network pivoting and tunneling tool",
	Long: `Burrow — Network pivoting, tunneling, and agent management.

Part of the Agent-HQ Attack Suite. Provides:
  - SOCKS5 proxy server (RFC 1928)
  - Local/remote TCP port forwarding
  - Reverse tunnel with keepalive and auto-reconnect
  - Multi-hop pivot chain orchestration
  - Network topology discovery (ping sweep + port scan)
  - Agent mode with reverse-connect to proxy server
  - TUN interface for transparent network pivoting
  - WebUI dashboard for session management
  - WebSocket transport for firewall evasion`,
	Version: version,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
