package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "1.0.0"

var rootCmd = &cobra.Command{
	Use:   "burrow",
	Short: "Network pivoting and tunneling tool",
	Long: `Burrow — One-command network pivoting and tunneling.

Part of the Agent-HQ Attack Suite. Provides:
  - SOCKS5 proxy server (RFC 1928)
  - Local/remote TCP port forwarding
  - Reverse tunnel with keepalive and auto-reconnect
  - Multi-hop pivot chain orchestration
  - Network topology discovery (ping sweep + port scan)`,
	Version: version,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
