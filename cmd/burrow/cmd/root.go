package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version = "1.0.0"
)

var rootCmd = &cobra.Command{
	Use:   "burrow",
	Short: "One-command network pivoting and tunneling",
	Long: `Burrow is a network tunneling and pivoting tool.

Provides:
  - Local port forwarding (forward traffic to remote target)
  - Reverse port forwarding (expose local service remotely)
  - SOCKS5 proxy server
  - Multi-hop pivot chains
  - Network discovery for pivot targets`,
	Version: version,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
