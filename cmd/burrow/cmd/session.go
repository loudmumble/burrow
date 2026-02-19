package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

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
  burrow session list --server 127.0.0.1:11601`,
	Run: func(cmd *cobra.Command, _ []string) {
		// TODO: Connect to proxy server API (or local Manager) and list sessions.
		// For now, print placeholder.
		fmt.Println("[*] Active sessions:")
		fmt.Println("    (no sessions — connect to a running proxy server to list agents)")
		fmt.Println()
		fmt.Println("    Hint: start a server with 'burrow server' and connect agents with 'burrow agent'")
	},
}

var sessionInfoCmd = &cobra.Command{
	Use:   "info [session-id]",
	Short: "Show details for an agent session",
	Long: `Display detailed information about a connected agent session including
hostname, OS, IP addresses, active tunnels, and routes.

Example:
  burrow session info abc123`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		sessionID := args[0]
		// TODO: Query proxy server API for session details.
		fmt.Printf("[*] Session info for: %s\n", sessionID)
		fmt.Println("    (not yet implemented — requires connection to proxy server)")
	},
}

var sessionUseCmd = &cobra.Command{
	Use:   "use [session-id]",
	Short: "Select a session for interactive commands",
	Long: `Select an agent session for interactive tunnel and route management.

This will be the basis for an interactive shell in a future release.

Example:
  burrow session use abc123`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		sessionID := args[0]
		// TODO: Set active session context and enter interactive mode.
		fmt.Printf("[*] Selected session: %s\n", sessionID)
		fmt.Println("    (interactive shell not yet implemented)")
	},
}

func init() {
	rootCmd.AddCommand(sessionCmd)
	sessionCmd.AddCommand(sessionListCmd)
	sessionCmd.AddCommand(sessionInfoCmd)
	sessionCmd.AddCommand(sessionUseCmd)

	sessionListCmd.Flags().String("server", "127.0.0.1:11601", "Proxy server address to query")
	sessionInfoCmd.Flags().String("server", "127.0.0.1:11601", "Proxy server address to query")
}
