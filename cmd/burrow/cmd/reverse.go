package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/loudmumble/burrow/internal/tunnel"
	"github.com/spf13/cobra"
)

var tunnelReverseCmd = &cobra.Command{
	Use:   "reverse",
	Short: "Reverse tunnel with keepalive and auto-reconnect",
	Long: `Create a reverse tunnel that connects outbound to an agent/controller
with keepalive heartbeats and exponential backoff reconnection.

Example:
  burrow tunnel reverse --agent-addr 10.0.0.1:8443
  burrow tunnel reverse --agent-addr 10.0.0.1:8443 --local-target 127.0.0.1:22`,
	Run: func(cmd *cobra.Command, args []string) {
		agentAddr, _ := cmd.Flags().GetString("agent-addr")
		localTarget, _ := cmd.Flags().GetString("local-target")
		maxRetries, _ := cmd.Flags().GetInt("max-retries")

		cfg := tunnel.DefaultReverseConfig()
		cfg.AgentAddr = agentAddr
		cfg.LocalTarget = localTarget
		cfg.MaxRetries = maxRetries

		rt := tunnel.NewReverseTunnelWithConfig(cfg)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		fmt.Printf("[*] Reverse tunnel: %s -> %s\n", agentAddr, localTarget)
		fmt.Printf("[*] Max retries: %d, Keepalive: %v\n", maxRetries, cfg.KeepaliveInterval)

		if err := rt.StartWithContext(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[*] Reverse tunnel active on %s. Press Ctrl+C to stop.\n", rt.Addr())

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		fmt.Println("\n[*] Shutting down...")
		cancel()
		rt.Stop()
	},
}

func init() {
	tunnelCmd.AddCommand(tunnelReverseCmd)

	tunnelReverseCmd.Flags().String("agent-addr", "0.0.0.0:8443", "Agent/controller address to connect to")
	tunnelReverseCmd.Flags().String("local-target", "127.0.0.1:22", "Local target to forward to")
	tunnelReverseCmd.Flags().Int("max-retries", 10, "Maximum reconnection attempts")
}
