package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/loudmumble/burrow/internal/pivot"
	"github.com/spf13/cobra"
)

var pivotCmd = &cobra.Command{
	Use:   "pivot",
	Short: "Multi-hop pivot chain setup",
	Long: `Create a multi-hop pivot chain through one or more hosts.

Connects through each hop sequentially and optionally opens a local
listener for forwarding traffic through the chain.

Example:
  burrow pivot --target 10.0.0.1 --port 8443
  burrow pivot --target 10.0.0.1 --port 8443 --hop 10.0.0.2:22 --hop 10.0.0.3:443
  burrow pivot --target 10.0.0.1 --port 8443 --local-port 1080`,
	Run: func(cmd *cobra.Command, args []string) {
		target, _ := cmd.Flags().GetString("target")
		port, _ := cmd.Flags().GetInt("port")
		hopsFlag, _ := cmd.Flags().GetStringSlice("hop")
		localPort, _ := cmd.Flags().GetInt("local-port")

		var hops []pivot.Hop

		for _, hopStr := range hopsFlag {
			h, p := parseEndpoint(hopStr)
			hops = append(hops, pivot.Hop{Host: h, Port: p})
		}

		hops = append(hops, pivot.Hop{Host: target, Port: port})

		chain := pivot.NewChain(hops)

		fmt.Printf("[*] Pivot chain through %d hop(s):\n", len(hops))
		for i, hop := range hops {
			fmt.Printf("    %d. %s\n", i+1, hop.Endpoint())
		}

		if err := chain.Establish(); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Chain establishment failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[*] Chain active! Route: %s\n", chain.Route())
		fmt.Printf("[*] Total latency: %v\n", chain.Latency())

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if localPort > 0 {
			listenAddr := fmt.Sprintf("127.0.0.1:%d", localPort)
			if err := chain.StartListener(ctx, listenAddr); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Listener error: %v\n", err)
				chain.Close()
				os.Exit(1)
			}
			fmt.Printf("[*] Local listener on %s\n", listenAddr)
		}

		fmt.Println("[*] Press Ctrl+C to stop.")

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		fmt.Println("\n[*] Closing pivot chain...")
		cancel()
		chain.Close()
		fmt.Println("[*] Done.")
	},
}

func init() {
	rootCmd.AddCommand(pivotCmd)
	pivotCmd.Flags().String("target", "", "Final target host")
	pivotCmd.Flags().IntP("port", "p", 8443, "Final target port")
	pivotCmd.Flags().StringSlice("hop", nil, "Intermediate hops (host:port), can be repeated")
	pivotCmd.Flags().Int("local-port", 0, "Open local listener on this port (0 = disabled)")
	pivotCmd.MarkFlagRequired("target")
}
