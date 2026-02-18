package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/loudmumble/burrow/internal/pivot"
	"github.com/spf13/cobra"
)

var pivotCmd = &cobra.Command{
	Use:   "pivot <hop1> <hop2> [hop3...]",
	Short: "Create a multi-hop pivot chain",
	Long: `Create a multi-hop pivot chain through multiple hosts.

Each hop is specified as host:port. Traffic is tunneled through
each hop in sequence.

Example:
  burrow pivot 10.0.0.1:22 10.0.0.2:22 10.0.0.3:443
  burrow pivot --user admin --key ~/.ssh/id_rsa 192.168.1.1:22 192.168.2.1:22`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		user, _ := cmd.Flags().GetString("user")
		keyPath, _ := cmd.Flags().GetString("key")
		localPort, _ := cmd.Flags().GetInt("local-port")

		hops := make([]pivot.Hop, len(args))
		for i, hop := range args {
			h, p := parseEndpoint(hop)
			hops[i] = pivot.Hop{
				Host: h,
				Port: p,
				User: user,
				Key:  keyPath,
			}
		}

		chain := pivot.NewChain(hops)

		fmt.Printf("Creating pivot chain through %d hops:\n", len(hops))
		for i, hop := range hops {
			fmt.Printf("  %d. %s:%d\n", i+1, hop.Host, hop.Port)
		}

		if err := chain.Establish(); err != nil {
			fmt.Fprintf(os.Stderr, "Error establishing chain: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("\nPivot chain active!\n")
		fmt.Printf("Local endpoint: 127.0.0.1:%d\n", localPort)
		fmt.Printf("Final target reachable via: %s\n", chain.Route())

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		fmt.Println("\nPress Ctrl+C to stop.")
		<-sigChan

		chain.Close()
		fmt.Println("\nPivot chain closed.")
	},
}

func init() {
	rootCmd.AddCommand(pivotCmd)
	pivotCmd.Flags().StringP("user", "u", "", "SSH username for hops")
	pivotCmd.Flags().StringP("key", "k", "", "SSH private key path")
	pivotCmd.Flags().IntP("local-port", "l", 1080, "Local SOCKS port")
}
