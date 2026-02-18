package cmd

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/loudmumble/burrow/internal/tunnel"
	"github.com/spf13/cobra"
)

var reverseCmd = &cobra.Command{
	Use:   "reverse",
	Short: "Create a reverse tunnel",
	Long: `Create a reverse tunnel where the remote side listens and 
forwards connections back to a local service.

Example:
  burrow reverse -l 0.0.0.0:8080 -t 127.0.0.1:3000
  # Remote users connecting to port 8080 reach your local port 3000`,
	Run: func(cmd *cobra.Command, args []string) {
		listen, _ := cmd.Flags().GetString("listen")
		target, _ := cmd.Flags().GetString("target")

		lhost, lport := parseEndpoint(listen)
		thost, tport := parseEndpoint(target)

		t := tunnel.NewReverseTunnel(lhost, lport, thost, tport)

		fmt.Printf("Creating reverse tunnel: %s:%d -> %s:%d\n", lhost, lport, thost, tport)

		if err := t.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Reverse tunnel active on %s:%d\n", lhost, lport)
		fmt.Println("Press Ctrl+C to stop.")

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		t.Stop()
		fmt.Println("\nTunnel closed.")
	},
}

func init() {
	rootCmd.AddCommand(reverseCmd)
	reverseCmd.Flags().StringP("listen", "l", "0.0.0.0:8443", "Remote listen address")
	reverseCmd.Flags().StringP("target", "t", "127.0.0.1:22", "Local target address")
}

func parseEndpointSimple(endpoint string) (string, int) {
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return endpoint, 0
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	return host, port
}
