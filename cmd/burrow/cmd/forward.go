package cmd

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/loudmumble/burrow/internal/tunnel"
	"github.com/spf13/cobra"
)

var forwardCmd = &cobra.Command{
	Use:   "forward",
	Short: "Create a local port forward tunnel",
	Long: `Create a local port forward that listens locally and forwards
all traffic to a remote target.

Example:
  burrow forward -l 127.0.0.1:8080 -r 10.0.0.5:80
  burrow forward -l 0.0.0.0:3389 -r 192.168.1.100:3389`,
	Run: func(cmd *cobra.Command, args []string) {
		listen, _ := cmd.Flags().GetString("listen")
		remote, _ := cmd.Flags().GetString("remote")
		protocol, _ := cmd.Flags().GetString("protocol")

		lhost, lport := parseEndpoint(listen)
		rhost, rport := parseEndpoint(remote)

		t := tunnel.NewTunnel(lhost, lport, rhost, rport, protocol)

		fmt.Printf("Creating tunnel: %s:%d -> %s:%d [%s]\n", lhost, lport, rhost, rport, protocol)

		if err := t.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Tunnel active. Press Ctrl+C to stop.\n")

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		t.Stop()
		fmt.Println("\nTunnel closed.")
	},
}

func init() {
	rootCmd.AddCommand(forwardCmd)
	forwardCmd.Flags().StringP("listen", "l", "127.0.0.1:8443", "Local listen address (host:port)")
	forwardCmd.Flags().StringP("remote", "r", "", "Remote target address (host:port)")
	forwardCmd.Flags().String("protocol", "tcp", "Protocol (tcp or udp)")
	forwardCmd.MarkFlagRequired("remote")
}

func parseEndpoint(endpoint string) (string, int) {
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid endpoint %s: %v\n", endpoint, err)
		os.Exit(1)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid port %s: %v\n", portStr, err)
		os.Exit(1)
	}
	return host, port
}
