package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/loudmumble/burrow/internal/tunnel"
	"github.com/spf13/cobra"
)

var tunnelCmd = &cobra.Command{
	Use:   "tunnel",
	Short: "TCP port forwarding tunnels",
}

var tunnelLocalCmd = &cobra.Command{
	Use:   "local",
	Short: "Local port forward (listen locally, forward to remote)",
	Long: `Listen on a local address and forward all TCP traffic to a remote target.

Example:
  burrow tunnel local --listen 127.0.0.1:8080 --remote 10.0.0.5:80`,
	Example: `  burrow tunnel local -l 127.0.0.1:8080 -r 10.0.0.5:80
  burrow tunnel local -l 0.0.0.0:3389 -r 10.0.0.5:3389`,
	Run: func(cmd *cobra.Command, args []string) {
		listen, _ := cmd.Flags().GetString("listen")
		remote, _ := cmd.Flags().GetString("remote")

		t := tunnel.NewLocalForward(listen, remote)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		fmt.Printf("[*] Local forward: %s -> %s\n", listen, remote)

		if err := t.StartWithContext(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[*] Tunnel active on %s. Press Ctrl+C to stop.\n", t.Addr())

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		fmt.Println("\n[*] Shutting down...")
		cancel()
		t.Stop()

		bIn, bOut := t.BytesTransferred()
		fmt.Printf("[*] Bytes transferred: %d in, %d out\n", bIn, bOut)
	},
}

var tunnelRemoteCmd = &cobra.Command{
	Use:   "remote",
	Short: "Remote port forward (listen on remote, forward to local target)",
	Long: `Listen on a given address and forward all TCP traffic to a target.

Example:
  burrow tunnel remote --listen 0.0.0.0:9090 --remote 192.168.1.10:22`,
	Example: `  burrow tunnel remote -l 0.0.0.0:9090 -r 192.168.1.10:22`,
	Run: func(cmd *cobra.Command, args []string) {
		listen, _ := cmd.Flags().GetString("listen")
		remote, _ := cmd.Flags().GetString("remote")

		t := tunnel.NewRemoteForward(listen, remote)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		fmt.Printf("[*] Remote forward: %s -> %s\n", listen, remote)

		if err := t.StartWithContext(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[*] Tunnel active on %s. Press Ctrl+C to stop.\n", t.Addr())

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		fmt.Println("\n[*] Shutting down...")
		cancel()
		t.Stop()

		bIn, bOut := t.BytesTransferred()
		fmt.Printf("[*] Bytes transferred: %d in, %d out\n", bIn, bOut)
	},
}

func init() {
	rootCmd.AddCommand(tunnelCmd)
	tunnelCmd.AddCommand(tunnelLocalCmd)
	tunnelCmd.AddCommand(tunnelRemoteCmd)

	tunnelLocalCmd.Flags().StringP("listen", "l", "127.0.0.1:8080", "Local listen address (host:port)")
	tunnelLocalCmd.Flags().StringP("remote", "r", "", "Remote target address (host:port)")
	tunnelLocalCmd.MarkFlagRequired("remote")

	tunnelRemoteCmd.Flags().StringP("listen", "l", "0.0.0.0:9090", "Listen address (host:port)")
	tunnelRemoteCmd.Flags().StringP("remote", "r", "", "Target address (host:port)")
	tunnelRemoteCmd.MarkFlagRequired("remote")
}

func parseEndpoint(endpoint string) (string, int) {
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Invalid endpoint %s: %v\n", endpoint, err)
		os.Exit(1)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Invalid port %s: %v\n", portStr, err)
		os.Exit(1)
	}
	return host, port
}
