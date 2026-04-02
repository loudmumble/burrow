package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/loudmumble/burrow/internal/relay"
	"github.com/spf13/cobra"
)

var relayCmd = &cobra.Command{
	Use:   "relay <source-spec> <dest-spec>",
	Short: "Bidirectional relay between two endpoints (socat-style)",
	Long: `Relay connects two endpoints and copies data bidirectionally between them.

Address spec types:
  tcp-listen:<port>             TCP listener on all interfaces
  tcp-listen:<host>:<port>      TCP listener on specific host
  tcp-connect:<host>:<port>     TCP client connection
  udp-listen:<port>             UDP listener
  udp-connect:<host>:<port>     UDP client
  unix-listen:<path>            Unix domain socket listener
  unix-connect:<path>           Unix domain socket client
  exec:<command>                Spawn process, relay stdin/stdout
  stdio                         Relay from/to stdin/stdout

Examples:
  burrow relay tcp-listen:8080 tcp-connect:10.0.0.5:80
  burrow relay unix-listen:/tmp/relay.sock tcp-connect:db.internal:5432
  burrow relay stdio tcp-connect:example.com:22
  burrow relay tcp-listen:2222 exec:"ssh user@target"`,
	Args: cobra.ExactArgs(2),
	Run:  runRelay,
}

func init() {
	rootCmd.AddCommand(relayCmd)
}

func runRelay(cmd *cobra.Command, args []string) {
	srcSpec := args[0]
	dstSpec := args[1]

	srcEndpoint, err := relay.ParseSpec(srcSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Invalid source spec: %v\n", err)
		os.Exit(1)
	}

	dstEndpoint, err := relay.ParseSpec(dstSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Invalid dest spec: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Fprintln(os.Stderr, "\n[*] Shutting down relay...")
		cancel()
	}()

	fmt.Fprintf(os.Stderr, "[*] Relay: %s <-> %s\n", srcSpec, dstSpec)

	srcConn, err := srcEndpoint.Open(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Source open failed: %v\n", err)
		os.Exit(1)
	}
	defer srcConn.Close()

	dstConn, err := dstEndpoint.Open(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Dest open failed: %v\n", err)
		os.Exit(1)
	}
	defer dstConn.Close()

	fmt.Fprintf(os.Stderr, "[*] Connected. Relaying...\n")

	if err := relay.Relay(ctx, srcConn, dstConn); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Relay error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "[*] Relay finished.\n")
}
