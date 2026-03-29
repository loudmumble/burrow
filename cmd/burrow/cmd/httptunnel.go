package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/loudmumble/burrow/internal/httptunnel"
	"github.com/spf13/cobra"
)

var httptunnelCmd = &cobra.Command{
	Use:   "httptunnel",
	Short: "HTTP-based tunnel (reGeorg-style)",
	Long: `HTTP-based tunnel for relaying TCP through HTTP requests.

Solves the "egress blocked" problem: the target has no outbound connectivity,
but the attacker can reach the target's HTTP port.

  Server (on target): accepts HTTP, relays TCP to internal hosts
  Client (on attacker): provides local SOCKS5, encodes traffic as HTTP`,
}

var httptunnelServerCmd = &cobra.Command{
	Use:   "server",
	Short: "Start HTTP tunnel server (runs on target)",
	Long: `Start an HTTP tunnel server that relays TCP connections via HTTP.

The server accepts HTTP POST requests and manages TCP sessions to internal hosts.
A fake HTML page is served on GET / for cover.

Example:
  burrow httptunnel server -l 0.0.0.0:8080
  burrow httptunnel server -l 0.0.0.0:443 -k s3cret
  burrow httptunnel server -l :8080 --path /api/health -k mykey`,
	Example: `  burrow httptunnel server -l 0.0.0.0:8080
  burrow httptunnel server -l 0.0.0.0:443 -k s3cret
  burrow httptunnel server -l :8080 --path /api/health -k mykey`,
	Run: func(cmd *cobra.Command, args []string) {
		listen, _ := cmd.Flags().GetString("listen")
		key, _ := cmd.Flags().GetString("key")
		path, _ := cmd.Flags().GetString("path")

		cfg := &httptunnel.ServerConfig{
			ListenAddr: listen,
			Path:       path,
		}
		if key != "" {
			cfg.Key = []byte(key)
		}

		srv := httptunnel.NewServer(cfg)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		fmt.Printf("[*] Starting HTTP tunnel server on %s\n", listen)
		if key != "" {
			fmt.Printf("[*] Authentication enabled (X-Token required)\n")
		}
		if path != "/b" && path != "" {
			fmt.Printf("[*] Tunnel path: %s\n", path)
		}

		errCh := make(chan error, 1)
		go func() {
			errCh <- srv.Start(ctx)
		}()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		select {
		case err := <-errCh:
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] Error: %v\n", err)
				os.Exit(1)
			}
		case <-sigChan:
			fmt.Println("\n[*] Shutting down...")
			cancel()
		}
	},
}

var httptunnelClientCmd = &cobra.Command{
	Use:   "client",
	Short: "Start HTTP tunnel client with local SOCKS5 (runs on attacker)",
	Long: `Start an HTTP tunnel client that provides a local SOCKS5 proxy.

All SOCKS5 traffic is tunneled through HTTP to the server, which relays
TCP connections to internal hosts.

Example:
  burrow httptunnel client -c http://target:8080/b -l 127.0.0.1:1080
  burrow httptunnel client -c https://target:443/b -k s3cret
  burrow httptunnel client -c http://target:8080/api/health -k mykey -l 0.0.0.0:9050`,
	Example: `  burrow httptunnel client -c http://target:8080/b -l 127.0.0.1:1080
  burrow httptunnel client -c https://target:443/b -k s3cret`,
	Run: func(cmd *cobra.Command, args []string) {
		serverURL, _ := cmd.Flags().GetString("connect")
		key, _ := cmd.Flags().GetString("key")
		socksAddr, _ := cmd.Flags().GetString("listen")

		cfg := &httptunnel.ClientConfig{
			ServerURL: serverURL,
			SocksAddr: socksAddr,
		}
		if key != "" {
			cfg.Key = []byte(key)
		}

		client := httptunnel.NewClient(cfg)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		fmt.Printf("[*] Starting HTTP tunnel client\n")
		fmt.Printf("[*] SOCKS5 proxy: %s\n", socksAddr)
		fmt.Printf("[*] Tunnel server: %s\n", serverURL)
		if key != "" {
			fmt.Printf("[*] Encryption enabled\n")
		}

		errCh := make(chan error, 1)
		go func() {
			errCh <- client.Start(ctx)
		}()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		select {
		case err := <-errCh:
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] Error: %v\n", err)
				os.Exit(1)
			}
		case <-sigChan:
			fmt.Println("\n[*] Shutting down...")
			cancel()
		}
	},
}

func init() {
	rootCmd.AddCommand(httptunnelCmd)
	httptunnelCmd.AddCommand(httptunnelServerCmd)
	httptunnelCmd.AddCommand(httptunnelClientCmd)

	// Server flags
	httptunnelServerCmd.Flags().StringP("listen", "l", "0.0.0.0:8080", "Listen address (host:port)")
	httptunnelServerCmd.Flags().StringP("key", "k", "", "Shared encryption/authentication key")
	httptunnelServerCmd.Flags().String("path", "/b", "URL path for tunnel endpoint")

	// Client flags
	httptunnelClientCmd.Flags().StringP("connect", "c", "", "HTTP tunnel server URL (e.g., http://target:8080/b)")
	httptunnelClientCmd.Flags().StringP("listen", "l", "127.0.0.1:1080", "Local SOCKS5 listen address")
	httptunnelClientCmd.Flags().StringP("key", "k", "", "Shared encryption/authentication key")
	httptunnelClientCmd.MarkFlagRequired("connect")
}
