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

// tunnelCmd is declared in forward.go — these subcommands extend it.

var tunnelServerCmd = &cobra.Command{
	Use:   "server",
	Short: "Start HTTP tunnel server (runs on target)",
	Long: `Start an HTTP tunnel server that relays TCP connections via HTTP.

Basic mode: XOR encoding, ?cmd= query params, X-Token auth header.
Secure mode (-s): AES-256-GCM, commands in cookies, HTML-wrapped responses,
  always returns 200 OK — no signaturable query strings or status codes.

Example:
  burrow tunnel server -l 0.0.0.0:8080
  burrow tunnel server -l 0.0.0.0:443 -k s3cret -s
  burrow tunnel server -l :8080 --path /api/health -k mykey -s`,
	Example: `  burrow tunnel server -l 0.0.0.0:8080
  burrow tunnel server -l 0.0.0.0:443 -k s3cret -s
  burrow tunnel server -l :8080 --path /api/health -k mykey`,
	Run: func(cmd *cobra.Command, args []string) {
		listen, _ := cmd.Flags().GetString("listen")
		key, _ := cmd.Flags().GetString("key")
		path, _ := cmd.Flags().GetString("path")
		secure, _ := cmd.Flags().GetBool("secure")

		if secure && key == "" {
			fmt.Fprintln(os.Stderr, "[!] Secure mode requires --key (-k)")
			os.Exit(1)
		}

		cfg := &httptunnel.ServerConfig{
			ListenAddr: listen,
			Path:       path,
			Secure:     secure,
		}
		if key != "" {
			cfg.Key = []byte(key)
		}

		srv := httptunnel.NewServer(cfg)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mode := "basic"
		if secure {
			mode = "secure (AES-256-GCM)"
		}
		fmt.Printf("[*] Starting tunnel server on %s [%s]\n", listen, mode)
		if key != "" && !secure {
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

var tunnelClientCmd = &cobra.Command{
	Use:   "client",
	Short: "Start HTTP tunnel client with local SOCKS5 (runs on attacker)",
	Long: `Start an HTTP tunnel client that provides a local SOCKS5 proxy.

All SOCKS5 traffic is tunneled through HTTP to the server, which relays
TCP connections to internal hosts.

Use -s/--secure to enable secure mode (must match server).

Example:
  burrow tunnel client -c http://target:8080/b -l 127.0.0.1:1080
  burrow tunnel client -c https://target:443/app -k s3cret -s
  burrow tunnel client -c http://target:8080/api/health -k mykey -s -l 0.0.0.0:9050`,
	Example: `  burrow tunnel client -c http://target:8080/b -l 127.0.0.1:1080
  burrow tunnel client -c https://target:443/app -k s3cret -s`,
	Run: func(cmd *cobra.Command, args []string) {
		serverURL, _ := cmd.Flags().GetString("connect")
		key, _ := cmd.Flags().GetString("key")
		socksAddr, _ := cmd.Flags().GetString("listen")
		secure, _ := cmd.Flags().GetBool("secure")

		if secure && key == "" {
			fmt.Fprintln(os.Stderr, "[!] Secure mode requires --key (-k)")
			os.Exit(1)
		}

		cfg := &httptunnel.ClientConfig{
			ServerURL: serverURL,
			SocksAddr: socksAddr,
			Secure:    secure,
		}
		if key != "" {
			cfg.Key = []byte(key)
		}

		client := httptunnel.NewClient(cfg)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mode := "basic"
		if secure {
			mode = "secure (AES-256-GCM)"
		}
		fmt.Printf("[*] Starting tunnel client [%s]\n", mode)
		fmt.Printf("[*] SOCKS5 proxy: %s\n", socksAddr)
		fmt.Printf("[*] Tunnel server: %s\n", serverURL)

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
	// tunnelCmd is defined in forward.go — we add server/client subcommands here
	tunnelCmd.AddCommand(tunnelServerCmd)
	tunnelCmd.AddCommand(tunnelClientCmd)

	// Server flags
	tunnelServerCmd.Flags().StringP("listen", "l", "0.0.0.0:8080", "Listen address (host:port)")
	tunnelServerCmd.Flags().StringP("key", "k", "", "Shared encryption/authentication key")
	tunnelServerCmd.Flags().String("path", "/b", "URL path for tunnel endpoint")
	tunnelServerCmd.Flags().BoolP("secure", "s", false, "Enable secure mode (AES-256-GCM, cookie commands, HTML wrapping)")

	// Client flags
	tunnelClientCmd.Flags().StringP("connect", "c", "", "Tunnel server URL (e.g., http://target:8080/b)")
	tunnelClientCmd.Flags().StringP("listen", "l", "127.0.0.1:1080", "Local SOCKS5 listen address")
	tunnelClientCmd.Flags().StringP("key", "k", "", "Shared encryption/authentication key")
	tunnelClientCmd.Flags().BoolP("secure", "s", false, "Enable secure mode (AES-256-GCM, cookie commands, HTML wrapping)")
	tunnelClientCmd.MarkFlagRequired("connect")
}
