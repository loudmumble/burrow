package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/loudmumble/burrow/internal/proxy"
	"github.com/spf13/cobra"
)

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Proxy server commands",
}

var proxySocks5Cmd = &cobra.Command{
	Use:   "socks5",
	Short: "Start a SOCKS5 proxy server (RFC 1928)",
	Long: `Start a SOCKS5 proxy server for routing traffic through the current host.

Example:
  burrow proxy socks5 --listen 127.0.0.1:1080
  burrow proxy socks5 --listen 0.0.0.0:9050 --auth user:pass`,
	Run: func(cmd *cobra.Command, args []string) {
		listen, _ := cmd.Flags().GetString("listen")
		auth, _ := cmd.Flags().GetString("auth")

		host, port := parseEndpoint(listen)

		var username, password string
		if auth != "" {
			parts := strings.SplitN(auth, ":", 2)
			username = parts[0]
			if len(parts) > 1 {
				password = parts[1]
			}
		}

		p := proxy.NewSOCKS5(host, port, username, password)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		fmt.Printf("[*] Starting SOCKS5 proxy on %s\n", listen)
		if username != "" {
			fmt.Printf("[*] Authentication: %s:****\n", username)
		}

		errCh := make(chan error, 1)
		go func() {
			errCh <- p.StartWithContext(ctx)
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
			p.Stop()
		}

		active, total, bIn, bOut := p.Stats()
		fmt.Printf("[*] Stats: %d active, %d total, %d bytes in, %d bytes out\n", active, total, bIn, bOut)
	},
}

var proxyHTTPCmd = &cobra.Command{
	Use:   "http",
	Short: "Start an HTTP forward proxy server with CONNECT support",
	Long: `Start an HTTP forward proxy server for routing traffic through the current host.
Supports both HTTP CONNECT tunneling (HTTPS) and regular HTTP forwarding.

Example:
  burrow proxy http --listen 127.0.0.1:8080
  burrow proxy http --listen 0.0.0.0:8080 --auth user:pass`,
	Run: func(cmd *cobra.Command, args []string) {
		listen, _ := cmd.Flags().GetString("listen")
		auth, _ := cmd.Flags().GetString("auth")

		host, port := parseEndpoint(listen)

		var username, password string
		if auth != "" {
			parts := strings.SplitN(auth, ":", 2)
			username = parts[0]
			if len(parts) > 1 {
				password = parts[1]
			}
		}

		p := proxy.NewHTTPProxy(host, port, username, password)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		fmt.Printf("[*] Starting HTTP proxy on %s\n", listen)
		if username != "" {
			fmt.Printf("[*] Authentication: %s:****\n", username)
		}

		errCh := make(chan error, 1)
		go func() {
			errCh <- p.StartWithContext(ctx)
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
			p.Stop()
		}

		active, total, bIn, bOut := p.Stats()
		fmt.Printf("[*] Stats: %d active, %d total, %d bytes in, %d bytes out\n", active, total, bIn, bOut)
	},
}

func init() {
	rootCmd.AddCommand(proxyCmd)
	proxyCmd.AddCommand(proxySocks5Cmd)
	proxyCmd.AddCommand(proxyHTTPCmd)

	proxySocks5Cmd.Flags().StringP("listen", "l", "127.0.0.1:1080", "Listen address (host:port)")
	proxySocks5Cmd.Flags().String("auth", "", "Authentication (username:password)")

	proxyHTTPCmd.Flags().StringP("listen", "l", "127.0.0.1:8080", "Listen address (host:port)")
	proxyHTTPCmd.Flags().String("auth", "", "Authentication (username:password)")
}
