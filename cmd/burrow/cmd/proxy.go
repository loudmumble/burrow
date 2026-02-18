package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/loudmumble/burrow/internal/proxy"
	"github.com/spf13/cobra"
)

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Start a SOCKS5 proxy server",
	Long: `Start a SOCKS5 proxy server that can be used to route
traffic through the current host.

Example:
  burrow proxy --addr 127.0.0.1 --port 1080
  burrow proxy -a 0.0.0.0 -p 9050 --auth user:pass`,
	Run: func(cmd *cobra.Command, args []string) {
		addr, _ := cmd.Flags().GetString("addr")
		port, _ := cmd.Flags().GetInt("port")
		auth, _ := cmd.Flags().GetString("auth")

		var username, password string
		if auth != "" {
			fmt.Sscanf(auth, "%[^:]:%s", &username, &password)
		}

		p := proxy.NewSOCKS5(addr, port, username, password)

		fmt.Printf("Starting SOCKS5 proxy on %s:%d\n", addr, port)
		if username != "" {
			fmt.Printf("Authentication: %s:****\n", username)
		}

		if err := p.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("SOCKS5 proxy active. Press Ctrl+C to stop.\n")

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		p.Stop()
		fmt.Println("\nProxy stopped.")
	},
}

func init() {
	rootCmd.AddCommand(proxyCmd)
	proxyCmd.Flags().StringP("addr", "a", "127.0.0.1", "Listen address")
	proxyCmd.Flags().IntP("port", "p", 1080, "Listen port")
	proxyCmd.Flags().String("auth", "", "Authentication (username:password)")
}
