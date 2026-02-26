package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/loudmumble/burrow/internal/discovery"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Network topology discovery (ping sweep + port scan)",
	Long: `Scan a subnet for reachable hosts and open ports.

Supports CIDR notation and bare /24 prefixes.

Example:
  burrow scan --subnet 10.0.0.0/24
  burrow scan --subnet 192.168.1.0/24 --ports 22,80,443,3389
  burrow scan --subnet 10.0.0 --timeout 3s`,
	Run: func(cmd *cobra.Command, args []string) {
		subnet, _ := cmd.Flags().GetString("subnet")
		portsStr, _ := cmd.Flags().GetString("ports")
		timeoutStr, _ := cmd.Flags().GetString("timeout")
		concurrency, _ := cmd.Flags().GetInt("concurrency")

		timeout, err := time.ParseDuration(timeoutStr)
		if err != nil {
			timeout = 2 * time.Second
		}

		var ports []int
		if portsStr != "" {
			ports = parsePorts(portsStr)
		}

		scanner := discovery.NewScanner(ports, timeout, concurrency)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			<-sigChan
			fmt.Println("\n[*] Scan interrupted.")
			cancel()
		}()

		fmt.Printf("[*] Scanning %s (timeout: %v, concurrency: %d)\n", subnet, timeout, concurrency)
		fmt.Printf("[*] Ports: %v\n\n", scanner.Ports())

		start := time.Now()
		targets, err := scanner.ScanSubnet(ctx, subnet)
		elapsed := time.Since(start)

		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Scan error: %v\n", err)
			os.Exit(1)
		}

		if len(targets) == 0 {
			fmt.Printf("[*] No hosts found. (%.1fs)\n", elapsed.Seconds())
			return
		}

		fmt.Printf("[*] Found %d host(s) in %.1fs:\n\n", len(targets), elapsed.Seconds())

		for _, t := range targets {
			pivotMark := ""
			if t.Pivotable {
				pivotMark = " [PIVOT]"
			}
			fmt.Printf("  %-15s  Ports: %-30s  Services: %s%s\n",
				t.IP,
				formatPorts(t.OpenPorts),
				strings.Join(t.Services, ", "),
				pivotMark)
		}
		fmt.Println()
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringP("subnet", "s", "", "Subnet to scan (CIDR or prefix, e.g. 10.0.0.0/24)")
	scanCmd.Flags().StringP("ports", "p", "", "Comma-separated ports (default: top 20)")
	scanCmd.Flags().String("timeout", "2s", "Per-port timeout")
	scanCmd.Flags().Int("concurrency", 256, "Max concurrent connections")
	scanCmd.MarkFlagRequired("subnet")
}

func parsePorts(s string) []int {
	return discovery.ParsePortRange(s)
}

func formatPorts(ports []int) string {
	strs := make([]string, len(ports))
	for i, p := range ports {
		strs[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(strs, ",")
}
