package cmd

import (
	"fmt"
	"strings"

	"github.com/loudmumble/burrow/internal/discovery"
	"github.com/spf13/cobra"
)

var discoverCmd = &cobra.Command{
	Use:   "discover <network>",
	Short: "Discover pivot targets on a network",
	Long: `Scan a network for potential pivot targets.

NETWORK is specified as a prefix (e.g., 192.168.1 for /24).

Example:
  burrow discover 192.168.1
  burrow discover 10.0.0 --ports 22,443,3389,8080`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		network := args[0]
		portsStr, _ := cmd.Flags().GetString("ports")

		ports := parsePorts(portsStr)

		fmt.Printf("Scanning %s.0/24 on ports %v...\n\n", network, ports)

		d := discovery.New(network, ports)
		targets := d.Scan()

		if len(targets) == 0 {
			fmt.Println("No pivot targets found.")
			return
		}

		fmt.Printf("Found %d pivot target(s):\n\n", len(targets))

		for _, t := range targets {
			fmt.Printf("  %s\n", t.IP)
			fmt.Printf("    Open ports: %v\n", t.OpenPorts)
			fmt.Printf("    Services:   %s\n", strings.Join(t.Services, ", "))
			fmt.Printf("    Pivotable:  %v\n\n", t.Pivotable)
		}
	},
}

func init() {
	rootCmd.AddCommand(discoverCmd)
	discoverCmd.Flags().StringP("ports", "p", "22,80,443,3389,8080", "Comma-separated ports to scan")
}

func parsePorts(s string) []int {
	parts := strings.Split(s, ",")
	ports := make([]int, 0, len(parts))
	for _, p := range parts {
		var port int
		fmt.Sscanf(strings.TrimSpace(p), "%d", &port)
		if port > 0 {
			ports = append(ports, port)
		}
	}
	return ports
}
