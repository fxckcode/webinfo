/*
Copyright © 2025 fxckcode
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/fxckcode/webinfo/cmd/internal/analyzer"
)

// rootCmd represents the main command of the application.
// It acts as the entry point when no subcommands are provided.
var rootCmd = &cobra.Command{
	Use:   "webinfo [url]",
	Short: "A powerful CLI to analyze websites",
	Long: `Webinfo is an all-in-one command-line tool that analyzes a website and displays:
- HTTP status, headers, and response time
- SSL/TLS certificate information
- Technologies used by the website (powered by Wappalyzer)
- DNS records (A, AAAA, MX, NS, TXT, CNAME)
- WHOIS domain registration details

Usage example:
  webinfo https://example.com`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("❌ You must provide a URL as an argument")
			fmt.Println("Usage: webinfo https://example.com")
			return
		}

		url := args[0]
		fmt.Println("🔎 Fetching information for URL:", url)

		analyzer.CheckHTTP(url)
		analyzer.CheckSSL(url)
		analyzer.CheckTechnologies(url)
		analyzer.CheckDNS(url)
		analyzer.CheckWHOIS(url)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main().
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

// init initializes flags and configuration for the root command.
func init() {
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle (reserved for future use)")
}
