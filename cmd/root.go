package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	verbose bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "subtake",
	Short: "A subdomain takeover detection tool",
	Long: `SubTake is a CLI tool for detecting subdomain takeover vulnerabilities.
It scans subdomains against known hosting service fingerprints to identify
potential takeover opportunities.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			os.Exit(1)
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output for debugging")
}
