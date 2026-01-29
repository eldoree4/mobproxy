package cmd

import "github.com/spf13/cobra"

var cleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Remove local workspace artifacts",
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: workspace cleanup (AMAN)
	},
}
