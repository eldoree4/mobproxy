package cmd

import "github.com/spf13/cobra"

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Vulnerability scanner",
}

var scanPassiveCmd = &cobra.Command{
	Use:   "passive",
	Short: "Run non-intrusive checks",
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: passive scan engine
	},
}

var scanActiveCmd = &cobra.Command{
	Use:   "active",
	Short: "Run controlled active tests",
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: active scan engine
	},
}

func init() {
	scanCmd.AddCommand(scanPassiveCmd, scanActiveCmd)
}
