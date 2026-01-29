package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	verbose bool
	noSave  bool
	project string
)

var rootCmd = &cobra.Command{
	Use:   "mobproxy",
	Short: "Mobile Pentesting Framework (CLI)",
	Long: `mobproxy — Mobile Pentesting Framework (CLI)

A BurpSuite-like MITM, scanner, and intruder framework
designed for Android (Termux) and Go-based environments.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().BoolVar(&noSave, "no-save", false, "Run in memory-only mode")
	rootCmd.PersistentFlags().StringVar(&project, "project", "", "Specify project directory")

	rootCmd.AddCommand(
		startCmd,
		proxyCmd,
		scanCmd,
		intruderCmd,
		cleanupCmd,
		certCmd,
		versionCmd,
	)
}
