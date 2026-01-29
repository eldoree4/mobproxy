package cmd

import "github.com/spf13/cobra"

var (
	profile     string
	proxyPort   int
	crawlDepth  int
	rateLimit   string
	noActive    bool
)

var startCmd = &cobra.Command{
	Use:   "start <target_url>",
	Short: "Start guided pentesting workflow (recommended)",
	Long: `Automatically runs a safe, structured pentesting flow:
- Create project
- Define scope
- Start proxy
- Passive collection
- Fingerprinting
- Light crawling
- Passive scan`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]

		// TODO: panggil orchestrator kamu di sini
		_ = target
	},
}

func init() {
	startCmd.Flags().StringVar(&profile, "profile", "safe", "Scanning preset (safe|balanced|deep)")
	startCmd.Flags().IntVar(&proxyPort, "proxy-port", 8080, "Proxy listen port")
	startCmd.Flags().IntVar(&crawlDepth, "crawl-depth", 2, "Crawler depth")
	startCmd.Flags().StringVar(&rateLimit, "rate-limit", "3r/s", "Request rate limit")
	startCmd.Flags().BoolVar(&noActive, "no-active", false, "Disable active scanning")
}
