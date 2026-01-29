package cmd

import "github.com/spf13/cobra"

var (
	requestID string
	position  string
	mode      string
	payload   string
	threads   int
	delay     int
)

var intruderCmd = &cobra.Command{
	Use:   "intruder",
	Short: "Payload-based fuzzing engine",
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: intruder engine
	},
}

func init() {
	intruderCmd.Flags().StringVar(&requestID, "request", "", "Request ID from history")
	intruderCmd.Flags().StringVar(&position, "position", "", "Injection point (param:id)")
	intruderCmd.Flags().StringVar(&mode, "mode", "sniper", "Attack mode")
	intruderCmd.Flags().StringVar(&payload, "payload", "", "Payload wordlist")
	intruderCmd.Flags().IntVar(&threads, "threads", 5, "Concurrent threads")
	intruderCmd.Flags().IntVar(&delay, "delay", 0, "Delay between requests (ms)")
}
