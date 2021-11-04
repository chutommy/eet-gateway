package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "eetg",
	Short: "EET Gateway is the entry point for communication with the Czech EET system",
	Long: `The EET Gateway is an open-source software which simplifies the communication
with the Czech EET system (Electronic Registration of Sales).`,
	Args: cobra.NoArgs,
}

// Execute executes the root command.
func Execute() {
	rootCmd.AddCommand(versionCmd, initCmd, serveCmd)

	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}
