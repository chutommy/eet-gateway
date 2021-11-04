package cmd

import (
	"github.com/spf13/cobra"
)

func initEETGCmd() {
	eetgCmd.CompletionOptions.DisableDefaultCmd = true
	eetgCmd.CompletionOptions.DisableNoDescFlag = true
	eetgCmd.CompletionOptions.DisableDescriptions = true
}

var eetgCmd = &cobra.Command{
	Use:   "eetg",
	Short: "EET Gateway is the entry point for communication with the Czech EET system",
	Long: `The EET Gateway is an open-source software which simplifies the communication
with the Czech EET system (Electronic Registration of Sales).`,
	Args: cobra.NoArgs,
}
