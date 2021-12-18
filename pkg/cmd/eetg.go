package cmd

import (
	"github.com/spf13/cobra"
)

func initEETGCmd() {
	eetgCmd.CompletionOptions.DisableDefaultCmd = true
	eetgCmd.CompletionOptions.DisableNoDescFlag = true
	eetgCmd.CompletionOptions.DisableDescriptions = true
	eetgCmd.SetHelpCommand(&cobra.Command{Hidden: true})
}

var eetgCmd = &cobra.Command{
	Use:   "eetg",
	Short: "EET Gateway - the RESTful API client of the Czech EET system",
	Args:  cobra.NoArgs,
}
