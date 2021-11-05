package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	eetgVersion   string
	eetgBuildTime string
	eetgOS        string
	eetgArch      string
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of the EET Gateway",
	Long: `Version command prints out the current version of the EET Gateway and
the OS/architecture of the binary build.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		s := fmt.Sprintf("EET Gateway v%s [%s/%s] (%s)", eetgVersion, eetgOS, eetgArch, eetgBuildTime)
		fmt.Println(s)
	},
}
