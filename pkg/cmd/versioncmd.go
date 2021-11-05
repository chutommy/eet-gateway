package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of the EET Gateway",
	Long: `Version command prints out the current version of the EET Gateway and
the OS/architecture of the binary build.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		s := fmt.Sprintf("EET Gateway v%s [%s/%s] (%s)", eetgVersion, runtime.GOOS, runtime.GOARCH, eetgBuildTime)
		fmt.Println(s)
	},
}
