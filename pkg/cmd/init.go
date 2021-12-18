package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	configFile = "eetgateway.json"
)

const (
	dirFlag = "dir"
)

func initInitCmd() {
	configDir, err := osConfigDir()
	if err != nil {
		panic(err)
	}

	initCmd.Flags().StringP(dirFlag, "d", configDir, "directory to generate config file")
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate a default config file",
	Args:  cobra.NoArgs,
	RunE:  initCmdRunE,
}

func initCmdRunE(cmd *cobra.Command, _ []string) error {
	dir, err := cmd.Flags().GetString(dirFlag)
	if err != nil {
		return fmt.Errorf("retrieve 'path' flag: %w", err)
	}

	err = os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("make directory %s: %w", dir, err)
	}

	// write file
	setDefaultConfig()
	path := filepath.Join(dir, configFile)
	err = viper.WriteConfigAs(path)
	if err != nil {
		return fmt.Errorf("write config as `%s`: %w", path, err)
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("retrieve absolute representation of the path to '%s': %w", path, err)
	}

	fmt.Printf("The config file was successfully generated: %s\n", absPath)

	return nil
}
