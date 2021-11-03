package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	configFile = "eetg.json"

	dirFlagName = "dir"
)

func init() {
	configDir, err := osConfigDir()
	if err != nil {
		panic(err)
	}

	initCmd.Flags().StringP(dirFlagName, "d", configDir, "location to generate config file")
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate the default config file",
	Args:  cobra.NoArgs,
	RunE:  initCmdRunE,
}

func initCmdRunE(cmd *cobra.Command, _ []string) error {
	dir, err := cmd.Flags().GetString(dirFlagName)
	if err != nil {
		return fmt.Errorf("retrieve 'path' flag: %w", err)
	}

	// err = os.MkdirAll(dir, os.ModePerm)
	// if err != nil {
	// 	return fmt.Errorf("make directory %s: %w", dir, err)
	// }

	// write file
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

func osConfigDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("retrieve user's home directory: %w", err)
	}

	var configDir string
	switch runtime.GOOS {
	case "linux":
		configDir = filepath.Join(homeDir, ".config", "eetgateway")
	case "darwin":
		configDir = filepath.Join(homeDir, "Library", "Preferences", "eetgateway")
	case "windows":
		configDir = filepath.Join(homeDir, "AppData", "Local", "EETGateway")
	}
	return configDir, nil
}
