package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chutommy/eetgateway/pkg/server"
	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	configPathFlag = "config"
)

func initServeCmd() {
	configDir, err := osConfigDir()
	if err != nil {
		panic(err)
	}

	configPath := filepath.Join(configDir, configFile)
	serveCmd.Flags().StringP(configPathFlag, "c", configPath, "path to config file")
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Initialize the EET Gateway API server",
	Args:  cobra.NoArgs,
	RunE:  serveCmdRunE,
}

func serveCmdRunE(cmd *cobra.Command, _ []string) error {
	configPath, err := cmd.Flags().GetString(configPathFlag)
	if err != nil {
		return fmt.Errorf("retrieve 'path' flag: %w", err)
	}

	// configuration
	setDefaultConfig()
	loadConfigFromENV()
	err = loadConfigFromFile(configPath)
	if err != nil {
		return fmt.Errorf("load config from file: %w", err)
	}

	setupLogger()
	log.Info().
		Str("entity", "Config Service").
		Str("action", "loading configuration").
		Str("from", "environment variables").
		Send()
	log.Info().
		Str("entity", "Config Service").
		Str("action", "loading configuration").
		Str("status", "configuration set").
		Str("path", configPath).
		Send()
	log.Info().
		Str("entity", "EET Gateway").
		Str("action", "initiating").
		Send()
	defer log.Info().
		Str("entity", "EET Gateway").
		Str("action", "exiting").
		Send()

	caSvc, err := newCASvc()
	if err != nil {
		return fmt.Errorf("start CA service: %w", err)
	}

	client, err := newFSCRClient()
	if err != nil {
		return fmt.Errorf("start FSCR client: %w", err)
	}

	ks, err := newKeystoreSvc()
	if err != nil {
		return fmt.Errorf("start keystore client: %w", err)
	}

	gSvc := newGatewaySvc(client, caSvc, ks)
	h := server.NewHTTPHandler(gSvc)

	httpServer, err := newHTTPServer(h)
	if err != nil {
		return fmt.Errorf("create http server: %w", err)
	}

	srv := server.NewService(httpServer)

	runServer(srv)

	return nil
}

func loadConfigFromENV() {
	viper.SetEnvPrefix("EETG")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
}

func loadConfigFromFile(path string) error {
	ext := filepath.Ext(path)
	name := strings.TrimSuffix(filepath.Base(path), ext)
	dir := filepath.Dir(path)

	viper.SetConfigName(name)
	viper.SetConfigType(ext[1:])
	viper.AddConfigPath(dir)

	if err := viper.ReadInConfig(); err != nil {
		var vErr viper.ConfigFileNotFoundError
		if errors.As(err, &vErr) {
			setupLogger()
			log.Info().
				Str("entity", "Config Service").
				Str("action", "loading configuration").
				Str("status", "config file not found (skipping)").
				Str("path", path).
				Send()
		} else {
			return fmt.Errorf("read config file: %w", vErr)
		}
	} else {
		watchConfig()
	}

	return nil
}

func watchConfig() {
	viper.OnConfigChange(func(e fsnotify.Event) {
		log.Info().
			Str("entity", "Config Service").
			Str("action", "watching config file").
			Str("status", "config file changed").
			Str("operation", e.Op.String()).
			Str("path", e.Name).
			Str("note", "restart server to take effect").
			Send()
	})
	viper.WatchConfig()
}

func setupLogger() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	zerolog.DurationFieldUnit = time.Second

	if viper.GetBool(cliQuietMode) {
		log.Logger = zerolog.Nop()
	} else {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}
}

func runServer(srv server.Service) {
	log.Info().
		Str("entity", "HTTP Server").
		Str("action", "listening").
		Str("status", "online").
		Dur("shutdownTimeout", viper.GetDuration(serverShutdownTimeout)).
		Send()

	err := srv.ListenAndServe(viper.GetBool(serverTLSEnable), viper.GetDuration(serverShutdownTimeout))

	log.Info().
		Str("entity", "HTTP Server").
		Str("action", "shutting down").
		Str("status", "offline").
		Err(err).
		Send()
}
