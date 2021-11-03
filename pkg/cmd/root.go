package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/chutommy/eetgateway/pkg/ca"
	"github.com/chutommy/eetgateway/pkg/fscr"
	"github.com/chutommy/eetgateway/pkg/gateway"
	"github.com/chutommy/eetgateway/pkg/keystore"
	"github.com/chutommy/eetgateway/pkg/server"
	"github.com/fsnotify/fsnotify"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "eetg",
	Short: "EET Gateway is the entry point for communication with the Czech EET system (Electronic Registration of Sales)",
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of the EET Gateway",
	Run: func(cmd *cobra.Command, args []string) {
		s := fmt.Sprintf("EET Gateway %s %s/%s", eetgVersion, runtime.GOOS, runtime.GOARCH)
		fmt.Println(s)
	},
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Initialize the EET Gateway service and start serving",
	Run: func(cmd *cobra.Command, args []string) {
		m()
	},
}

// Execute executes the root command.
func Execute() {
	viper.SetDefault(apiQuietMode, false)

	viper.SetDefault(eetProductionMode, false)

	viper.SetDefault(redisNetwork, "tcp")
	viper.SetDefault(redisAddr, "localhost:6379")
	viper.SetDefault(redisUsername, "")
	viper.SetDefault(redisPassword, "")
	viper.SetDefault(redisDB, 0)
	viper.SetDefault(redisIdleTimeout, 5*time.Minute)
	viper.SetDefault(redisDialTimeout, 3*time.Second)
	viper.SetDefault(redisReadTimeout, 1*time.Second)
	viper.SetDefault(redisWriteTimeout, 1*time.Second)
	viper.SetDefault(redisPoolTimeout, 1*time.Second)
	viper.SetDefault(redisPoolSize, 100)
	viper.SetDefault(redisIdleCheckFrequency, 1*time.Minute)
	viper.SetDefault(redisMinIdleConns, 5)

	viper.SetDefault(serverAddr, ":8080")
	viper.SetDefault(serverIdleTimeout, time.Second*100)
	viper.SetDefault(serverWriteTimeout, time.Second*10)
	viper.SetDefault(serverReadTimeout, time.Second*10)
	viper.SetDefault(serverReadHeaderTimeout, time.Second*2)
	viper.SetDefault(serverMaxHeaderBytes, http.DefaultMaxHeaderBytes)
	viper.SetDefault(serverShutdownTimeout, 10*time.Second)

	rootCmd.AddCommand(initCmd, serveCmd, versionCmd)

	if err := rootCmd.Execute(); err != nil {
		log.Fatal().
			Str("entity", "CLI Service").
			Str("action", "executing root command").
			Err(err).
			Send()
	}
}

const (
	eetgVersion = "v0.4.0"
)

const (
	apiQuietMode = "api.quiet_mode"

	eetProductionMode = "eet.production_mode"

	redisNetwork            = "redis.network"
	redisAddr               = "redis.addr"
	redisUsername           = "redis.username"
	redisPassword           = "redis.password"
	redisDB                 = "redis.db"
	redisIdleTimeout        = "redis.time.idle_timeout"
	redisDialTimeout        = "redis.time.dial_timeout"
	redisReadTimeout        = "redis.time.read_timeout"
	redisWriteTimeout       = "redis.time.write_timeout"
	redisPoolTimeout        = "redis.time.pool_timeout"
	redisIdleCheckFrequency = "redis.time.idle_check_frequency"
	redisPoolSize           = "redis.pool_size"
	redisMinIdleConns       = "redis.min_idle_conns"

	serverAddr              = "server.addr"
	serverIdleTimeout       = "server.time.idle_timeout"
	serverWriteTimeout      = "server.time.write_timeout"
	serverReadTimeout       = "server.time.read_timeout"
	serverReadHeaderTimeout = "server.time.read_header_timeout"
	serverShutdownTimeout   = "server.time.shutdown_timeout"
	serverMaxHeaderBytes    = "server.data.max_header_bytes"
)

func m() {
	// Logger
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	zerolog.DurationFieldUnit = time.Second
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	gin.SetMode(gin.ReleaseMode)

	log.Info().
		Str("entity", "EET Gateway").
		Str("action", "initiating").
		Send()
	defer log.Info().
		Str("entity", "EET Gateway").
		Str("action", "exiting").
		Send()

	// Viper
	log.Info().
		Str("entity", "Config Service").
		Str("action", "setting defaults").
		Send()

	// set defaults

	// load from file
	configDir, err := osConfigDir()
	if err != nil {
		panic(err)
	}

	configPath := filepath.Join(configDir, configFile)
	extension := filepath.Ext(configPath)
	filename := strings.TrimSuffix(filepath.Base(configPath), extension)
	directory := filepath.Dir(configPath)
	viper.SetConfigName(filename)
	viper.SetConfigType(extension[1:])
	viper.AddConfigPath(directory)

	log.Info().
		Str("entity", "Config Service").
		Str("action", "looking for config file").
		Str("path", configPath).
		Send()

	if err := viper.ReadInConfig(); err != nil {
		if ok := errors.As(err, &viper.ConfigFileNotFoundError{}); ok {
			fmt.Println("Config file not found, run eetg init")
			os.Exit(1)
		} else {
			fmt.Println("invalid config file: %w", err)
			os.Exit(1)
		}
	}

	log.Info().
		Str("entity", "Config Service").
		Str("action", "loading config file").
		Str("status", "config file located").
		Str("path", configPath).
		Send()

	// watch config changes
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

	// load env variables
	viper.SetEnvPrefix("EETG")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// CA Service
	caRoots, err := ca.PlaygroundRoots()
	errCheck(err)
	caMode := "playground"
	if viper.GetBool(eetProductionMode) {
		caRoots, err = ca.ProductionRoots()
		errCheck(err)
		caMode = "production"
	}

	caDSigPool := x509.NewCertPool()
	if ok := caDSigPool.AppendCertsFromPEM(ca.ICACertificate); !ok {
		panic("failed to parse root certificate")
	}

	log.Info().
		Str("entity", "Certificate Authority Service").
		Str("action", "starting").
		Str("mode", caMode).
		Send()

	caSvc := fscr.NewCAService(caRoots, caDSigPool)

	// FSCR Client
	certPool, err := x509.SystemCertPool()
	errCheck(err)

	fscrURL := fscr.PlaygroundURL
	fscrMode := "playground"
	if viper.GetBool(eetProductionMode) {
		fscrURL = fscr.ProductionURL
		fscrMode = "production"
	}

	log.Info().
		Str("entity", "FSCR Client").
		Str("action", "starting").
		Str("url", fscrURL).
		Str("mode", fscrMode).
		Send()

	client := fscr.NewClient(&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// ServerName:   "",
				// Certificates: nil,
				RootCAs: certPool,
				// ClientCAs:    nil,
				MinVersion: tls.VersionTLS13,
			},
		},
	}, fscrURL)

	// KeyStore Client
	log.Info().
		Str("entity", "KeyStore Client").
		Str("action", "starting").
		Str("network", viper.GetString(redisNetwork)).
		Str("addr", viper.GetString(redisAddr)).
		Int("db", viper.GetInt(redisDB)).
		Int("minIdleConns", viper.GetInt(redisMinIdleConns)).
		Send()

	ks := keystore.NewRedisService(redis.NewClient(&redis.Options{
		Network:            viper.GetString(redisNetwork),
		Addr:               viper.GetString(redisAddr),
		Username:           viper.GetString(redisUsername),
		Password:           viper.GetString(redisPassword),
		DB:                 viper.GetInt(redisDB),
		PoolSize:           viper.GetInt(redisPoolSize),
		MinIdleConns:       viper.GetInt(redisMinIdleConns),
		IdleTimeout:        viper.GetDuration(redisIdleTimeout),
		DialTimeout:        viper.GetDuration(redisDialTimeout),
		ReadTimeout:        viper.GetDuration(redisReadTimeout),
		WriteTimeout:       viper.GetDuration(redisWriteTimeout),
		PoolTimeout:        viper.GetDuration(redisPoolTimeout),
		IdleCheckFrequency: viper.GetDuration(redisIdleCheckFrequency),
		// TLSConfig: &tls.Config{
		// 	ServerName:   "",
		// 	Certificates: nil,
		// 	RootCAs:      nil,
		// 	ClientCAs:    nil,
		// 	MinVersion:   tls.VersionTLS13,
		// },
	}))

	// HTTP Server
	log.Info().
		Str("entity", "HTTP Server").
		Str("action", "starting").
		Str("addr", viper.GetString(serverAddr)).
		Dur("idleTimeout", viper.GetDuration(serverIdleTimeout)).
		Dur("writeTimeout", viper.GetDuration(serverWriteTimeout)).
		Dur("readTimeout", viper.GetDuration(serverReadTimeout)).
		Dur("readHeaderTimeout", viper.GetDuration(serverReadHeaderTimeout)).
		Int("maxHeaderBytes", viper.GetInt(serverMaxHeaderBytes)).
		Send()

	gSvc := gateway.NewService(client, caSvc, ks)
	h := server.NewHandler(gSvc)
	srv := server.NewService(&http.Server{
		Addr:              viper.GetString(serverAddr),
		ReadTimeout:       viper.GetDuration(serverReadTimeout),
		ReadHeaderTimeout: viper.GetDuration(serverReadHeaderTimeout),
		WriteTimeout:      viper.GetDuration(serverWriteTimeout),
		IdleTimeout:       viper.GetDuration(serverIdleTimeout),
		MaxHeaderBytes:    viper.GetInt(serverMaxHeaderBytes),
		Handler:           h.HTTPHandler(),
		// TLSConfig: &tls.Config{
		// 	ServerName:   "",
		// 	Certificates: nil,
		// 	RootCAs:      nil,
		// 	ClientCAs:    nil,
		// 	MinVersion:   tls.VersionTLS13,
		// },
	})

	// serve
	gatewayRun(srv)
}

func gatewayRun(srv server.Service) {
	log.Info().
		Str("entity", "HTTP Server").
		Str("action", "listening").
		Str("status", "online").
		Dur("shutdownTimeout", viper.GetDuration(serverShutdownTimeout)).
		Send()

	err := srv.ListenAndServe(viper.GetDuration(serverShutdownTimeout))

	log.Info().
		Str("entity", "HTTP Server").
		Str("action", "shutting down").
		Str("status", "offline").
		Err(err).
		Send()
}

func errCheck(err error) {
	if err != nil {
		panic(err)
	}
}