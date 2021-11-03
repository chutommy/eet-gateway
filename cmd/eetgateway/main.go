package main

// NOTE: This file consists of dev snippets.

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
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
	"github.com/spf13/viper"
)

const (
	configFileName = "config"
	configFileType = "json"
	configFile     = configFileName + "." + configFileType
)

const (
	eetProductionMode = "eet.production.mode"

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

func main() {
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

	// load from file
	var configDir string
	homeDir, err := os.UserHomeDir()
	errCheck(err)

	switch runtime.GOOS {
	case "linux":
		configDir = filepath.Join(homeDir, ".config", "eetgateway")
	case "darwin":
		configDir = filepath.Join(homeDir, "Library", "Preferences", "eetgateway")
	case "windows":
		configDir = filepath.Join(homeDir, "AppData", "Local", "EETGateway")
	}

	viper.SetConfigName(configFileName)
	viper.SetConfigType(configFileType)
	viper.AddConfigPath(configDir)

	log.Info().
		Str("entity", "Config Service").
		Str("action", "looking for config file").
		Str("path", filepath.Join(configDir, configFile)).
		Send()

	if err := viper.ReadInConfig(); err != nil {
		if ok := errors.As(err, &viper.ConfigFileNotFoundError{}); ok {
			log.Info().
				Str("entity", "Config Service").
				Str("action", "generating config file").
				Str("status", "config file not found").
				Str("path", filepath.Join(configDir, configFile)).
				Send()

			err = os.MkdirAll(configDir, os.ModePerm)
			errCheck(err)

			err = viper.SafeWriteConfig()
			errCheck(err)
		} else {
			errCheck(err)
		}
	} else {
		log.Info().
			Str("entity", "Config Service").
			Str("action", "loading config file").
			Str("status", "config file located").
			Str("path", filepath.Join(configDir, configFile)).
			Send()
	}

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
	log.Info().
		Str("entity", "HTTP Server").
		Str("action", "listening").
		Str("status", "online").
		Dur("shutdownTimeout", viper.GetDuration(serverShutdownTimeout)).
		Send()

	err = srv.ListenAndServe(viper.GetDuration(serverShutdownTimeout))

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
