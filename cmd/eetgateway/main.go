package main

// NOTE: This file consists of dev snippets.

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"time"

	"github.com/chutommy/eetgateway/pkg/ca"
	"github.com/chutommy/eetgateway/pkg/fscr"
	"github.com/chutommy/eetgateway/pkg/gateway"
	"github.com/chutommy/eetgateway/pkg/keystore"
	"github.com/chutommy/eetgateway/pkg/server"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

const (
	eetProductionMode       = "eet_production_mode"
	redisNetwork            = "redis_network"
	redisAddr               = "redis_addr"
	redisUsername           = "redis_username"
	redisPassword           = "redis_password"
	redisDB                 = "redis_db"
	redisIdleTimeout        = "redis_idle_timeout"
	redisDialTimeout        = "redis_dial_timeout"
	redisReadTimeout        = "redis_read_timeout"
	redisWriteTimeout       = "redis_write_timeout"
	redisPoolTimeout        = "redis_pool_timeout"
	redisPoolSize           = "redis_pool_size"
	redisIdleCheckFrequency = "redis_idle_check_frequency"
	redisMinIdleConns       = "redis_min_idle_conns"
	serverAddr              = "server_addr"
	serverIdleTimeout       = "server_idle_timeout"
	serverWriteTimeout      = "server_write_timeout"
	serverReadTimeout       = "server_read_timeout"
	serverReadHeaderTimeout = "server_read_header_timeout"
	serverMaxHeaderBytes    = "server_max_header_bytes"
	serverShutdownTimeout   = "server_shutdown_timeout"
)

func main() {
	// Viper
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

	// Logger
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	zerolog.DurationFieldUnit = time.Millisecond
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

	// CA Service
	caRoots, err := ca.PlaygroundRoots()
	caMode := "playground"
	if viper.GetBool(eetProductionMode) {
		caRoots, err = ca.ProductionRoots()
		caMode = "production"
	}
	errCheck(err)

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
