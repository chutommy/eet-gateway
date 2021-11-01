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
)

func main() {
	// Viper
	eet_production_mode := false

	redis_network := "tcp"
	redis_addr := "localhost:6379"
	redis_username := ""
	redis_password := ""
	redis_db := 0
	redis_idle_timeout := 5 * time.Minute
	redis_dial_timeout := 3 * time.Second
	redis_read_timeout := 1 * time.Second
	redis_write_timeout := 1 * time.Second
	redis_pool_timeout := 1 * time.Second
	redis_pool_size := 100
	redis_idle_check_frequency := 1 * time.Minute
	redis_min_idle_conns := 5

	server_addr := ":3000"
	server_idle_timeout := time.Second * 100
	server_write_timeout := time.Second * 10
	server_read_timeout := time.Second * 10
	server_read_header_timeout := time.Second * 2
	server_max_header_bytes := http.DefaultMaxHeaderBytes
	server_shutdown_timeout := 10 * time.Second

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
	if eet_production_mode {
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
	if eet_production_mode {
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
		Str("network", redis_network).
		Str("addr", redis_addr).
		Int("db", redis_db).
		Int("minIdleConns", redis_min_idle_conns).
		Send()

	ks := keystore.NewRedisService(redis.NewClient(&redis.Options{
		Network:            redis_network,
		Addr:               redis_addr,
		Username:           redis_username,
		Password:           redis_password,
		DB:                 redis_db,
		IdleTimeout:        redis_idle_timeout,
		DialTimeout:        redis_dial_timeout,
		ReadTimeout:        redis_read_timeout,
		WriteTimeout:       redis_write_timeout,
		PoolTimeout:        redis_pool_timeout,
		PoolSize:           redis_pool_size,
		IdleCheckFrequency: redis_idle_check_frequency,
		MinIdleConns:       redis_min_idle_conns,
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
		Str("addr", server_addr).
		Dur("idleTimeout", server_idle_timeout).
		Dur("writeTimeout", server_write_timeout).
		Dur("readTimeout", server_read_timeout).
		Dur("readHeaderTimeout", server_read_header_timeout).
		Int("maxHeaderBytes", server_max_header_bytes).
		Send()

	gSvc := gateway.NewService(client, caSvc, ks)
	h := server.NewHandler(gSvc)
	srv := server.NewService(&http.Server{
		Addr:              server_addr,
		Handler:           h.HTTPHandler(),
		ReadTimeout:       server_read_timeout,
		ReadHeaderTimeout: server_read_header_timeout,
		WriteTimeout:      server_write_timeout,
		IdleTimeout:       server_idle_timeout,
		MaxHeaderBytes:    server_max_header_bytes,
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
		Dur("shutdownTimeout", server_shutdown_timeout).
		Send()

	err = srv.ListenAndServe(server_shutdown_timeout)

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
