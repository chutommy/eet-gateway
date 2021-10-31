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
	// logs
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	gin.SetMode(gin.ReleaseMode)

	// CA service
	eetCARoots, err := ca.PlaygroundRoots()
	errCheck(err)

	dsigPool := x509.NewCertPool()
	if ok := dsigPool.AppendCertsFromPEM(ca.ICACertificate); !ok {
		panic("failed to parse root certificate")
	}

	caSvc := fscr.NewCAService(eetCARoots, dsigPool)

	// FSCR client
	certPool, err := x509.SystemCertPool()
	errCheck(err)
	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            certPool,
				InsecureSkipVerify: false,
				MinVersion:         tls.VersionTLS13,
			},
		},
	}

	client := fscr.NewClient(c, fscr.PlaygroundURL)

	// keystore client
	rdb := redis.NewClient(&redis.Options{
		Network:      "tcp",
		Addr:         "localhost:6379",
		Username:     "",
		Password:     "",
		DB:           0,
		MinIdleConns: 2,
		TLSConfig:    nil,
	})

	ks := keystore.NewRedisService(rdb)

	// EET gateway service
	gSvc := gateway.NewService(client, caSvc, ks)

	// HTTP server
	h := server.NewHandler(gSvc)
	srv := server.NewService(&http.Server{
		Addr:              ":3000",
		Handler:           h.HTTPHandler(),
		TLSConfig:         nil,
		ReadTimeout:       time.Second * 10,
		ReadHeaderTimeout: time.Second * 2,
		WriteTimeout:      time.Second * 10,
		IdleTimeout:       time.Second * 100,
		MaxHeaderBytes:    http.DefaultMaxHeaderBytes,
	})

	srv.ListenAndServe(10 * time.Second)
}

func errCheck(err error) {
	if err != nil {
		panic(err)
	}
}
