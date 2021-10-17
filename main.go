package main

// WARNING: This file consists of dev snippets.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

	"github.com/chutommy/eetgateway/pkg/ca"
	"github.com/chutommy/eetgateway/pkg/eet"
	"github.com/chutommy/eetgateway/pkg/fscr"
	"github.com/chutommy/eetgateway/pkg/keystore"
	"github.com/chutommy/eetgateway/pkg/server"
	"github.com/go-redis/redis/v8"
	"github.com/rs/zerolog"
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	zerolog.SetGlobalLevel(zerolog.DebugLevel) // lowest => log everything

	eetCARoots, err := ca.PlaygroundRoots()
	errCheck(err)

	dsigPool := x509.NewCertPool()
	if ok := dsigPool.AppendCertsFromPEM(ca.ICACertificate); !ok {
		panic("failed to parse root certificate")
	}
	caSvc := fscr.NewCAService(eetCARoots, dsigPool)

	// dep services
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
	errCheck(err)

	rdb := redis.NewClient(&redis.Options{
		Network:      "tcp",
		Addr:         "localhost:6379",
		Username:     "",
		Password:     "",
		DB:           0,
		MinIdleConns: 2,
		TLSConfig:    nil,
	})

	_, err = rdb.Ping(context.Background()).Result()
	errCheck(err)

	ks := keystore.NewRedisService(rdb)
	gSvc := eet.NewGatewayService(client, caSvc, ks)

	// server
	h := server.NewHandler(gSvc)
	srv := server.NewService(&http.Server{
		Addr:              ":8080",
		Handler:           h.HTTPHandler(),
		TLSConfig:         nil,
		ReadTimeout:       time.Second * 10,
		ReadHeaderTimeout: time.Second * 2,
		WriteTimeout:      time.Second * 10,
		IdleTimeout:       time.Second * 100,
		MaxHeaderBytes:    http.DefaultMaxHeaderBytes,
	})
	fmt.Println(srv.ListenAndServe(10 * time.Second))
}

func errCheck(err error) {
	if err != nil {
		panic(err)
	}
}
