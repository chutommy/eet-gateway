package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	slog "log"
	"net/http"

	"github.com/chutommy/eetgateway/pkg/ca"
	"github.com/chutommy/eetgateway/pkg/fscr"
	"github.com/chutommy/eetgateway/pkg/gateway"
	"github.com/chutommy/eetgateway/pkg/keystore"
	"github.com/chutommy/eetgateway/pkg/server"
	"github.com/go-redis/redis/v8"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

const (
	eetServerName = "eet.cz"
)

func newCASvc() (fscr.CAService, error) {
	mode, roots, err := getCARoots()
	if err != nil {
		return nil, fmt.Errorf("fetch CA roots and mode")
	}

	dsigPool := x509.NewCertPool()
	if ok := dsigPool.AppendCertsFromPEM(ca.ICACertificate); !ok {
		return nil, fmt.Errorf("append to dsig certificate pool")
	}

	log.Info().
		Str("entity", "Certificate Authority Service").
		Str("action", "starting").
		Str("mode", mode).
		Send()

	return fscr.NewCAService(roots, dsigPool), nil
}

func getCARoots() (string, []*x509.Certificate, error) {
	mode := "playground"
	roots, err := ca.PlaygroundRoots()
	if err != nil {
		return "", nil, fmt.Errorf("retrieve playground roots: %w", err)
	}

	if viper.GetBool(eetProductionMode) {
		mode = "production"
		roots, err = ca.ProductionRoots()
		if err != nil {
			return "", nil, fmt.Errorf("retrieve production roots: %w", err)
		}
	}

	return mode, roots, nil
}

func newFSCRClient() (fscr.Client, error) {
	url, mode := fscrURL()

	log.Info().
		Str("entity", "FSCR Client").
		Str("action", "starting").
		Str("url", url).
		Str("mode", mode).
		Str("requestTimeout", viper.GetDuration(eetRequestTimeout).String()).
		Str("serverName", eetServerName).
		Str("tlsVersion", "TLS 1.3").
		Send()

	c := fscr.NewClient(&http.Client{
		Timeout: viper.GetDuration(eetRequestTimeout),
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         eetServerName,
				ClientAuth:         tls.NoClientCert,
				ClientSessionCache: tls.NewLRUClientSessionCache(64),
				MinVersion:         tls.VersionTLS13,
			},
		},
	}, url)

	if err := c.Ping(); err != nil {
		return nil, fmt.Errorf("ping FSCR: %w", err)
	}

	return c, nil
}

func fscrURL() (url string, mode string) {
	url = fscr.PlaygroundURL
	mode = "playground"
	if viper.GetBool(eetProductionMode) {
		url = fscr.ProductionURL
		mode = "production"
	}

	return
}

func newKeystoreSvc() (keystore.Service, error) {
	log.Info().
		Str("entity", "KeyStore Client").
		Str("action", "starting").
		Str("network", viper.GetString(redisNetwork)).
		Str("addr", viper.GetString(redisAddr)).
		Int("db", viper.GetInt(redisDB)).
		Dur("dialTimeout", viper.GetDuration(redisDialTimeout)).
		Dur("readTimeout", viper.GetDuration(redisReadTimeout)).
		Dur("writeTimeout", viper.GetDuration(redisWriteTimeout)).
		Dur("idleTimeout", viper.GetDuration(redisIdleTimeout)).
		Dur("poolTimeout", viper.GetDuration(redisPoolTimeout)).
		Dur("idleCheckFrequency", viper.GetDuration(redisIdleCheckFrequency)).
		Int("poolSize", viper.GetInt(redisPoolSize)).
		Int("minIdleConns", viper.GetInt(redisMinIdleConns)).
		Send()

	opt := &redis.Options{
		Network:            viper.GetString(redisNetwork),
		Addr:               viper.GetString(redisAddr),
		Username:           viper.GetString(redisUsername),
		Password:           viper.GetString(redisPassword),
		DB:                 viper.GetInt(redisDB),
		DialTimeout:        viper.GetDuration(redisDialTimeout),
		ReadTimeout:        viper.GetDuration(redisReadTimeout),
		WriteTimeout:       viper.GetDuration(redisWriteTimeout),
		IdleTimeout:        viper.GetDuration(redisIdleTimeout),
		PoolTimeout:        viper.GetDuration(redisPoolTimeout),
		IdleCheckFrequency: viper.GetDuration(redisIdleCheckFrequency),
		PoolSize:           viper.GetInt(redisPoolSize),
		MinIdleConns:       viper.GetInt(redisMinIdleConns),
	}

	if viper.GetBool(redisTLSEnable) {
		log.Info().
			Str("entity", "KeyStore Client").
			Str("action", "enabling TLS").
			Str("serverName", viper.GetString(redisTLSServerName)).
			Strs("rootCAs", viper.GetStringSlice(redisTLSRootCAs)).
			Str("certificate", viper.GetString(redisTLSCertificate)).
			Str("privateKey", viper.GetString(redisTLSPrivateKey)).
			Str("tlsVersion", "TLS 1.2").
			Send()

		cert, err := tls.LoadX509KeyPair(viper.GetString(redisTLSCertificate), viper.GetString(redisTLSPrivateKey))
		if err != nil {
			return nil, fmt.Errorf("load redis TLS keypair: %w", err)
		}

		pool := x509.NewCertPool()
		for _, v := range viper.GetStringSlice(redisTLSRootCAs) {
			data, err := ioutil.ReadFile(v)
			if err != nil {
				return nil, fmt.Errorf("read file %s: %w", v, err)
			}

			b, _ := pem.Decode(data)
			cert, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse root CA certificate %s: %w", v, err)
			}

			pool.AddCert(cert)
		}

		opt.TLSConfig = &tls.Config{
			Certificates:       []tls.Certificate{cert},
			ServerName:         viper.GetString(redisTLSServerName),
			RootCAs:            pool,
			ClientSessionCache: tls.NewLRUClientSessionCache(64),
			MinVersion:         tls.VersionTLS12,
		}
	}

	ks := keystore.NewRedisService(redis.NewClient(opt))
	if err := ks.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("ping keystore: %w", err)
	}

	return ks, nil
}

func newGatewaySvc(client fscr.Client, caSvc fscr.CAService, ks keystore.Service) gateway.Service {
	return gateway.NewService(client, caSvc, ks)
}

func newHTTPServer(h server.Handler) (*http.Server, error) {
	log.Info().
		Str("entity", "HTTP Server").
		Str("action", "starting").
		Str("addr", viper.GetString(serverAddr)).
		Dur("readTimeout", viper.GetDuration(serverReadTimeout)).
		Dur("readHeaderTimeout", viper.GetDuration(serverReadHeaderTimeout)).
		Dur("writeTimeout", viper.GetDuration(serverWriteTimeout)).
		Dur("idleTimeout", viper.GetDuration(serverIdleTimeout)).
		Int("maxHeaderBytes", viper.GetInt(serverMaxHeaderBytes)).
		Send()

	httpServer := &http.Server{
		Addr:              viper.GetString(serverAddr),
		ReadTimeout:       viper.GetDuration(serverReadTimeout),
		ReadHeaderTimeout: viper.GetDuration(serverReadHeaderTimeout),
		WriteTimeout:      viper.GetDuration(serverWriteTimeout),
		IdleTimeout:       viper.GetDuration(serverIdleTimeout),
		MaxHeaderBytes:    viper.GetInt(serverMaxHeaderBytes),
		Handler:           h.HTTPHandler(),
		ErrorLog:          slog.New(ioutil.Discard, "", 0),
	}

	if viper.GetBool(serverTLSEnable) {
		log.Info().
			Str("entity", "HTTP Server").
			Str("action", "enabling server TLS").
			Str("certificate", viper.GetString(serverTLSCertificate)).
			Str("privateKey", viper.GetString(serverTLSPrivateKey)).
			Str("tlsVersion", "TLS 1.2").
			Send()

		cert, err := tls.LoadX509KeyPair(viper.GetString(serverTLSCertificate), viper.GetString(serverTLSPrivateKey))
		if err != nil {
			return nil, fmt.Errorf("load SSL certificate: %w", err)
		}

		httpServer.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0)
		httpServer.TLSConfig = &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
		}
	}

	if viper.GetBool(serverMutualTLSEnable) {
		log.Info().
			Str("entity", "HTTP Server").
			Str("action", "enabling client TLS").
			Strs("rootCAs", viper.GetStringSlice(serverMutualTLSClientCAs)).
			Str("tlsVersion", "TLS 1.2").
			Send()

		pool := x509.NewCertPool()
		for _, v := range viper.GetStringSlice(serverMutualTLSClientCAs) {
			data, err := ioutil.ReadFile(v)
			if err != nil {
				return nil, fmt.Errorf("read file %s: %w", v, err)
			}

			b, _ := pem.Decode(data)
			cert, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse client CA certificate %s: %w", v, err)
			}

			pool.AddCert(cert)
		}

		httpServer.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
		httpServer.TLSConfig.ClientCAs = pool
	}

	return httpServer, nil
}
