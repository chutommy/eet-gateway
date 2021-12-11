package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chutommy/eetgateway/pkg/ca"
	"github.com/chutommy/eetgateway/pkg/fscr"
	"github.com/chutommy/eetgateway/pkg/gateway"
	"github.com/chutommy/eetgateway/pkg/keystore"
	"github.com/chutommy/eetgateway/pkg/server"
	"github.com/fsnotify/fsnotify"
	"github.com/go-redis/redis/v8"
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

func newHTTPServer(h server.Handler) (*http.Server, error) {
	httpServer := &http.Server{
		Addr:              viper.GetString(serverAddr),
		ReadTimeout:       viper.GetDuration(serverReadTimeout),
		ReadHeaderTimeout: viper.GetDuration(serverReadHeaderTimeout),
		WriteTimeout:      viper.GetDuration(serverWriteTimeout),
		IdleTimeout:       viper.GetDuration(serverIdleTimeout),
		MaxHeaderBytes:    viper.GetInt(serverMaxHeaderBytes),
		Handler:           h.HTTPHandler(),
	}

	if viper.GetBool(serverTLSEnable) {
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

	return httpServer, nil
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

func newGatewaySvc(client fscr.Client, caSvc fscr.CAService, ks keystore.Service) gateway.Service {
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

	return gateway.NewService(client, caSvc, ks)
}

func newKeystoreSvc() (keystore.Service, error) {
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
		// TODO TLS
		// TLSConfig: &tls.Config{
		// 	ServerName:   "",
		// 	Certificates: nil,
		// 	RootCAs:      nil,
		// 	ClientCAs:    nil,
		// 	MinVersion:   tls.VersionTLS13,
		// },
	}))

	if err := ks.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("ping keystore: %w", err)
	}

	return ks, nil
}

func newFSCRClient() (fscr.Client, error) {
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("retrieve system certificate pool: %w", err)
	}

	url, mode := fscrURL()

	log.Info().
		Str("entity", "FSCR Client").
		Str("action", "starting").
		Str("url", url).
		Str("requestTimeout", viper.GetDuration(eetRequestTimeout).String()).
		Str("mode", mode).
		Send()

	c := fscr.NewClient(&http.Client{
		Timeout: viper.GetDuration(eetRequestTimeout),
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "eet.cz",
				RootCAs:            certPool,
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

func fscrURL() (string, string) {
	url := fscr.PlaygroundURL
	mode := "playground"
	if viper.GetBool(eetProductionMode) {
		url = fscr.ProductionURL
		mode = "production"
	}

	return url, mode
}

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

func loadConfigFromENV() {
	viper.SetEnvPrefix("EETG")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
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

	if viper.GetBool(apiQuietMode) {
		log.Logger = zerolog.Nop()
	} else {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}
}
