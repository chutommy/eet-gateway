package cmd

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/spf13/viper"
)

const (
	// WARNING!
	// If the configuration file structure or the variable names are modified,
	// DO NOT FORGET to update example of configuration files as well.
	// ["eetgateway.json", ".env"]

	cliQuietMode = "cli.quiet_mode"

	eetProductionMode = "eet.production_mode"
	eetRequestTimeout = "eet.request_timeout"

	redisNetwork  = "redis.network"
	redisAddr     = "redis.addr"
	redisUsername = "redis.username"
	redisPassword = "redis.password"
	redisDB       = "redis.db"

	redisDialTimeout        = "redis.dial_timeout"
	redisReadTimeout        = "redis.read_timeout"
	redisWriteTimeout       = "redis.write_timeout"
	redisIdleTimeout        = "redis.idle_timeout"
	redisPoolTimeout        = "redis.pool_timeout"
	redisIdleCheckFrequency = "redis.idle_check_frequency"

	redisPoolSize     = "redis.pool_size"
	redisMinIdleConns = "redis.min_idle_conns"

	redisTLSEnable      = "redis.tls.enable"
	redisTLSServerName  = "redis.tls.server_name"
	redisTLSRootCAs     = "redis.tls.root_cas"
	redisTLSCertificate = "redis.tls.certificate"
	redisTLSPrivateKey  = "redis.tls.private_key"

	serverAddr = "server.addr"

	serverReadTimeout       = "server.read_timeout"
	serverReadHeaderTimeout = "server.read_header_timeout"
	serverWriteTimeout      = "server.write_timeout"
	serverIdleTimeout       = "server.idle_timeout"
	serverShutdownTimeout   = "server.shutdown_timeout"

	serverMaxHeaderBytes = "server.max_header_bytes"

	serverTLSEnable      = "server.tls.enable"
	serverTLSCertificate = "server.tls.certificate"
	serverTLSPrivateKey  = "server.tls.private_key"

	serverMutualTLSEnable    = "server.mutual_tls.enable"
	serverMutualTLSClientCAs = "server.mutual_tls.client_cas"
)

func setDefaultConfig() {
	viper.SetDefault(cliQuietMode, false)

	viper.SetDefault(eetProductionMode, false)
	viper.SetDefault(eetRequestTimeout, (10 * time.Second).String())

	viper.SetDefault(redisNetwork, "tcp")
	viper.SetDefault(redisAddr, "localhost:6379")
	viper.SetDefault(redisUsername, "")
	viper.SetDefault(redisPassword, "")
	viper.SetDefault(redisDB, 0)

	viper.SetDefault(redisDialTimeout, (3 * time.Second).String())
	viper.SetDefault(redisReadTimeout, (1 * time.Second).String())
	viper.SetDefault(redisWriteTimeout, (1 * time.Second).String())
	viper.SetDefault(redisIdleTimeout, (5 * time.Minute).String())
	viper.SetDefault(redisPoolTimeout, (1 * time.Second).String())
	viper.SetDefault(redisIdleCheckFrequency, (1 * time.Minute).String())

	viper.SetDefault(redisPoolSize, 100)
	viper.SetDefault(redisMinIdleConns, 5)

	viper.SetDefault(redisTLSEnable, false)
	viper.SetDefault(redisTLSServerName, "")
	viper.SetDefault(redisTLSRootCAs, []string{"certs/redis/server/ca.crt"})
	viper.SetDefault(redisTLSCertificate, "certs/redis/client/client.crt")
	viper.SetDefault(redisTLSPrivateKey, "certs/redis/client/client.key")

	viper.SetDefault(serverAddr, "localhost:8080")

	viper.SetDefault(serverReadTimeout, (100 * time.Second).String())
	viper.SetDefault(serverReadHeaderTimeout, (100 * time.Second).String())
	viper.SetDefault(serverWriteTimeout, (100 * time.Second).String())
	viper.SetDefault(serverIdleTimeout, (100 * time.Second).String())
	viper.SetDefault(serverShutdownTimeout, (10 * time.Second).String())

	viper.SetDefault(serverMaxHeaderBytes, http.DefaultMaxHeaderBytes)

	viper.SetDefault(serverTLSEnable, false)
	viper.SetDefault(serverTLSCertificate, "certs/server/server.crt")
	viper.SetDefault(serverTLSPrivateKey, "certs/server/server.key")

	viper.SetDefault(serverMutualTLSEnable, false)
	viper.SetDefault(serverMutualTLSClientCAs, []string{"certs/client/ca.crt"})
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
