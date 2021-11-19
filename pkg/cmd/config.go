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

func configSetDefault() {
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

	viper.SetDefault(serverAddr, "localhost:8080")
	viper.SetDefault(serverIdleTimeout, time.Second*100)
	viper.SetDefault(serverWriteTimeout, time.Second*10)
	viper.SetDefault(serverReadTimeout, time.Second*10)
	viper.SetDefault(serverReadHeaderTimeout, time.Second*2)
	viper.SetDefault(serverMaxHeaderBytes, http.DefaultMaxHeaderBytes)
	viper.SetDefault(serverShutdownTimeout, 10*time.Second)
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
