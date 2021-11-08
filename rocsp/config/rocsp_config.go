package rocsp_config

import (
	"fmt"

	"github.com/go-redis/redis/v8"
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/rocsp"
)

// RedisConfig contains the configuration needed to act as a Redis client.
type RedisConfig struct {
	// PasswordFile is a file containing the password for the Redis user.
	cmd.PasswordConfig
	// TLS contains the configuration to speak TLS with Redis.
	TLS cmd.TLSConfig
	// Username is a Redis username.
	Username string
	// Addrs is a list of IP address:port pairs.
	Addrs []string
	// Timeout is a per-request timeout applied to all Redis requests.
	Timeout cmd.ConfigDuration
}

func MakeClient(c *RedisConfig, clk clock.Clock) (*rocsp.WritingClient, error) {
	password, err := c.PasswordConfig.Pass()
	if err != nil {
		return nil, fmt.Errorf("loading password: %w", err)
	}

	tlsConfig, err := c.TLS.Load()
	if err != nil {
		return nil, fmt.Errorf("loading TLS config: %w", err)
	}

	timeout := c.Timeout.Duration

	rdb := redis.NewClusterClient(&redis.ClusterOptions{
		Addrs:     c.Addrs,
		Username:  c.Username,
		Password:  password,
		TLSConfig: tlsConfig,
		PoolSize:  100, // TODO(#5781): Make this configurable
	})
	return rocsp.NewWritingClient(rdb, timeout, clk), nil
}
