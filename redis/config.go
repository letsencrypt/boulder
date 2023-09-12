package redis

import (
	"fmt"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/config"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
)

// Config contains the configuration needed to act as a Redis client.
type Config struct {
	// TLS contains the configuration to speak TLS with Redis.
	TLS cmd.TLSConfig

	// Username used to authenticate to each Redis instance.
	Username string `validate:"required"`

	// PasswordFile is the path to a file holding the password used to
	// authenticate to each Redis instance.
	PasswordFile cmd.PasswordConfig `validate:"required"`

	// ShardAddrs is a map of shard names to IP address:port pairs. The go-redis
	// `Ring` client will shard reads and writes across the provided Redis
	// Servers based on a consistent hashing algorithm.
	ShardAddrs map[string]string `validate:"required_without=Lookups,min=1,dive,hostname_port"`

	// Lookups each entry contains a service and domain name that will be used
	// to construct a SRV DNS query to lookup Redis backends. For example: if
	// the resource record is 'foo.service.consul', then the 'Service' is 'foo'
	// and the 'Domain' is 'service.consul'. The expected dNSName to be
	// authenticated in the server certificate would be 'foo.service.consul'.
	Lookups []cmd.ServiceDomain `validate:"required_without=ShardAddrs,min=1,dive"`

	// LookupTimeout is the timeout for each periodic SRV lookup. Defaults to 30
	// seconds if unspecified.
	LookupTimeout config.Duration `validate:"-"`

	// LookupDNSAuthority can only be specified with Lookups. It's a single
	// <hostname|IPv4|[IPv6]>:<port> of the DNS server to be used for resolution
	// of Redis backends. If the address contains a hostname it will be resolved
	// using system DNS. If the address contains a port, the client will use it
	// directly, otherwise port 53 is used. If this field is left unspecified
	// the system DNS will be used for resolution.
	LookupDNSAuthority string `validate:"excluded_without=Lookups,omitempty,ip|hostname|hostname_port"`

	// Timeout is a per-request timeout applied to all Redis requests.
	Timeout config.Duration `validate:"-"`

	// Enables read-only commands on replicas.
	ReadOnly bool
	// Allows routing read-only commands to the closest primary or replica.
	// It automatically enables ReadOnly.
	RouteByLatency bool
	// Allows routing read-only commands to a random primary or replica.
	// It automatically enables ReadOnly.
	RouteRandomly bool

	// PoolFIFO uses FIFO mode for each node connection pool GET/PUT (default LIFO).
	PoolFIFO bool

	// Maximum number of retries before giving up.
	// Default is to not retry failed commands.
	MaxRetries int `validate:"min=0"`
	// Minimum backoff between each retry.
	// Default is 8 milliseconds; -1 disables backoff.
	MinRetryBackoff config.Duration `validate:"-"`
	// Maximum backoff between each retry.
	// Default is 512 milliseconds; -1 disables backoff.
	MaxRetryBackoff config.Duration `validate:"-"`

	// Dial timeout for establishing new connections.
	// Default is 5 seconds.
	DialTimeout config.Duration `validate:"-"`
	// Timeout for socket reads. If reached, commands will fail
	// with a timeout instead of blocking. Use value -1 for no timeout and 0 for default.
	// Default is 3 seconds.
	ReadTimeout config.Duration `validate:"-"`
	// Timeout for socket writes. If reached, commands will fail
	// with a timeout instead of blocking.
	// Default is ReadTimeout.
	WriteTimeout config.Duration `validate:"-"`

	// Maximum number of socket connections.
	// Default is 5 connections per every CPU as reported by runtime.NumCPU.
	// If this is set to an explicit value, that's not multiplied by NumCPU.
	// PoolSize applies per cluster node and not for the whole cluster.
	// https://pkg.go.dev/github.com/go-redis/redis#ClusterOptions
	PoolSize int `validate:"min=0"`
	// Minimum number of idle connections which is useful when establishing
	// new connection is slow.
	MinIdleConns int `validate:"min=0"`
	// Connection age at which client retires (closes) the connection.
	// Default is to not close aged connections.
	MaxConnAge config.Duration `validate:"-"`
	// Amount of time client waits for connection if all connections
	// are busy before returning an error.
	// Default is ReadTimeout + 1 second.
	PoolTimeout config.Duration `validate:"-"`
	// Amount of time after which client closes idle connections.
	// Should be less than server's timeout.
	// Default is 5 minutes. -1 disables idle timeout check.
	IdleTimeout config.Duration `validate:"-"`
	// Frequency of idle checks made by idle connections reaper.
	// Default is 1 minute. -1 disables idle connections reaper,
	// but idle connections are still discarded by the client
	// if IdleTimeout is set.
	// Deprecated: This field has been deprecated and will be removed.
	IdleCheckFrequency config.Duration `validate:"-"`
}

// NewRing returns a new Redis ring client.
func (c *Config) NewRing(stats prometheus.Registerer) (*redis.Ring, error) {
	password, err := c.PasswordFile.Pass()
	if err != nil {
		return nil, fmt.Errorf("loading password: %w", err)
	}

	tlsConfig, err := c.TLS.Load(stats)
	if err != nil {
		return nil, fmt.Errorf("loading TLS config: %w", err)
	}

	return redis.NewRing(&redis.RingOptions{
		Addrs:     c.ShardAddrs,
		Username:  c.Username,
		Password:  password,
		TLSConfig: tlsConfig,

		MaxRetries:      c.MaxRetries,
		MinRetryBackoff: c.MinRetryBackoff.Duration,
		MaxRetryBackoff: c.MaxRetryBackoff.Duration,
		DialTimeout:     c.DialTimeout.Duration,
		ReadTimeout:     c.ReadTimeout.Duration,
		WriteTimeout:    c.WriteTimeout.Duration,

		PoolSize:        c.PoolSize,
		MinIdleConns:    c.MinIdleConns,
		ConnMaxLifetime: c.MaxConnAge.Duration,
		PoolTimeout:     c.PoolTimeout.Duration,
		ConnMaxIdleTime: c.IdleTimeout.Duration,
	}), nil
}

// NewRingWithPeriodicLookups returns a new Redis ring client whose shards are
// periodically updated via SRV lookups. An initial SRV lookup is performed to
// populate the Redis ring shards. If this lookup fails or otherwise results in
// an empty set of resolved shards, an error is returned.
func (c *Config) NewRingWithPeriodicLookups(stats prometheus.Registerer, logger blog.Logger) (*redis.Ring, *Lookup, error) {
	ring, err := c.NewRing(stats)
	if err != nil {
		return nil, nil, err
	}

	lookup, err := newLookup(c.Lookups, c.LookupDNSAuthority, c.LookupTimeout.Duration, ring, logger, stats)
	if err != nil {
		return nil, nil, err
	}

	return ring, lookup, nil
}
