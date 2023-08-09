package ratelimits

import (
	"testing"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/metrics"

	"github.com/go-redis/redis/v8"
	"github.com/jmhodges/clock"
)

func makeClient(clk clock.FakeClock) *RedisSource {
	CACertFile := "../test/redis-tls/minica.pem"
	CertFile := "../test/redis-tls/boulder/cert.pem"
	KeyFile := "../test/redis-tls/boulder/key.pem"
	tlsConfig := cmd.TLSConfig{
		CACertFile: CACertFile,
		CertFile:   CertFile,
		KeyFile:    KeyFile,
	}
	tlsConfig2, err := tlsConfig.Load(metrics.NoopRegisterer)
	if err != nil {
		panic(err)
	}

	client := redis.NewRing(&redis.RingOptions{
		Addrs: map[string]string{
			"shard1": "10.33.33.4:4218",
			"shard2": "10.33.33.5:4218",
		},
		Username:  "unittest-rw",
		Password:  "824968fa490f4ecec1e52d5e34916bdb60d45f8d",
		TLSConfig: tlsConfig2,
	})
	return NewRedisSource(client, 5*time.Second, clk, metrics.NoopRegisterer)
}

func newRedisTestLimiter(t *testing.T, clk clock.FakeClock) *Limiter {
	return newTestLimiter(t, makeClient(clk), clk)
}
