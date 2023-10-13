package ratelimits

import (
	"testing"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
	"golang.org/x/net/context"

	"github.com/jmhodges/clock"
	"github.com/redis/go-redis/v9"
)

func newTestRedisSource(clk clock.FakeClock, addrs map[string]string) *RedisSource {
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
		Addrs:     addrs,
		Username:  "unittest-rw",
		Password:  "824968fa490f4ecec1e52d5e34916bdb60d45f8d",
		TLSConfig: tlsConfig2,
	})
	return NewRedisSource(client, clk, metrics.NoopRegisterer)
}

func newRedisTestLimiter(t *testing.T, clk clock.FakeClock) *Limiter {
	return newTestLimiter(t, newTestRedisSource(clk, map[string]string{
		"shard1": "10.33.33.4:4218",
		"shard2": "10.33.33.5:4218",
	}), clk)
}

func Test_RedisSource_Ping(t *testing.T) {
	clk := clock.NewFake()
	workingSource := newTestRedisSource(clk, map[string]string{
		"shard1": "10.33.33.4:4218",
		"shard2": "10.33.33.5:4218",
	})

	err := workingSource.Ping(context.Background())
	test.AssertNotError(t, err, "Ping should not error")

	missingFirstShardSource := newTestRedisSource(clk, map[string]string{
		"shard1": "10.33.33.4:1337",
		"shard2": "10.33.33.5:4218",
	})

	err = missingFirstShardSource.Ping(context.Background())
	test.AssertError(t, err, "Ping should not error")

	missingSecondShardSource := newTestRedisSource(clk, map[string]string{
		"shard1": "10.33.33.4:4218",
		"shard2": "10.33.33.5:1337",
	})

	err = missingSecondShardSource.Ping(context.Background())
	test.AssertError(t, err, "Ping should not error")
}
