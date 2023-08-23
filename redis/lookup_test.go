package redis

import (
	"context"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"

	"github.com/redis/go-redis/v9"
)

func newTestRedisRing() *redis.Ring {
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
		Username:  "unittest-rw",
		Password:  "824968fa490f4ecec1e52d5e34916bdb60d45f8d",
		TLSConfig: tlsConfig2,
	})
	return client
}

func Test_Lookup(t *testing.T) {
	t.Parallel()

	logger := blog.NewMock()
	ring := newTestRedisRing()

	lookup := NewLookup([]cmd.ServiceDomain{
		{
			Service: "redisratelimits",
			Domain:  "service.consul",
		},
	},
		"consul.service.consul",
		250*time.Millisecond,
		ring,
		logger,
	)

	testCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lookup.Start(testCtx)

	// The Consul service entry for 'redisratelimits' is configured to return
	// two SRV targets. We should only have two shards in the ring.
	test.Assert(t, ring.Len() == 2, "Expected 2 shards in the ring")

	// Ensure we can reach both shards using the PING command.
	err := ring.ForEachShard(testCtx, func(ctx context.Context, shard *redis.Client) error {
		return shard.Ping(ctx).Err()
	})
	test.AssertNotError(t, err, "Expected PING to succeed for both shards")

	// Drop both Shards from the ring.
	ring.SetAddrs(map[string]string{})
	test.Assert(t, ring.Len() == 0, "Expected 0 shards in the ring")

	// Sleep 300ms to allow the periodic lookup to run.
	time.Sleep(300 * time.Millisecond)

	// The ring should now have two shards again.
	test.Assert(t, ring.Len() == 2, "Expected 2 shards in the ring")
}

func Test_LookupWithOneFailingSRV(t *testing.T) {
	t.Parallel()

	logger := blog.NewMock()
	ring := newTestRedisRing()

	lookup := NewLookup([]cmd.ServiceDomain{
		{
			Service: "doesnotexist",
			Domain:  "service.consuls",
		},
		{
			Service: "redisratelimits",
			Domain:  "service.consul",
		},
	},
		"consul.service.consul",
		250*time.Millisecond,
		ring,
		logger,
	)

	testCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lookup.Start(testCtx)

	// The Consul service entry for 'redisratelimits' is configured to return
	// two SRV targets. We should only have two shards in the ring.
	test.Assert(t, ring.Len() == 2, "Expected 2 shards in the ring")

	// No error message should have been logged for 'doesnotexist' because some
	// SRV targets were found for 'redisratelimits'.
	noExist := logger.GetAllMatching(".*doesnotexist.*")
	test.Assert(t, len(noExist) == 0, "Expected no error message for doesnotexist")
}

func Test_LookupWithAllFailingSRV(t *testing.T) {
	t.Parallel()

	logger := blog.NewMock()
	ring := newTestRedisRing()

	// Arrest panic.
	defer func() {
		r := recover()
		test.AssertNil(t, r, "Expected NewLookup with all failing SRV lookups to panic")
	}()

	NewLookup([]cmd.ServiceDomain{
		{
			Service: "doesnotexist",
			Domain:  "service.consuls",
		},
		{
			Service: "doesnotexist2",
			Domain:  "service.consuls",
		},
	},
		"consul.service.consul",
		250*time.Millisecond,
		ring,
		logger,
	)
}
