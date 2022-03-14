package sa

import (
	"context"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/rocsp"
	"github.com/letsencrypt/boulder/test"
)

func TestStoreOCSPRedis(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()
	response := []byte{0, 0, 1}
	ctx := context.Background()
	err := sa.storeOCSPRedis(ctx, response, 58923463773186183, time.Hour)
	test.AssertNotError(t, err, "unexpected error")
}

func TestStoreOCSPRedisInvalidIssuer(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()
	response := []byte{0, 0, 1}
	ctx := context.Background()
	// 1234 is expected to not be a valid issuerID
	err := sa.storeOCSPRedis(ctx, response, 1234, time.Hour)
	test.AssertContains(t, err.Error(), "no issuer found for an ID in certificateStatus: 1234")
}

func TestStoreOCSPRedisFail(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()
	sa.rocspWriteClient = rocsp.NewMockWriteFailClient()
	response := []byte{0, 0, 1}
	ctx := context.Background()
	err := sa.storeOCSPRedis(ctx, response, 58923463773186183, time.Hour)
	test.AssertContains(t, err.Error(), "could not store response")
}
