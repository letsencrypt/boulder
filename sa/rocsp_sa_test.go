package sa

import (
	"context"
	"io/ioutil"
	"testing"

	"github.com/letsencrypt/boulder/rocsp"
	"github.com/letsencrypt/boulder/test"
)

func getOCSPResponse() ([]byte, error) {
	return ioutil.ReadFile("testdata/ocsp.response")
}

func TestStoreOCSPRedis(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()
	response, err := getOCSPResponse()
	test.AssertNotError(t, err, "unexpected error")
	ctx := context.Background()
	err = sa.storeOCSPRedis(ctx, response, 58923463773186183)
	test.AssertNotError(t, err, "unexpected error")
}

func TestStoreOCSPRedisInvalidIssuer(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()
	response, err := getOCSPResponse()
	test.AssertNotError(t, err, "unexpected error")
	ctx := context.Background()
	// 1234 is expected to not be a valid issuerID
	err = sa.storeOCSPRedis(ctx, response, 1234)
	test.AssertContains(t, err.Error(), "no issuer found for an ID in certificateStatus: 1234")
}

func TestStoreOCSPRedisFail(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()
	sa.rocspWriteClient = rocsp.NewMockWriteFailClient()
	response, err := getOCSPResponse()
	test.AssertNotError(t, err, "unexpected error")
	ctx := context.Background()
	err = sa.storeOCSPRedis(ctx, response, 58923463773186183)
	test.AssertContains(t, err.Error(), "could not store response")
}
