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
	err = sa.storeOCSPRedis(ctx, response)
	test.AssertNotError(t, err, "unexpected error")
}

func TestStoreOCSPRedisFail(t *testing.T) {
	sa, _, cleanUp := initSA(t)
	defer cleanUp()
	sa.rocspWriteClient = rocsp.NewMockWriteFailClient()
	response, err := getOCSPResponse()
	test.AssertNotError(t, err, "unexpected error")
	ctx := context.Background()
	err = sa.storeOCSPRedis(ctx, response)
	test.AssertContains(t, err.Error(), "could not store response")
}
