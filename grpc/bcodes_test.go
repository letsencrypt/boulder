package grpc

import (
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestErrors(t *testing.T) {
	test.AssertEquals(t, wrapError(nil, nil), nil)
	test.AssertEquals(t, unwrapError(nil, nil), nil)
}
