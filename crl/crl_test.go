package crl

import (
	"math/big"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestId(t *testing.T) {
	out, err := Id(1337, Number(42), 1)
	test.AssertNotError(t, err, "Failed to create CRLId")
	test.AssertEquals(t, out.String(), "{\"issuerID\":1337,\"crlNum\":42,\"shardIdx\":1}")
}

func TestNumber(t *testing.T) {
	out := Number(42)
	test.AssertDeepEquals(t, *out, *big.NewInt(42))
}
