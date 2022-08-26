package crl

import (
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/test"
)

func TestId(t *testing.T) {
	thisUpdate := time.Now()
	out, err := Id(1337, Number(thisUpdate), 1)
	test.AssertNotError(t, err, "Failed to create CRLId")
	expectCRLId := fmt.Sprintf("{\"issuerID\":1337,\"crlNumber\":%d,\"shardIdx\":1}", big.NewInt(thisUpdate.UnixNano()))
	test.AssertEquals(t, string(out), expectCRLId)
}
