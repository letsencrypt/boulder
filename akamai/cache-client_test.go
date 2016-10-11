package akamai

import (
	"bytes"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
)

func TestConstructAuthHeader(t *testing.T) {
	stats := metrics.NewNoopScope()
	cpc, err := NewCachePurgeClient(
		"https://akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net",
		"akab-client-token-xxx-xxxxxxxxxxxxxxxx",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=",
		"akab-access-token-xxx-xxxxxxxxxxxxxxxx",
		0,
		time.Second,
		nil,
		stats,
	)
	test.AssertNotError(t, err, "Failed to create cache purge client")
	fc := clock.NewFake()
	cpc.clk = fc
	wantedTimestamp, err := time.Parse(timestampFormat, "20140321T19:34:21+0000")
	test.AssertNotError(t, err, "Failed to parse timestamp")
	fc.Add(wantedTimestamp.Sub(fc.Now()))

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s%s", cpc.apiEndpoint, purgePath),
		bytes.NewBuffer([]byte{0}),
	)
	test.AssertNotError(t, err, "Failed to create request")

	expectedHeader := "EG1-HMAC-SHA256 client_token=akab-client-token-xxx-xxxxxxxxxxxxxxxx;access_token=akab-access-token-xxx-xxxxxxxxxxxxxxxx;timestamp=20140321T19:34:21+0000;nonce=nonce-xx-xxxx-xxxx-xxxx-xxxxxxxxxxxx;signature=hXm4iCxtpN22m4cbZb4lVLW5rhX8Ca82vCFqXzSTPe4="
	authHeader, err := cpc.constructAuthHeader(
		req,
		[]byte("datadatadatadatadatadatadatadata"),
		"/testapi/v1/t3",
		"nonce-xx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
	)
	test.AssertNotError(t, err, "Failed to create authorization header")
	test.AssertEquals(t, authHeader, expectedHeader)
}
