//go:build integration

package integration

import (
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/test"
)

// TestWFECORS is a small integration test that checks that the
// Access-Control-Allow-Origin header is returned for a GET request to the
// directory endpoint that has an Origin request header of "*".
func TestWFECORS(t *testing.T) {
	// Construct a GET request with an Origin header to sollicit an
	// Access-Control-Allow-Origin response header.
	getReq, _ := http.NewRequest("GET", "http://boulder.service.consul:4001/directory", nil)
	getReq.Header.Set("Origin", "*")

	// Performing the GET should return status 200.
	client := &http.Client{}
	resp, err := client.Do(getReq)
	test.AssertNotError(t, err, "GET directory")
	test.AssertEquals(t, resp.StatusCode, http.StatusOK)

	// We expect that the response has the correct Access-Control-Allow-Origin
	// header.
	corsAllowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	test.AssertEquals(t, corsAllowOrigin, "*")
}

// TestWFEHTTPMetrics verifies that the measured_http metrics we collect
// for boulder-wfe and boulder-wfe2 are being properly collected. In order
// to initialize the prometheus metrics we make a call to the /directory
// endpoint before checking the /metrics endpoint.
func TestWFEHTTPMetrics(t *testing.T) {
	// Check boulder-wfe2
	resp, err := http.Get("http://boulder.service.consul:4001/directory")
	test.AssertNotError(t, err, "GET boulder-wfe2 directory")
	test.AssertEquals(t, resp.StatusCode, http.StatusOK)
	resp.Body.Close()

	resp, err = http.Get("http://boulder.service.consul:8013/metrics")
	test.AssertNotError(t, err, "GET boulder-wfe2 metrics")
	test.AssertEquals(t, resp.StatusCode, http.StatusOK)
	body, err := io.ReadAll(resp.Body)
	test.AssertNotError(t, err, "Reading boulder-wfe2 metrics response")
	test.AssertContains(t, string(body), `response_time_count{code="200",endpoint="/directory",method="GET"}`)
	resp.Body.Close()
}

// TestWFEHealthz checks to make sure that the /health endpoint returns 200 OK,
// retrying in case overrides take a moment to load.
func TestWFEHealthz(t *testing.T) {
	retries := 0
	var status int
	for retries < 5 {
		time.Sleep(core.RetryBackoff(retries, time.Millisecond*2, time.Millisecond*50, 2))
		resp, err := http.Get("http://boulder.service.consul:4001/healthz")
		test.AssertNotError(t, err, "GET boulder-wfe2 healthz")
		status = resp.StatusCode
		resp.Body.Close()
		if status == http.StatusOK {
			break
		}
		retries++
	}
	test.AssertEquals(t, status, http.StatusOK)
}
