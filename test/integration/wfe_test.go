package integration

import (
	"net/http"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

// TestWFECORS is a small integration test that checks that the
// Access-Control-Allow-Origin header is returned for a GET request to the
// directory endpoint that has an Origin request header of "*".
func TestWFECORS(t *testing.T) {
	// Construct a GET request with an Origin header to sollicit an
	// Access-Control-Allow-Origin response header.
	getReq, _ := http.NewRequest("GET", "http://boulder:4001/directory", nil)
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
