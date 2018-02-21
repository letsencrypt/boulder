package akamai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jmhodges/clock"

	blog "github.com/letsencrypt/boulder/log"
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
		"production",
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
		fmt.Sprintf("%s%s", cpc.apiEndpoint, v2PurgePath),
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

type akamaiServer struct {
	responseCode int
	v3           bool
}

func (as *akamaiServer) sendResponse(w http.ResponseWriter, resp purgeResponse) {
	respBytes, err := json.Marshal(resp)
	if err != nil {
		fmt.Printf("Failed to marshal response body: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(as.responseCode)
	w.Write(respBytes)
}

func (as *akamaiServer) akamaiHandler(w http.ResponseWriter, r *http.Request) {
	// Enforce the request path based on the API version we're emulating
	if (as.v3 == false && r.URL.Path != v2PurgePath) ||
		(as.v3 == true && !strings.HasPrefix(r.URL.Path, v3PurgePath)) {
		resp := purgeResponse{
			HTTPStatus: http.StatusNotFound,
			Detail:     fmt.Sprintf("Invalid path: %q", r.URL.Path),
		}
		as.sendResponse(w, resp)
		return
	}

	var req struct {
		Objects []string
		Type    string
		Action  string
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("Failed to read request body: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Enforce that a V3 request is well formed and does not include the "Type"
	// and "Action" fields used by the V2 api.
	if as.v3 == true && (req.Type != "" || req.Action != "") {
		resp := purgeResponse{
			HTTPStatus: http.StatusBadRequest,
			Detail:     fmt.Sprintf("Invalid request body: included V2 Type %q and Action %q\n", req.Type, req.Action),
		}
		as.sendResponse(w, resp)
		return
	}

	err = json.Unmarshal(body, &req)
	if err != nil {
		fmt.Printf("Failed to unmarshal request body: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp := purgeResponse{
		HTTPStatus:       as.responseCode,
		Detail:           "?",
		EstimatedSeconds: 10,
		PurgeID:          "?",
	}

	for _, testURL := range req.Objects {
		if !strings.HasPrefix(testURL, "http://") {
			resp.HTTPStatus = http.StatusForbidden
			break
		}
	}
	as.sendResponse(w, resp)
}

// TestV2Purge tests the legacy CCU v2 Akamai API used when the v3Network
// parameter to NewCachePurgeClient is "".
func TestV2Purge(t *testing.T) {
	log := blog.NewMock()

	as := akamaiServer{responseCode: http.StatusCreated}
	m := http.NewServeMux()
	server := httptest.NewUnstartedServer(m)
	m.HandleFunc("/", as.akamaiHandler)
	server.Start()

	client, err := NewCachePurgeClient(
		server.URL,
		"token",
		"secret",
		"accessToken",
		"",
		3,
		time.Second,
		log,
		metrics.NewNoopScope(),
	)
	test.AssertNotError(t, err, "Failed to create CachePurgeClient")
	fc := clock.NewFake()
	client.clk = fc

	err = client.Purge([]string{"http://test.com"})
	test.AssertNotError(t, err, "Purge failed with 201 response")

	started := fc.Now()
	as.responseCode = http.StatusInternalServerError
	err = client.Purge([]string{"http://test.com"})
	test.AssertError(t, err, "Purge didn't fail with 400 response")
	test.Assert(t, fc.Since(started) > (time.Second*4), "Retries should've taken at least 4.4 seconds")

	started = fc.Now()
	as.responseCode = http.StatusCreated
	err = client.Purge([]string{"http:/test.com"})
	test.AssertError(t, err, "Purge didn't fail with 403 response from malformed URL")
	test.Assert(t, fc.Since(started) < time.Second, "Purge should've failed out immediately")
}

// TestV3Purge tests the Akamai CCU v3 purge API by setting the v3Network
// parameter to "production".
func TestV3Purge(t *testing.T) {
	log := blog.NewMock()

	as := akamaiServer{
		responseCode: http.StatusCreated,
		v3:           true,
	}
	m := http.NewServeMux()
	server := httptest.NewUnstartedServer(m)
	m.HandleFunc("/", as.akamaiHandler)
	server.Start()

	// Client is a purge client with a "production" v3Network parameter
	client, err := NewCachePurgeClient(
		server.URL,
		"token",
		"secret",
		"accessToken",
		"production",
		3,
		time.Second,
		log,
		metrics.NewNoopScope(),
	)
	test.AssertNotError(t, err, "Failed to create CachePurgeClient")
	client.clk = clock.NewFake()

	err = client.Purge([]string{"http://test.com"})
	test.AssertNotError(t, err, "Purge failed with 201 response")

	started := client.clk.Now()
	as.responseCode = http.StatusInternalServerError
	err = client.Purge([]string{"http://test.com"})
	test.AssertError(t, err, "Purge didn't fail with 400 response")
	test.Assert(t, client.clk.Since(started) > (time.Second*4), "Retries should've taken at least 4.4 seconds")

	started = client.clk.Now()
	as.responseCode = http.StatusCreated
	err = client.Purge([]string{"http:/test.com"})
	test.AssertError(t, err, "Purge didn't fail with 403 response from malformed URL")
	test.Assert(t, client.clk.Since(started) < time.Second, "Purge should've failed out immediately")
}

func TestNewCachePurgeClient(t *testing.T) {
	log := blog.NewMock()
	m := http.NewServeMux()
	server := httptest.NewUnstartedServer(m)

	// Creating a new cache purge client with an invalid "network" parameter should error
	_, err := NewCachePurgeClient(
		server.URL,
		"token",
		"secret",
		"accessToken",
		"fake",
		3,
		time.Second,
		log,
		metrics.NewNoopScope(),
	)
	test.AssertError(t, err, "NewCachePurgeClient with invalid network parameter didn't error")

	// Creating a new cache purge client with a valid "network" parameter shouldn't error
	_, err = NewCachePurgeClient(
		server.URL,
		"token",
		"secret",
		"accessToken",
		"staging",
		3,
		time.Second,
		log,
		metrics.NewNoopScope(),
	)
	test.AssertNotError(t, err, "NewCachePurgeClient with valid network parameter errored")

	// Creating a new cache purge client with an invalid server URL parameter should error
	_, err = NewCachePurgeClient(
		"h&amp;ttp://whatever",
		"token",
		"secret",
		"accessToken",
		"staging",
		3,
		time.Second,
		log,
		metrics.NewNoopScope(),
	)
	test.AssertError(t, err, "NewCachePurgeClient with invalid server url parameter didn't error")
}
