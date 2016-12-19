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

type akamaiServer struct {
	responseCode int
}

func (as *akamaiServer) akamaiHandler(w http.ResponseWriter, r *http.Request) {
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
	err = json.Unmarshal(body, &req)
	if err != nil {
		fmt.Printf("Failed to unmarshal request body: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	fmt.Printf("Request: %#v\n", req)
	var resp struct {
		HTTPStatus       int
		Detail           string
		EstimatedSeconds int
		PurgeID          string
	}
	resp.HTTPStatus = as.responseCode
	resp.Detail = "?"
	resp.EstimatedSeconds = 10
	resp.PurgeID = "?"

	for _, testURL := range req.Objects {
		if !strings.HasPrefix(testURL, "http://") {
			resp.HTTPStatus = http.StatusForbidden
		}
	}

	respBytes, err := json.Marshal(resp)
	if err != nil {
		fmt.Printf("Failed to marshal response body: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(as.responseCode)
	w.Write(respBytes)
}

func TestPurge(t *testing.T) {
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
