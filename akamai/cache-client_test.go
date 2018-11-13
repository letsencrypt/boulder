package akamai

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
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
	log := blog.NewMock()
	stats := metrics.NewNoopScope()
	cpc, err := NewCachePurgeClient(
		"https://akaa-baseurl-xxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net",
		"akab-client-token-xxx-xxxxxxxxxxxxxxxx",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=",
		"akab-access-token-xxx-xxxxxxxxxxxxxxxx",
		"production",
		0,
		time.Second,
		log,
		stats,
	)
	test.AssertNotError(t, err, "Failed to create cache purge client")
	fc := clock.NewFake()
	cpc.clk = fc
	wantedTimestamp, err := time.Parse(timestampFormat, "20140321T19:34:21+0000")

	test.AssertNotError(t, err, "Failed to parse timestamp")
	fc.Set(wantedTimestamp)

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
	*httptest.Server
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

	err = as.checkSignature(r, body)
	if err != nil {
		fmt.Printf("Error checking signature: %s\n", err)
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

func (as *akamaiServer) checkSignature(r *http.Request, body []byte) error {
	bodyHash := sha256.Sum256(body)
	bodyHashB64 := base64.StdEncoding.EncodeToString(bodyHash[:])

	authorization := r.Header.Get("Authorization")
	authValues := make(map[string]string)
	for _, v := range strings.Split(authorization, ";") {
		splitValue := strings.Split(v, "=")
		authValues[splitValue[0]] = splitValue[1]
	}
	headerTimestamp := authValues["timestamp"]
	splitHeader := strings.Split(authorization, "signature=")
	shortenedHeader, signature := splitHeader[0], splitHeader[1]
	hostPort := strings.Split(as.URL, "://")[1]
	// Assume all unittests use "secret" as the client secret.
	h := hmac.New(sha256.New, signingKey("secret", headerTimestamp))
	input := []byte(fmt.Sprintf("POST\thttp\t%s\t%s\t\t%s\t%s",
		hostPort,
		r.URL.Path,
		bodyHashB64,
		shortenedHeader,
	))
	h.Write(input)
	expectedSignature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	if signature != expectedSignature {
		return fmt.Errorf("Wrong signature %q in %q. Expected %q\n",
			signature, authorization, expectedSignature)
	}
	return nil
}

func newAkamaiServer(code int, v3 bool) *akamaiServer {
	m := http.NewServeMux()
	as := akamaiServer{
		responseCode: code,
		v3:           v3,
		Server:       httptest.NewServer(m),
	}
	m.HandleFunc("/", as.akamaiHandler)
	return &as
}

// TestV2Purge tests the legacy CCU v2 Akamai API used when the v3Network
// parameter to NewCachePurgeClient is "".
func TestV2Purge(t *testing.T) {
	log := blog.NewMock()

	as := newAkamaiServer(http.StatusCreated, false)
	defer as.Close()

	client, err := NewCachePurgeClient(
		as.URL,
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
	as := newAkamaiServer(http.StatusCreated, true)
	defer as.Close()

	// Client is a purge client with a "production" v3Network parameter
	client, err := NewCachePurgeClient(
		as.URL,
		"token",
		"secret",
		"accessToken",
		"production",
		3,
		time.Second,
		blog.NewMock(),
		metrics.NewNoopScope(),
	)
	test.AssertNotError(t, err, "Failed to create CachePurgeClient")
	fc := clock.NewFake()
	client.clk = fc

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
	// Creating a new cache purge client with an invalid "network" parameter should error
	_, err := NewCachePurgeClient(
		"http://127.0.0.1:9000/",
		"token",
		"secret",
		"accessToken",
		"fake",
		3,
		time.Second,
		blog.NewMock(),
		metrics.NewNoopScope(),
	)
	test.AssertError(t, err, "NewCachePurgeClient with invalid network parameter didn't error")

	// Creating a new cache purge client with a valid "network" parameter shouldn't error
	_, err = NewCachePurgeClient(
		"http://127.0.0.1:9000/",
		"token",
		"secret",
		"accessToken",
		"staging",
		3,
		time.Second,
		blog.NewMock(),
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
		blog.NewMock(),
		metrics.NewNoopScope(),
	)
	test.AssertError(t, err, "NewCachePurgeClient with invalid server url parameter didn't error")
}

func TestBigBatchPurge(t *testing.T) {
	log := blog.NewMock()

	m := http.NewServeMux()
	as := akamaiServer{
		responseCode: http.StatusCreated,
		v3:           true,
		Server:       httptest.NewUnstartedServer(m),
	}
	m.HandleFunc("/", as.akamaiHandler)
	as.Start()

	client, err := NewCachePurgeClient(
		as.URL,
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

	var urls []string
	for i := 0; i < 250; i++ {
		urls = append(urls, fmt.Sprintf("http://test.com/%d", i))
	}

	err = client.Purge(urls)
	test.AssertNotError(t, err, "Purge failed with 201 response")
}
