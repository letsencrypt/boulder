package akamai

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"
)

const (
	v3PurgePath     = "/ccu/v3/delete/url/"
	v3PurgeTagPath  = "/ccu/v3/delete/tag/"
	timestampFormat = "20060102T15:04:05-0700"
)

type v3PurgeRequest struct {
	Objects []string `json:"objects"`
}

type purgeResponse struct {
	HTTPStatus       int    `json:"httpStatus"`
	Detail           string `json:"detail"`
	EstimatedSeconds int    `json:"estimatedSeconds"`
	PurgeID          string `json:"purgeId"`
}

// CachePurgeClient talks to the Akamai CCU REST API. It is safe to make concurrent
// purge requests.
type CachePurgeClient struct {
	client       *http.Client
	apiEndpoint  string
	apiHost      string
	apiScheme    string
	clientToken  string
	clientSecret string
	accessToken  string
	v3Network    string
	retries      int
	retryBackoff time.Duration
	log          blog.Logger
	purgeLatency prometheus.Histogram
	purges       *prometheus.CounterVec
	clk          clock.Clock
}

// errFatal is used by CachePurgeClient.purge to indicate that it failed for a
// reason that cannot be remediated by retrying a purge request
type errFatal string

func (e errFatal) Error() string { return string(e) }

var (
	// ErrAllRetriesFailed lets the caller of Purge to know if all the purge submission
	// attempts failed
	ErrAllRetriesFailed = errors.New("All attempts to submit purge request failed")
)

// NewCachePurgeClient constructs a new CachePurgeClient
func NewCachePurgeClient(
	endpoint,
	clientToken,
	clientSecret,
	accessToken string,
	v3Network string,
	retries int,
	retryBackoff time.Duration,
	log blog.Logger,
	stats prometheus.Registerer,
) (*CachePurgeClient, error) {
	purgeLatency := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "ccu_purge_latency",
		Help:    "Histogram of latencies of CCU purges",
		Buckets: metrics.InternetFacingBuckets,
	})
	stats.MustRegister(purgeLatency)
	purges := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ccu_purges",
		Help: "A counter of CCU purges labelled by the result",
	}, []string{"type"})
	stats.MustRegister(purges)

	endpoint = strings.TrimSuffix(endpoint, "/")
	apiURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	// The network string must be either "production" or "staging".
	if v3Network != "production" && v3Network != "staging" {
		return nil, fmt.Errorf(
			"Invalid CCU v3 network: %q. Must be \"staging\" or \"production\"", v3Network)
	}
	return &CachePurgeClient{
		client:       new(http.Client),
		apiEndpoint:  endpoint,
		apiHost:      apiURL.Host,
		apiScheme:    strings.ToLower(apiURL.Scheme),
		clientToken:  clientToken,
		clientSecret: clientSecret,
		accessToken:  accessToken,
		v3Network:    v3Network,
		retries:      retries,
		retryBackoff: retryBackoff,
		log:          log,
		clk:          clock.New(),
		purgeLatency: purgeLatency,
		purges:       purges,
	}, nil
}

// Akamai uses a special authorization header to identify clients to their EdgeGrid
// APIs, their docs (https://developer.akamai.com/introduction/Client_Auth.html)
// provide a  description of the required generation process.
func (cpc *CachePurgeClient) constructAuthHeader(body []byte, apiPath string, nonce string) (string, error) {
	// The akamai API is very time sensitive (recommending reliance on a stratum 2
	// or better time source) and, although it doesn't say it anywhere, really wants
	// the timestamp to be in the UTC timezone for some reason.
	timestamp := cpc.clk.Now().UTC().Format(timestampFormat)
	header := fmt.Sprintf(
		"EG1-HMAC-SHA256 client_token=%s;access_token=%s;timestamp=%s;nonce=%s;",
		cpc.clientToken,
		cpc.accessToken,
		timestamp,
		nonce,
	)
	bodyHash := sha256.Sum256(body)
	tbs := fmt.Sprintf(
		"%s\t%s\t%s\t%s\t%s\t%s\t%s",
		"POST",
		cpc.apiScheme,
		cpc.apiHost,
		apiPath,
		"", // We don't need to send any signed headers for a purge so this can be blank
		base64.StdEncoding.EncodeToString(bodyHash[:]),
		header,
	)

	cpc.log.Debugf("To-be-signed Akamai EdgeGrid authentication: %q", tbs)

	h := hmac.New(sha256.New, signingKey(cpc.clientSecret, timestamp))
	h.Write([]byte(tbs))
	return fmt.Sprintf(
		"%ssignature=%s",
		header,
		base64.StdEncoding.EncodeToString(h.Sum(nil)),
	), nil
}

// signingKey makes a signing key by HMAC'ing the timestamp
// using a client secret as the key.
func signingKey(clientSecret string, timestamp string) []byte {
	h := hmac.New(sha256.New, []byte(clientSecret))
	h.Write([]byte(timestamp))
	key := make([]byte, base64.StdEncoding.EncodedLen(32))
	base64.StdEncoding.Encode(key, h.Sum(nil))
	return key
}

func (cpc *CachePurgeClient) PurgeTags(tags []string) error {
	purgeReq := v3PurgeRequest{
		Objects: tags,
	}
	endpoint := fmt.Sprintf("%s%s%s", cpc.apiEndpoint, v3PurgeTagPath, cpc.v3Network)
	return cpc.authedRequest(endpoint, purgeReq)
}

// purge actually sends the individual requests to the Akamai endpoint and checks
// if they are successful
func (cpc *CachePurgeClient) purge(urls []string) error {
	purgeReq := v3PurgeRequest{
		Objects: urls,
	}
	endpoint := fmt.Sprintf("%s%s%s", cpc.apiEndpoint, v3PurgePath, cpc.v3Network)
	return cpc.authedRequest(endpoint, purgeReq)
}

// POST to the given URL with the body that results from json.Marshal'ing `body`,
// using the Akamai authentication mechanism.
func (cpc *CachePurgeClient) authedRequest(target string, requestBody interface{}) error {
	reqJSON, err := json.Marshal(requestBody)
	if err != nil {
		return errFatal(err.Error())
	}
	req, err := http.NewRequest(
		"POST",
		target,
		bytes.NewBuffer(reqJSON),
	)
	if err != nil {
		return errFatal(err.Error())
	}

	parsedTarget, err := url.Parse(target)
	if err != nil {
		return errFatal(fmt.Sprintf("parsing url %q: %s", target, err))
	}

	// Create authorization header for request
	authHeader, err := cpc.constructAuthHeader(
		reqJSON,
		parsedTarget.Path,
		core.RandomString(16),
	)
	if err != nil {
		return errFatal(err.Error())
	}
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Content-Type", "application/json")

	cpc.log.Debugf("POSTing to %s with Authorization %s: %s",
		target, authHeader, reqJSON)

	s := cpc.clk.Now()
	resp, err := cpc.client.Do(req)
	cpc.purgeLatency.Observe(cpc.clk.Since(s).Seconds())
	if err != nil {
		return err
	}
	if resp.Body == nil {
		return fmt.Errorf("No response body")
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		_ = resp.Body.Close()
		return err
	}
	err = resp.Body.Close()
	if err != nil {
		return err
	}

	// Check purge was successful
	var purgeInfo purgeResponse
	err = json.Unmarshal(body, &purgeInfo)
	if err != nil {
		return fmt.Errorf("response to %s: json.Unmarshal(%q): %w", target, body, err)
	}
	if purgeInfo.HTTPStatus != http.StatusCreated || resp.StatusCode != http.StatusCreated {
		if purgeInfo.HTTPStatus == http.StatusForbidden {
			return errFatal("Unauthorized to purge URLs")
		}
		return fmt.Errorf("Unexpected HTTP status code '%d': %s", resp.StatusCode, string(body))
	}

	cpc.log.AuditInfof("Sent successful purge request purgeID: %s, purge expected in: %ds, for request body: %s",
		purgeInfo.PurgeID, purgeInfo.EstimatedSeconds, reqJSON)

	return nil
}

func (cpc *CachePurgeClient) purgeBatch(urls []string) error {
	successful := false
	for i := 0; i <= cpc.retries; i++ {
		cpc.clk.Sleep(core.RetryBackoff(i, cpc.retryBackoff, time.Minute, 1.3))

		err := cpc.purge(urls)
		if err != nil {
			var errorFatal errFatal
			if errors.As(err, &errorFatal) {
				cpc.purges.WithLabelValues("fatal failure").Inc()
				return err
			}
			cpc.log.AuditErrf("Akamai cache purge failed, retrying: %s", err)
			cpc.purges.WithLabelValues("retryable failure").Inc()
			continue
		}
		successful = true
		break
	}

	if !successful {
		cpc.purges.WithLabelValues("fatal failure").Inc()
		return ErrAllRetriesFailed
	}

	cpc.purges.WithLabelValues("success").Inc()
	return nil
}

var akamaiBatchSize = 100

// Purge attempts to send a purge request to the Akamai CCU API cpc.retries number
//  of times before giving up and returning ErrAllRetriesFailed
func (cpc *CachePurgeClient) Purge(urls []string) error {
	for i := 0; i < len(urls); {
		sliceEnd := i + akamaiBatchSize
		if sliceEnd > len(urls) {
			sliceEnd = len(urls)
		}
		err := cpc.purgeBatch(urls[i:sliceEnd])
		if err != nil {
			return err
		}
		i += akamaiBatchSize
	}
	return nil
}

// CheckSignature is used for tests, it exported so that it can be used in akamai-test-srv
func CheckSignature(secret string, url string, r *http.Request, body []byte) error {
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
	hostPort := strings.Split(url, "://")[1]
	h := hmac.New(sha256.New, signingKey(secret, headerTimestamp))
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

func reverseBytes(b []byte) []byte {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

func generateOCSPCacheKeys(req []byte, ocspServer string) []string {
	hash := md5.Sum(req)
	encReq := base64.StdEncoding.EncodeToString(req)
	return []string{
		// Generate POST key, format is the URL that was POST'd to with a query string with
		// the parameter 'body-md5' and the value of the first two uint32s in little endian
		// order in hex of the MD5 hash of the OCSP request body.
		//
		// There is no public documentation of this feature that has been published by Akamai
		// as far as we are aware.
		fmt.Sprintf("%s?body-md5=%x%x", ocspServer, reverseBytes(hash[0:4]), reverseBytes(hash[4:8])),
		// RFC 2560 and RFC 5019 state OCSP GET URLs 'MUST properly url-encode the base64
		// encoded' request but a large enough portion of tools do not properly do this
		// (~10% of GET requests we receive) such that we must purge both the encoded
		// and un-encoded URLs.
		//
		// Due to Akamai proxy/cache behavior which collapses '//' -> '/' we also
		// collapse double slashes in the un-encoded URL so that we properly purge
		// what is stored in the cache.
		fmt.Sprintf("%s%s", ocspServer, strings.Replace(encReq, "//", "/", -1)),
		fmt.Sprintf("%s%s", ocspServer, url.QueryEscape(encReq)),
	}
}

// GeneratePurgeURLs generates akamai URLs that can be POSTed to in order to
// purge akamai's cache of the corresponding OCSP responses. The URLs encode
// the contents of the OCSP request, so this method constructs a full OCSP
// request.
func GeneratePurgeURLs(cert, issuer *x509.Certificate) ([]string, error) {
	req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, err
	}

	// Create a GET and special Akamai POST style OCSP url for each endpoint in cert.OCSPServer
	urls := []string{}
	for _, ocspServer := range cert.OCSPServer {
		if !strings.HasSuffix(ocspServer, "/") {
			ocspServer += "/"
		}
		urls = append(urls, generateOCSPCacheKeys(req, ocspServer)...)
	}
	return urls, nil
}
