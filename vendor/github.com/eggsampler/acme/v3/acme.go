package acme

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	// LetsEncryptProduction holds the production directory url
	LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"

	// LetsEncryptStaging holds the staging directory url
	LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"

	// ZeroSSLProduction holds the ZeroSSL directory url
	ZeroSSLProduction = "https://acme.zerossl.com/v2/DV90"

	userAgentString = "eggsampler-acme/v3 Go-http-client/1.1"
)

// NewClient creates a new acme client given a valid directory url.
func NewClient(directoryURL string, options ...OptionFunc) (Client, error) {
	// Set a default http timeout of 60 seconds, this can be overridden
	// via an OptionFunc eg: acme.NewClient(url, WithHTTPTimeout(10 * time.Second))
	httpClient := &http.Client{
		Timeout: 60 * time.Second,
	}

	acmeClient := Client{
		httpClient: httpClient,
		nonces:     &nonceStack{},
		retryCount: 5,
	}

	acmeClient.dir.URL = directoryURL

	for _, opt := range options {
		if err := opt(&acmeClient); err != nil {
			return acmeClient, fmt.Errorf("acme: error setting option: %v", err)
		}
	}

	if _, err := acmeClient.get(directoryURL, &acmeClient.dir, http.StatusOK); err != nil {
		return acmeClient, err
	}

	return acmeClient, nil
}

// Directory is the object returned by the client connecting to a directory url.
func (c Client) Directory() Directory {
	return c.dir
}

// Helper function to get the poll interval and poll timeout, defaulting if 0
func (c Client) getPollingDurations() (time.Duration, time.Duration) {
	pollInterval := c.PollInterval
	if pollInterval == 0 {
		pollInterval = 500 * time.Millisecond
	}
	pollTimeout := c.PollTimeout
	if pollTimeout == 0 {
		pollTimeout = 30 * time.Second
	}
	return pollInterval, pollTimeout
}

// Helper function to have a central point for performing http requests. Stores
// any returned nonces in the stack. The caller is responsible for closing the
// body so they can read the response.
func (c Client) do(req *http.Request, addNonce bool) (*http.Response, error) {
	// identifier for this client, as well as the default go user agent
	if c.userAgentSuffix != "" {
		req.Header.Set("User-Agent", userAgentString+" "+c.userAgentSuffix)
	} else {
		req.Header.Set("User-Agent", userAgentString)
	}

	if c.acceptLanguage != "" {
		req.Header.Set("Accept-Language", c.acceptLanguage)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return resp, err
	}

	if addNonce {
		c.nonces.push(resp.Header.Get("Replay-Nonce"))
	}

	return resp, nil
}

// Helper function to perform an HTTP get request and read the body. The caller
// is responsible for closing the body so they can read the response.
func (c Client) getRaw(url string, expectedStatus ...int) (*http.Response, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("acme: error creating request: %v", err)
	}

	resp, err := c.do(req, true)
	if err != nil {
		return resp, nil, fmt.Errorf("acme: error fetching response: %v", err)
	}
	defer resp.Body.Close()

	if err := checkError(resp, expectedStatus...); err != nil {
		return resp, nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return resp, body, fmt.Errorf("acme: error reading response body: %v", err)
	}

	return resp, body, nil
}

// Helper function for performing a http get on an acme resource. The caller is
// responsible for closing the body so they can read the response.
func (c Client) get(url string, out interface{}, expectedStatus ...int) (*http.Response, error) {
	resp, body, err := c.getRaw(url, expectedStatus...)
	if err != nil {
		return resp, err
	}

	if len(body) > 0 && out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return resp, fmt.Errorf("acme: error parsing response body: %v", err)
		}
	}

	return resp, nil
}

func (c Client) nonce() (string, error) {
	nonce := c.nonces.pop()
	if nonce != "" {
		return nonce, nil
	}

	if c.dir.NewNonce == "" {
		return "", errors.New("acme: no new nonce url")
	}

	req, err := http.NewRequest("HEAD", c.dir.NewNonce, nil)
	if err != nil {
		return "", fmt.Errorf("acme: error creating new nonce request: %v", err)
	}

	resp, err := c.do(req, false)
	if err != nil {
		return "", fmt.Errorf("acme: error fetching new nonce: %v", err)
	}

	nonce = resp.Header.Get("Replay-Nonce")
	return nonce, nil
}

// Helper function to perform an HTTP post request and read the body. Will
// attempt to retry if error is badNonce. The caller is responsible for closing
// the body so they can read the response.
func (c Client) postRaw(retryCount int, requestURL, kid string, privateKey crypto.Signer, payload interface{}, expectedStatus []int) (*http.Response, []byte, error) {
	nonce, err := c.nonce()
	if err != nil {
		return nil, nil, err
	}

	data, err := jwsEncodeJSON(payload, privateKey, KeyID(kid), nonce, requestURL)
	if err != nil {
		return nil, nil, fmt.Errorf("acme: error encoding json payload: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, requestURL, bytes.NewReader(data))
	if err != nil {
		return nil, nil, fmt.Errorf("acme: error creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/jose+json")

	resp, err := c.do(req, true)
	if err != nil {
		return resp, nil, fmt.Errorf("acme: error sending request: %v", err)
	}
	defer resp.Body.Close()

	if err := checkError(resp, expectedStatus...); err != nil {
		prob, ok := err.(Problem)
		if !ok {
			// don't retry for an error we don't know about
			return resp, nil, err
		}
		if retryCount >= c.retryCount {
			// don't attempt to retry if too many retries
			return resp, nil, err
		}
		if strings.HasSuffix(prob.Type, ":badNonce") {
			// only retry if error is badNonce
			return c.postRaw(retryCount+1, requestURL, kid, privateKey, payload, expectedStatus)
		}
		return resp, nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return resp, body, fmt.Errorf("acme: error reading response body: %v", err)
	}

	return resp, body, nil
}

// Helper function for performing a http post to an acme resource. The caller is
// responsible for closing the body so they can read the response.
func (c Client) post(requestURL, keyID string, privateKey crypto.Signer, payload interface{}, out interface{}, expectedStatus ...int) (*http.Response, error) {
	resp, body, err := c.postRaw(0, requestURL, keyID, privateKey, payload, expectedStatus)
	if err != nil {
		return resp, err
	}

	if _, b := os.LookupEnv("ACME_DEBUG_POST"); b {
		fmt.Println()
		fmt.Println("========= " + requestURL)
		fmt.Println(string(body))
		fmt.Println()
	}

	if len(body) > 0 && out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return resp, fmt.Errorf("acme: error parsing response: %v - %s", err, string(body))
		}
	}

	return resp, nil
}

var regLink = regexp.MustCompile(`<(.+?)>;\s*rel="(.+?)"`)

// Fetches a http Link header from an http response and closes the body.
func fetchLink(resp *http.Response, wantedLink string) string {
	if resp == nil {
		return ""
	}
	linkHeader := resp.Header["Link"]
	if len(linkHeader) == 0 {
		return ""
	}
	for _, l := range linkHeader {
		matches := regLink.FindAllStringSubmatch(l, -1)
		for _, m := range matches {
			if len(m) != 3 {
				continue
			}
			if m[2] == wantedLink {
				return m[1]
			}
		}
	}
	return ""
}

// Fetch is a helper function to assist with POST-AS-GET requests
func (c Client) Fetch(account Account, requestURL string, result interface{}, expectedStatus ...int) error {
	if len(expectedStatus) == 0 {
		expectedStatus = []int{http.StatusOK}
	}
	_, err := c.post(requestURL, account.URL, account.PrivateKey, "", result, expectedStatus...)

	return err
}

// Fetches all http Link header from a http response
func fetchLinks(resp *http.Response, wantedLink string) []string {
	if resp == nil {
		return nil
	}
	linkHeader := resp.Header["Link"]
	if len(linkHeader) == 0 {
		return nil
	}
	var links []string
	for _, l := range linkHeader {
		matches := regLink.FindAllStringSubmatch(l, -1)
		for _, m := range matches {
			if len(m) != 3 {
				continue
			}
			if m[2] == wantedLink {
				links = append(links, m[1])
			}
		}
	}
	return links
}
