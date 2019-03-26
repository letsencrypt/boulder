package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	"net/http"
	"time"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test/load-generator/acme"

	"gopkg.in/square/go-jose.v2"
)

var (
	// stringToOperation maps a configured plan action to a function that can
	// operate on a state/context.
	stringToOperation = map[string]func(*State, *context) error{
		"newAccount":    newAccount,
		"getAccount":    getAccount,
		"newOrder":      newOrder,
		"fulfillOrder":  fulfillOrder,
		"finalizeOrder": finalizeOrder,
	}
)

// It's awkward to work with core.Order or corepb.Order when the API returns
// a different object than either of these types can represent without
// converting field values. The WFE uses an unexported `orderJSON` type for the
// API results that contain an order. We duplicate it here instead of moving it
// somewhere exported for this one utility.
type OrderJSON struct {
	// The URL field isn't returned by the API, we populate it manually with the
	// `Location` header.
	URL            string
	Status         core.AcmeStatus       `json:"status"`
	Expires        time.Time             `json:"expires"`
	Identifiers    []core.AcmeIdentifier `json:"identifiers"`
	Authorizations []string              `json:"authorizations"`
	Finalize       string                `json:"finalize"`
	Certificate    string                `json:"certificate,omitempty"`
	Error          *probs.ProblemDetails `json:"error,omitempty"`
}

// getAccount takes a randomly selected v2 account from `state.accts` and puts it
// into `ctx.acct`. The context `nonceSource` is also populated as convenience.
func getAccount(s *State, ctx *context) error {
	s.rMu.RLock()
	defer s.rMu.RUnlock()

	// There must be an existing v2 account in the state
	if len(s.accts) == 0 {
		return errors.New("no accounts to return")
	}

	// Select a random account from the state and put it into the context
	ctx.acct = s.accts[mrand.Intn(len(s.accts))]
	ctx.ns = &nonceSource{s: s}
	return nil
}

// newAccount puts a V2 account into the provided context. If the state provided
// has too many accounts already (based on `state.NumAccts` and `state.maxRegs`)
// then `newAccount` puts an existing account from the state into the context,
// otherwise it creates a new account and puts it into both the state and the
// context.
func newAccount(s *State, ctx *context) error {
	// Check the max regs and if exceeded, just return an existing account instead
	// of creating a new one.
	if s.maxRegs != 0 && s.numAccts() >= s.maxRegs {
		return getAccount(s, ctx)
	}

	// Create a random signing key
	signKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	ctx.acct = &account{
		key: signKey,
	}
	ctx.ns = &nonceSource{s: s}

	// Prepare an account registration message body
	reqBody := struct {
		ToSAgreed bool `json:"termsOfServiceAgreed"`
		Contact   []string
	}{
		ToSAgreed: true,
	}
	// Set the account contact email if configured
	if s.email != "" {
		reqBody.Contact = []string{fmt.Sprintf("mailto:%s", s.email)}
	}
	reqBodyStr, err := json.Marshal(&reqBody)
	if err != nil {
		return err
	}

	// Sign the new account registration body using a JWS with an embedded JWK
	// because we do not have a key ID from the server yet.
	newAccountURL := s.directory.EndpointURL(acme.NewAccountEndpoint)
	jws, err := ctx.signEmbeddedV2Request(reqBodyStr, newAccountURL)
	if err != nil {
		return err
	}
	bodyBuf := []byte(jws.FullSerialize())

	// POST the account creation request to the server
	nStarted := time.Now()
	resp, err := s.post(newAccountURL, bodyBuf, ctx.ns)
	nFinished := time.Now()
	nState := "error"
	defer func() {
		s.callLatency.Add(
			fmt.Sprintf("POST %s", acme.NewAccountEndpoint), nStarted, nFinished, nState)
	}()
	if err != nil {
		return fmt.Errorf("%s, post failed: %s", newAccountURL, err)
	}
	defer resp.Body.Close()

	// We expect that the result is a created account
	if resp.StatusCode != http.StatusCreated {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("%s, bad response: %s", newAccountURL, body)
		}
		return fmt.Errorf("%s, bad response status %d: %s", newAccountURL, resp.StatusCode, body)
	}

	// Populate the context account's key ID with the Location header returned by
	// the server
	locHeader := resp.Header.Get("Location")
	if locHeader == "" {
		return fmt.Errorf("%s, bad response - no Location header with account ID", newAccountURL)
	}
	ctx.acct.id = locHeader

	// Add the account to the state
	nState = "good"
	s.addAccount(ctx.acct)
	return nil
}

// randDomain generates a random(-ish) domain name as a subdomain of the
// provided base domain.
func randDomain(base string) string {
	// This approach will cause some repeat domains but not enough to make rate
	// limits annoying!
	n := time.Now().UnixNano()
	b := new(bytes.Buffer)
	binary.Write(b, binary.LittleEndian, n)
	return fmt.Sprintf("%x.%s", sha1.Sum(b.Bytes()), base)
}

// newOrder creates a new pending order object for a random set of domains using
// the context's account.
func newOrder(s *State, ctx *context) error {
	// Pick a random number of names within the constraints of the maxNamesPerCert
	// parameter
	orderSize := 1 + mrand.Intn(s.maxNamesPerCert-1)
	// Generate that many random domain names. There may be some duplicates, we
	// don't care. The ACME server will collapse those down for us, how handy!
	dnsNames := []core.AcmeIdentifier{}
	for i := 0; i <= orderSize; i++ {
		dnsNames = append(dnsNames, core.AcmeIdentifier{
			Type:  core.IdentifierDNS,
			Value: randDomain(s.domainBase),
		})
	}

	// create the new order request object
	initOrder := struct {
		Identifiers []core.AcmeIdentifier
	}{
		Identifiers: dnsNames,
	}
	initOrderStr, err := json.Marshal(&initOrder)
	if err != nil {
		return err
	}

	// Sign the new order request with the context account's key/key ID
	newOrderURL := s.directory.EndpointURL(acme.NewOrderEndpoint)
	jws, err := ctx.signKeyIDV2Request(initOrderStr, newOrderURL)
	if err != nil {
		return err
	}
	bodyBuf := []byte(jws.FullSerialize())

	// POST the new-order endpoint
	nStarted := time.Now()
	resp, err := s.post(newOrderURL, bodyBuf, ctx.ns)
	nFinished := time.Now()
	nState := "error"
	defer func() {
		s.callLatency.Add(
			fmt.Sprintf("POST %s", acme.NewOrderEndpoint), nStarted, nFinished, nState)
	}()
	if err != nil {
		return fmt.Errorf("%s, post failed: %s", newOrderURL, err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%s, bad response: %s", newOrderURL, body)
	}

	// We expect that the result is a created order
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("%s, bad response status %d: %s", newOrderURL, resp.StatusCode, body)
	}

	// Unmarshal the Order object
	var orderJSON OrderJSON
	err = json.Unmarshal(body, &orderJSON)
	if err != nil {
		return err
	}

	// Populate the URL of the order from the Location header
	orderURL := resp.Header.Get("Location")
	if orderURL == "" {
		return fmt.Errorf("%s, bad response - no Location header with order ID", newOrderURL)
	}
	orderJSON.URL = orderURL

	// Store the pending order in the context
	ctx.pendingOrders = append(ctx.pendingOrders, &orderJSON)
	nState = "good"
	return nil
}

// popPendingOrder *removes* a random pendingOrder from the context, returning
// it.
func popPendingOrder(ctx *context) *OrderJSON {
	orderIndex := mrand.Intn(len(ctx.pendingOrders))
	order := ctx.pendingOrders[orderIndex]
	ctx.pendingOrders = append(ctx.pendingOrders[:orderIndex], ctx.pendingOrders[orderIndex+1:]...)
	return order
}

// getAuthorization fetches an authorization by GETing the provided URL. It
// records the latency and result of the GET operation in the state.
func getAuthorization(s *State, url string) (*core.Authorization, error) {
	// GET the provided URL, tracking elapsed time
	aStarted := time.Now()
	resp, err := s.get(url)
	aFinished := time.Now()
	aState := "error"
	// Defer logging the latency and result
	defer func() {
		s.callLatency.Add("GET /acme/authz/{ID}", aStarted, aFinished, aState)
	}()
	// If there was an error, note the state and return
	if err != nil {
		return nil, fmt.Errorf("%s bad response: %s", url, err)
	}

	// Read the response body
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Unmarshal an authorization from the HTTP response body
	var authz core.Authorization
	err = json.Unmarshal(body, &authz)
	if err != nil {
		return nil, fmt.Errorf("%s response: %s", url, body)
	}
	// The Authorization ID is not set in the response so we populate it using the
	// URL
	authz.ID = url
	aState = "good"
	return &authz, nil
}

// completeAuthorization processes a provided authorization by solving its
// HTTP-01 challenge using the context's account and the state's challenge
// server. Aftering POSTing the authorization's HTTP-01 challenge the
// authorization will be polled waiting for a state change.
func completeAuthorization(authz *core.Authorization, s *State, ctx *context) error {
	// Skip if the authz isn't pending
	if authz.Status != core.StatusPending {
		return nil
	}

	// Find a challenge to solve from the pending authorization. For now, we only
	// process HTTP-01 challenges and must error if there isn't a HTTP-01
	// challenge to solve.
	var chalToSolve *core.Challenge
	for _, challenge := range authz.Challenges {
		if challenge.Type == core.ChallengeTypeHTTP01 {
			chalToSolve = &challenge
			break
		}
	}
	if chalToSolve == nil {
		return errors.New("no http-01 challenges to complete")
	}

	// Compute the key authorization from the context account's key
	jwk := &jose.JSONWebKey{Key: &ctx.acct.key.PublicKey}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return err
	}
	authStr := fmt.Sprintf("%s.%s", chalToSolve.Token, base64.RawURLEncoding.EncodeToString(thumbprint))

	// Add the challenge response to the state's test server
	fmt.Printf("\n\nADDING HTTP-01 for token %q keyauth %q\n\n", chalToSolve.Token, authStr)
	s.challSrv.AddHTTPOneChallenge(chalToSolve.Token, authStr)
	// Clean up after we're done
	//defer s.challSrv.DeleteHTTPOneChallenge(chalToSolve.Token)

	// Prepare the Challenge POST body
	update := fmt.Sprintf(`{"keyAuthorization":"%s"}`, authStr)
	jws, err := ctx.signKeyIDV2Request([]byte(update), chalToSolve.URL)
	if err != nil {
		return err
	}
	requestPayload := []byte(jws.FullSerialize())

	// POST the challenge update to begin the challenge process
	cStarted := time.Now()
	resp, err := s.post(chalToSolve.URL, requestPayload, ctx.ns)
	cFinished := time.Now()
	cState := "error"
	// Record the final latency and state when finished
	defer func() {
		s.callLatency.Add("POST /acme/challenge/{ID}", cStarted, cFinished, cState)
	}()
	if err != nil {
		return err
	}

	// Read the response body and cleanup when finished
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	// The response code is expected to be Status OK
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Unexpected HTTP response code: %d", resp.StatusCode)
	}

	// Poll the authorization waiting for the challenge response to be recorded in
	// a change of state. The polling may sleep and retry a few times if required
	pollAuthorization(authz, s, ctx)
	if err != nil {
		return err
	}

	// The challenge is completed, the authz is valid
	cState = "good"
	return nil
}

// pollAuthorization GETs a provided authorization up to three times, sleeping
// in between attempts, waiting for the status of the returned authorization to
// be valid. If the status is invalid, or if three GETs do not produce the
// correct authorization state an error is returned. If no error is returned
// then the authorization is valid and ready.
func pollAuthorization(authz *core.Authorization, s *State, ctx *context) error {
	authzURL := authz.ID
	for i := 0; i < 3; i++ {
		// Fetch the authz by its URL
		authz, err := getAuthorization(s, authzURL)
		if err != nil {
			return nil
		}
		// If the authz is invalid, abort with an error
		if authz.Status == "invalid" {
			return fmt.Errorf("Authorization %q failed challenge and is status invalid", authzURL)
		}
		// If the authz is valid, return with no error - the authz is ready to go!
		if authz.Status == "valid" {
			return nil
		}
		// Otherwise sleep and try again
		time.Sleep(3 * time.Second)
	}
	return fmt.Errorf("Timed out polling authorization %q", authzURL)
}

// fulfillOrder processes a pending order from the context, completing each
// authorization's HTTP-01 challenge using the context's account, and finally
// placing the now-ready-to-be-finalized order into the context's list of
// fulfilled orders.
func fulfillOrder(s *State, ctx *context) error {
	// There must be at least one pending order in the context to fulfill
	if len(ctx.pendingOrders) == 0 {
		return errors.New("no pending orders to fulfill")
	}

	// Get an order to fulfill from the context
	order := popPendingOrder(ctx)

	// Each of its authorizations need to be processed
	for _, url := range order.Authorizations {
		// Fetch the authz by its URL
		authz, err := getAuthorization(s, url)
		if err != nil {
			return nil
		}

		// Complete the authorization by solving a challenge
		completeAuthorization(authz, s, ctx)
	}

	// Once all of the authorizations have been fulfilled the order is fulfilled
	// and ready for future finalization.
	ctx.fulfilledOrders = append(ctx.fulfilledOrders, order.URL)
	return nil
}

// getOrder GETs an order by URL, returning an OrderJSON object. It tracks the
// latency of the GET operation in the provided state.
func getOrder(s *State, url string) (*OrderJSON, error) {
	// GET the order URL
	aStarted := time.Now()
	resp, err := s.get(url)
	aFinished := time.Now()
	aState := "error"
	// Track the latency and result
	defer func() {
		s.callLatency.Add("GET /acme/order/{ID}", aStarted, aFinished, aState)
	}()
	// If there was an error, track that result
	if err != nil {
		return nil, fmt.Errorf("%s bad response: %s", url, err)
	}
	// Read the response body
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s, bad response: %s", url, body)
	}

	// We expect a HTTP status OK response
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s, bad response status %d: %s", url, resp.StatusCode, body)
	}

	// Unmarshal the Order object from the response body
	var orderJSON OrderJSON
	err = json.Unmarshal(body, &orderJSON)
	if err != nil {
		return nil, err
	}

	// Populate the order's URL based on the URL we fetched it from
	orderJSON.URL = url
	aState = "good"
	return &orderJSON, nil
}

// pollOrderForCert polls a provided order, waiting for the status to change to
// valid such that a certificate URL for the order is known. Three attempts are
// made to check the order status, sleeping 3s between each. If these attempts
// expire without the status becoming valid an error is returned.
func pollOrderForCert(order *OrderJSON, s *State, ctx *context) (*OrderJSON, error) {
	for i := 0; i < 3; i++ {
		// Fetch the order by its URL
		order, err := getOrder(s, order.URL)
		if err != nil {
			return nil, err
		}
		// If the order is invalid, fail
		if order.Status == "invalid" {
			return nil, fmt.Errorf("Order %q failed and is status invalid", order.URL)
		}
		// If the order is valid, return with no error - the authz is ready to go!
		if order.Status == "valid" {
			return order, nil
		}
		// Otherwise sleep and try again
		time.Sleep(3 * time.Second)
	}
	return nil, fmt.Errorf("Timed out polling order %q", order.URL)
}

// popFulfilledOrder **removes** a fulfilled order from the context, returning
// it. Fulfilled orders have all of their authorizations satisfied.
func popFulfilledOrder(ctx *context) string {
	orderIndex := mrand.Intn(len(ctx.fulfilledOrders))
	order := ctx.fulfilledOrders[orderIndex]
	ctx.fulfilledOrders = append(ctx.fulfilledOrders[:orderIndex], ctx.fulfilledOrders[orderIndex+1:]...)
	return order
}

// finalizeOrder removes a fulfilled order from the context and POSTs a CSR to
// the order's finalization URL. The CSR's key is set from the state's
// `certKey`. The order is then polled for the status to change to valid so that
// the certificate URL can be added to the context. The context's `certs` list
// is updated with the URL for the order's certificate.
func finalizeOrder(s *State, ctx *context) error {
	// There must be at least one fulfilled order in the context
	if len(ctx.fulfilledOrders) < 1 {
		return fmt.Errorf("No fulfilled orders in the context ready to be finalized")
	}

	// Pop a fulfilled order to process, and then GET its contents
	orderID := popFulfilledOrder(ctx)
	order, err := getOrder(s, orderID)
	if err != nil {
		return err
	}
	// Mark down the finalization URL for the order
	finalizeURL := order.Finalize

	// Pull the values from the order identifiers for use in the CSR
	dnsNames := make([]string, len(order.Identifiers))
	for i, ident := range order.Identifiers {
		dnsNames[i] = ident.Value
	}

	// Create a CSR using the state's certKey
	csr, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{DNSNames: dnsNames},
		s.certKey,
	)
	if err != nil {
		return err
	}

	// Create the finalization request body with the encoded CSR
	request := fmt.Sprintf(
		`{"csr":"%s"}`,
		base64.URLEncoding.EncodeToString(csr),
	)

	// Sign the request body with the context's account key/keyID
	jws, err := ctx.signKeyIDV2Request([]byte(request), finalizeURL)
	if err != nil {
		return err
	}
	requestPayload := []byte(jws.FullSerialize())

	// POST the finalization URL for the order
	started := time.Now()
	resp, err := s.post(finalizeURL, requestPayload, ctx.ns)
	finished := time.Now()
	state := "error"
	// Track the latency and the result state
	defer func() {
		s.callLatency.Add("POST /acme/order/finalize", started, finished, state)
	}()
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad response, status %d", resp.StatusCode)
	}
	// Read the body to ensure there isn't an error. We don't need the actual
	// contents.
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Poll the order waiting for the certificate to be ready
	completedOrder, err := pollOrderForCert(order, s, ctx)
	if err != nil {
		return err
	}

	// The valid order should have a certificate URL
	certURL := completedOrder.Certificate
	if certURL == "" {
		return fmt.Errorf("Order %q was finalized but has no cert URL", order.URL)
	}

	// Append the certificate URL into the context's list of certificates
	ctx.certs = append(ctx.certs, certURL)
	ctx.finalizedOrders = append(ctx.finalizedOrders, order.URL)
	state = "good"
	return nil
}

// min returns the smaller of the two inputs
func min(a, b int) int {
	if a > b {
		return b
	}
	return a
}
