package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/test/challsrv"
)

// RatePeriod describes how long a certain throughput should be maintained
type RatePeriod struct {
	For  time.Duration
	Rate int64
}

// registration is an ACME v1 registration resource
type registration struct {
	key            *ecdsa.PrivateKey
	signer         jose.Signer
	finalizedAuthz []string
	certs          []string
	mu             sync.Mutex
}

// account is an ACME v2 account resource. It does not have a `jose.Signer`
// because we need to set the Signer options per-request with the URL being
// POSTed and must construct it on the fly from the `key`. Accounts are
// protected by a `sync.Mutex` that must be held for updates (see
// `account.Update`).
type account struct {
	key             *ecdsa.PrivateKey
	id              string
	finalizedOrders []string
	certs           []string
	mu              sync.Mutex
}

// update locks an account resource's mutex and sets the `finalizedOrders` and
// `certs` fields to the provided values.
func (acct *account) update(finalizedOrders, certs []string) {
	acct.mu.Lock()
	defer acct.mu.Unlock()

	acct.finalizedOrders = append(acct.finalizedOrders, finalizedOrders...)
	acct.certs = append(acct.certs, certs...)
}

// update locks a registration resource's mutx and sets the `finalizedAuthz` and
// `certs` fields to the provided values.
func (r *registration) update(finalizedAuthz, certs []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.finalizedAuthz = append(r.finalizedAuthz, finalizedAuthz...)
	r.certs = append(r.certs, certs...)
}

type context struct {
	/* ACME V1 Context */
	// The current V1 registration (may be nil for V2 load generation)
	reg *registration
	// Pending authorizations waiting for challenge validation
	pendingAuthz []*core.Authorization
	// IDs of finalized authorizations in valid status
	finalizedAuthz []string

	/* ACME V2 Context */
	// The current V2 account (may be nil for legacy load generation)
	acct *account
	// Pending orders waiting for authorization challenge validation
	pendingOrders []*OrderJSON
	// Fulfilled orders in a valid status waiting for finalization
	fulfilledOrders []string
	// Finalized orders that have certificates
	finalizedOrders []string

	/* Shared Context */
	// A list of URLs for issued certificates
	certs []string
	// The nonce source for JWS signature nonce headers
	ns *nonceSource
}

// signEmbeddedV2Request signs the provided request data using the context's
// account's private key. The provided URL is set as a protected header per ACME
// v2 JWS standards. The resulting JWS contains an **embedded** JWK - this makes
// this function primarily applicable to new account requests where no key ID is
// known.
func (c *context) signEmbeddedV2Request(data []byte, url string) (*jose.JSONWebSignature, error) {
	// Create a signing key for the account's private key
	signingKey := jose.SigningKey{
		Key:       c.acct.key,
		Algorithm: jose.ES256,
	}
	// Create a signer, setting the URL protected header
	signer, err := jose.NewSigner(signingKey, &jose.SignerOptions{
		NonceSource: c.ns,
		EmbedJWK:    true,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
	})
	if err != nil {
		return nil, err
	}

	// Sign the data with the signer
	signed, err := signer.Sign(data)
	if err != nil {
		return nil, err
	}
	return signed, nil
}

// signKeyIDV2Request signs the provided request data using the context's
// account's private key. The provided URL is set as a protected header per ACME
// v2 JWS standards. The resulting JWS contains a Key ID header that is
// populated using the context's account's ID. This is the default JWS signing
// style for ACME v2 requests and should be used everywhere but where the key ID
// is unknown (e.g. new-account requests where an account doesn't exist yet).
func (c *context) signKeyIDV2Request(data []byte, url string) (*jose.JSONWebSignature, error) {
	// Create a JWK with the account's private key and key ID
	jwk := &jose.JSONWebKey{
		Key:       c.acct.key,
		Algorithm: "ECDSA",
		KeyID:     c.acct.id,
	}

	// Create a signing key with the JWK
	signerKey := jose.SigningKey{
		Key:       jwk,
		Algorithm: jose.ES256,
	}

	// Ensure the signer's nonce source and URL header will be set
	opts := &jose.SignerOptions{
		NonceSource: c.ns,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
	}

	// Construct the signer with the configured options
	signer, err := jose.NewSigner(signerKey, opts)
	if err != nil {
		return nil, err
	}

	// Sign the data with the signer
	signed, err := signer.Sign(data)
	if err != nil {
		return nil, err
	}
	return signed, nil
}

type RateDelta struct {
	Inc    int64
	Period time.Duration
}

type Plan struct {
	Runtime time.Duration
	Rate    int64
	Delta   *RateDelta
}

type respCode struct {
	code int
	num  int
}

// State holds *all* the stuff
type State struct {
	apiBase         string
	domainBase      string
	email           string
	maxRegs         int
	maxNamesPerCert int
	realIP          string
	certKey         *ecdsa.PrivateKey

	operations []func(*State, *context) error

	rMu sync.RWMutex

	// regs holds V1 registration objects
	regs []*registration
	// accts holds V2 account objects
	accts []*account

	challSrv    *challsrv.ChallSrv
	callLatency latencyWriter
	client      *http.Client

	getTotal  int64
	postTotal int64
	respCodes map[int]*respCode
	cMu       sync.Mutex

	wg *sync.WaitGroup
}

type rawRegistration struct {
	Certs          []string `json:"certs"`
	FinalizedAuthz []string `json:"finalizedAuthz"`
	RawKey         []byte   `json:"rawKey"`
}

type rawAccount struct {
	FinalizedOrders []string `json:"finalizedOrders"`
	Certs           []string `json:"certs"`
	ID              string   `json:"id"`
	RawKey          []byte   `json:"rawKey"`
}

type snapshot struct {
	Registrations []rawRegistration
	Accounts      []rawAccount
}

func (s *State) numAccts() int {
	s.rMu.RLock()
	defer s.rMu.RUnlock()
	return len(s.accts)
}

func (s *State) numRegs() int {
	s.rMu.RLock()
	defer s.rMu.RUnlock()
	return len(s.regs)
}

// Snapshot will save out generated registrations and accounts
func (s *State) Snapshot(filename string) error {
	fmt.Printf("[+] Saving registrations/accounts to %s\n", filename)
	snap := snapshot{}
	// assume rMu lock operations aren't happening right now
	for _, reg := range s.regs {
		k, err := x509.MarshalECPrivateKey(reg.key)
		if err != nil {
			return err
		}
		snap.Registrations = append(snap.Registrations, rawRegistration{
			Certs:          reg.certs,
			FinalizedAuthz: reg.finalizedAuthz,
			RawKey:         k,
		})
	}
	for _, acct := range s.accts {
		k, err := x509.MarshalECPrivateKey(acct.key)
		if err != nil {
			return err
		}
		snap.Accounts = append(snap.Accounts, rawAccount{
			Certs:           acct.certs,
			FinalizedOrders: acct.finalizedOrders,
			ID:              acct.id,
			RawKey:          k,
		})
	}
	cont, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, cont, os.ModePerm)
}

// Restore previously generated registrations and accounts
func (s *State) Restore(filename string) error {
	fmt.Printf("[+] Loading registrations/accounts from %s\n", filename)
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	snap := snapshot{}
	err = json.Unmarshal(content, &snap)
	if err != nil {
		return err
	}
	for _, r := range snap.Registrations {
		key, err := x509.ParseECPrivateKey(r.RawKey)
		if err != nil {
			continue
		}
		signer, err := jose.NewSigner(jose.SigningKey{
			Key:       key,
			Algorithm: jose.RS256,
		}, &jose.SignerOptions{
			NonceSource: &nonceSource{s: s},
			EmbedJWK:    true,
		})
		if err != nil {
			continue
		}
		s.regs = append(s.regs, &registration{
			key:    key,
			signer: signer,
			certs:  r.Certs,
		})
	}
	for _, a := range snap.Accounts {
		key, err := x509.ParseECPrivateKey(a.RawKey)
		if err != nil {
			continue
		}
		if err != nil {
			continue
		}
		s.accts = append(s.accts, &account{
			key:             key,
			id:              a.ID,
			finalizedOrders: a.FinalizedOrders,
			certs:           a.Certs,
		})
	}
	return nil
}

// New returns a pointer to a new State struct or an error
func New(
	apiBase string,
	keySize int,
	domainBase string,
	realIP string,
	maxRegs, maxNamesPerCert int,
	latencyPath string,
	userEmail string,
	operations []string) (*State, error) {
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: 5 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // CDN bypass can cause validation failures
			},
			MaxIdleConns:    500,
			IdleConnTimeout: 90 * time.Second,
		},
		Timeout: 10 * time.Second,
	}
	latencyFile, err := newLatencyFile(latencyPath)
	if err != nil {
		return nil, err
	}
	s := &State{
		client:          client,
		apiBase:         apiBase,
		certKey:         certKey,
		domainBase:      domainBase,
		callLatency:     latencyFile,
		wg:              new(sync.WaitGroup),
		realIP:          realIP,
		maxRegs:         maxRegs,
		maxNamesPerCert: maxNamesPerCert,
		email:           userEmail,
		respCodes:       make(map[int]*respCode),
	}

	// convert operations strings to methods
	for _, opName := range operations {
		op, present := stringToOperation[opName]
		if !present {
			return nil, fmt.Errorf("unknown operation %q", opName)
		}
		s.operations = append(s.operations, op)
	}

	return s, nil
}

// Run runs the WFE load-generator
func (s *State) Run(httpOneAddr string, p Plan) error {
	// Create a new challenge server for HTTP-01 challenges
	challSrv, err := challsrv.New(challsrv.Config{
		HTTPOneAddrs: []string{httpOneAddr},
		// Use a logger that has a load-generator prefix
		Log: log.New(os.Stdout, "load-generator challsrv - ", log.LstdFlags),
	})
	if err != nil {
		return err
	}
	// Save the challenge server in the state
	s.challSrv = challSrv

	// Create a waitgroup that can be used to block until the challenge server has
	// cleanly shut down
	challSrvWg := new(sync.WaitGroup)
	challSrvWg.Add(1)
	// Start the Challenge server in its own Go routine
	go s.challSrv.Run(challSrvWg)
	fmt.Printf("[+] Started http-01 challenge server: %q\n", httpOneAddr)

	if p.Delta != nil {
		go func() {
			for {
				time.Sleep(p.Delta.Period)
				atomic.AddInt64(&p.Rate, p.Delta.Inc)
			}
		}()
	}

	// Run sending loop
	stop := make(chan bool, 1)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("[+] Beginning execution plan")
	i := int64(0)
	go func() {
		for {
			start := time.Now()
			select {
			case <-stop:
				return
			default:
				s.wg.Add(1)
				go s.sendCall()
				atomic.AddInt64(&i, 1)
			}
			sf := time.Duration(time.Second.Nanoseconds()/atomic.LoadInt64(&p.Rate)) - time.Since(start)
			time.Sleep(sf)
		}
	}()
	go func() {
		lastTotal := int64(0)
		lastGet := int64(0)
		lastPost := int64(0)
		for {
			time.Sleep(time.Second)
			curTotal := atomic.LoadInt64(&i)
			curGet := atomic.LoadInt64(&s.getTotal)
			curPost := atomic.LoadInt64(&s.postTotal)
			fmt.Printf(
				"%s Action rate: %d/s [expected: %d/s], Request rate: %d/s [POST: %d/s, GET: %d/s], Responses: [%s]\n",
				time.Now().Format("2006-01-02 15:04:05"),
				curTotal-lastTotal,
				atomic.LoadInt64(&p.Rate),
				(curGet+curPost)-(lastGet+lastPost),
				curGet-lastGet,
				curPost-lastPost,
				s.respCodeString(),
			)
			lastTotal = curTotal
			lastGet = curGet
			lastPost = curPost
		}
	}()

	select {
	case <-time.After(p.Runtime):
		fmt.Println("[+] Execution plan finished")
	case sig := <-sigs:
		fmt.Printf("[!] Execution plan interrupted: %s caught\n", sig.String())
	}
	stop <- true
	fmt.Println("[+] Waiting for pending flows to finish before killing challenge server")
	s.wg.Wait()
	fmt.Println("[+] Shutting down challenge server")
	// Send a Shutdown request to the challenge server
	s.challSrv.Shutdown()
	// Wait on the waitgroup we gave the challenge server when we called Run().
	// This will block until the challenge server is fully shut down.
	challSrvWg.Wait()
	return nil
}

// HTTP utils

func (s *State) addRespCode(code int) {
	s.cMu.Lock()
	defer s.cMu.Unlock()
	code = code / 100
	if e, ok := s.respCodes[code]; ok {
		e.num++
	} else if !ok {
		s.respCodes[code] = &respCode{code, 1}
	}
}

// codes is a convenience type for holding copies of the state object's
// `respCodes` field of `map[int]*respCode`. Unlike the state object the
// respCodes are copied by value and not held as pointers. The codes type allows
// sorting the response codes for output.
type codes []respCode

func (c codes) Len() int {
	return len(c)
}

func (c codes) Less(i, j int) bool {
	return c[i].code < c[j].code
}

func (c codes) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

func (s *State) respCodeString() string {
	s.cMu.Lock()
	list := codes{}
	for _, v := range s.respCodes {
		list = append(list, *v)
	}
	s.cMu.Unlock()
	sort.Sort(list)
	counts := []string{}
	for _, v := range list {
		counts = append(counts, fmt.Sprintf("%dxx: %d", v.code, v.num))
	}
	return strings.Join(counts, ", ")
}

var userAgent = "boulder load-generator -- heyo ^_^"

func (s *State) post(endpoint string, payload []byte, ns *nonceSource) (*http.Response, error) {
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Add("X-Real-IP", s.realIP)
	req.Header.Add("User-Agent", userAgent)
	atomic.AddInt64(&s.postTotal, 1)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	go s.addRespCode(resp.StatusCode)
	if newNonce := resp.Header.Get("Replay-Nonce"); newNonce != "" {
		ns.addNonce(newNonce)
	}
	return resp, nil
}

func (s *State) get(path string) (*http.Response, error) {
	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("X-Real-IP", s.realIP)
	req.Header.Add("User-Agent", userAgent)
	atomic.AddInt64(&s.getTotal, 1)
	resp, err := s.client.Get(path)
	if err != nil {
		return nil, err
	}
	go s.addRespCode(resp.StatusCode)
	return resp, nil
}

// Nonce utils, these methods are used to generate/store/retrieve the nonces
// required for JWS in V1 ACME requests

// signWithNonce signs the provided message with the provided signer, returning
// the raw JWS bytes or an error. signWithNonce is not compatible with ACME v2
func (s *State) signWithNonce(payload []byte, signer jose.Signer) ([]byte, error) {
	jws, err := signer.Sign(payload)
	if err != nil {
		return nil, err
	}
	return []byte(jws.FullSerialize()), nil
}

type nonceSource struct {
	mu        sync.Mutex
	noncePool []string
	s         *State
}

func (ns *nonceSource) getNonce() (string, error) {
	started := time.Now()
	resp, err := ns.s.client.Head(fmt.Sprintf("%s/directory", ns.s.apiBase))
	finished := time.Now()
	state := "good"
	defer func() { ns.s.callLatency.Add("HEAD /directory", started, finished, state) }()
	if err != nil {
		state = "error"
		return "", err
	}
	defer resp.Body.Close()
	if nonce := resp.Header.Get("Replay-Nonce"); nonce != "" {
		return nonce, nil
	}
	state = "error"
	return "", errors.New("'Replay-Nonce' header not supplied")
}

// Nonce satisfies the interface jose.NonceSource, should probably actually be per context but ¯\_(ツ)_/¯ for now
func (ns *nonceSource) Nonce() (string, error) {
	ns.mu.Lock()
	if len(ns.noncePool) == 0 {
		ns.mu.Unlock()
		return ns.getNonce()
	}
	defer ns.mu.Unlock()
	nonce := ns.noncePool[0]
	if len(ns.noncePool) > 1 {
		ns.noncePool = ns.noncePool[1:]
	} else {
		ns.noncePool = []string{}
	}
	return nonce, nil
}

func (ns *nonceSource) addNonce(nonce string) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.noncePool = append(ns.noncePool, nonce)
}

// addAccount adds the provided account to the state's list of accts
func (s *State) addAccount(acct *account) {
	s.rMu.Lock()
	defer s.rMu.Unlock()

	s.accts = append(s.accts, acct)
}

// addRegistration adds the provided registration to the state's list of regs
func (s *State) addRegistration(reg *registration) {
	s.rMu.Lock()
	defer s.rMu.Unlock()

	s.regs = append(s.regs, reg)
}

func (s *State) sendCall() {
	defer s.wg.Done()
	ctx := &context{}

	for _, op := range s.operations {
		err := op(s, ctx)
		if err != nil {
			method := runtime.FuncForPC(reflect.ValueOf(op).Pointer()).Name()
			fmt.Printf("[FAILED] %s: %s\n", method, err)
			break
		}
	}
	// If the context's V1 registration
	if ctx.reg != nil {
		ctx.reg.update(ctx.finalizedAuthz, ctx.certs)
	}
	// If the context's V2 account isn't nil, update it based on the context's
	// finalizedOrders and certs.
	if ctx.acct != nil {
		ctx.acct.update(ctx.finalizedOrders, ctx.certs)
	}
}
