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
	mrand "math/rand"
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

	"gopkg.in/square/go-jose.v1"

	"github.com/letsencrypt/boulder/core"
)

// RatePeriod describes how long a certain throughput should be maintained
type RatePeriod struct {
	For  time.Duration
	Rate int64
}

type registration struct {
	key            *ecdsa.PrivateKey
	signer         jose.Signer
	finalizedAuthz []string
	certs          []string
	mu             sync.Mutex
}

func (r *registration) update(finalizedAuthz, certs []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.finalizedAuthz = append(r.finalizedAuthz, finalizedAuthz...)
	r.certs = append(r.certs, certs...)
}

type context struct {
	reg            *registration
	pendingAuthz   []*core.Authorization
	finalizedAuthz []string
	certs          []string
	ns             *nonceSource
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

	rMu  sync.RWMutex
	regs []*registration

	challSrv    *challSrv
	callLatency *latencyFile
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

type snapshot struct {
	Registrations []rawRegistration
}

func (s *State) numRegs() int {
	s.rMu.RLock()
	defer s.rMu.RUnlock()
	return len(s.regs)
}

// Snapshot will save out generated registrations and certs (ignoring authorizations)
func (s *State) Snapshot(filename string) error {
	fmt.Printf("[+] Saving registrations to %s\n", filename)
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
			// RawKey:         x509.MarshalPKCS1PrivateKey(reg.key),
			RawKey: k,
		})
	}
	cont, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, cont, os.ModePerm)
}

// Restore previously generated registrations and certs
func (s *State) Restore(filename string) error {
	fmt.Printf("[+] Loading registrations from %s\n", filename)
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
		signer, err := jose.NewSigner(jose.RS256, key)
		if err != nil {
			continue
		}
		s.regs = append(s.regs, &registration{
			key:    key,
			signer: signer,
			certs:  r.Certs,
			//			auths:  r.Auths,
		})
	}
	return nil
}

// New returns a pointer to a new State struct or an error
func New(apiBase string, keySize int, domainBase string, realIP string, maxRegs int, latencyPath string, userEmail string, operations []string) (*State, error) {
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
		client:      client,
		apiBase:     apiBase,
		certKey:     certKey,
		domainBase:  domainBase,
		callLatency: latencyFile,
		wg:          new(sync.WaitGroup),
		realIP:      realIP,
		maxRegs:     maxRegs,
		email:       userEmail,
		respCodes:   make(map[int]*respCode),
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
func (s *State) Run(httpOneAddr string, tlsOneAddr string, p Plan) error {
	s.challSrv = newChallSrv(httpOneAddr, tlsOneAddr)
	s.challSrv.run()
	fmt.Printf("[+] Started challenge servers, http-01: %q, tls-sni-01: %q\n", httpOneAddr, tlsOneAddr)

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

type codes []*respCode

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
		list = append(list, v)
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
// required for JWS

func (s *State) signWithNonce(endpoint string, alwaysNew bool, payload []byte, signer jose.Signer) ([]byte, error) {
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

func (s *State) addRegistration(reg *registration) {
	s.rMu.Lock()
	defer s.rMu.Unlock()

	s.regs = append(s.regs, reg)
}

func getRegistration(s *State, ctx *context) error {
	s.rMu.RLock()
	defer s.rMu.RUnlock()

	if len(s.regs) == 0 {
		return errors.New("no registrations to return")
	}
	ctx.reg = s.regs[mrand.Intn(len(s.regs))]
	ctx.ns = &nonceSource{s: s}
	ctx.reg.signer.SetNonceSource(ctx.ns)
	return nil
}

func (s *State) sendCall() {
	defer s.wg.Done()
	ctx := &context{}

	for _, op := range s.operations {
		err := op(s, ctx)
		if err != nil {
			method := runtime.FuncForPC(reflect.ValueOf(op).Pointer()).Name() // XXX: sketchy :/
			fmt.Printf("[FAILED] %s: %s\n", method, err)
			break
		}
	}
	if ctx.reg != nil {
		ctx.reg.update(ctx.finalizedAuthz, ctx.certs)
	}
}
