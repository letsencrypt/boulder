package wfe

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/square/go-jose"

	"github.com/letsencrypt/boulder/cmd/load-generator/latency"
	"github.com/letsencrypt/boulder/core"
)

// RatePeriod describes how long a certain throughput should be maintained
type RatePeriod struct {
	For  time.Duration
	Rate int64
}

type registration struct {
	key            *rsa.PrivateKey
	signer         jose.Signer
	finalizedAuthz []string
	certs          []string
}

type context struct {
	reg            *registration
	pendingAuthz   []*core.Authorization
	finalizedAuthz []string
	certs          []string
}

type Plan struct {
	runtime time.Duration
	rate    int64
	delta   *struct {
		inc    int64
		period time.Duration
	}
}

// State holds *all* the stuff
type State struct {
	apiBase         string
	domainBase      string
	email           string
	maxRegs         int
	maxNamesPerCert int
	realIP          string
	certKey         *rsa.PrivateKey

	operations []func(*context) error

	regPool sync.Pool
	numRegs int64

	challSrv    *ChallSrv
	callLatency *latency.File
	client      *http.Client
	nMu         *sync.RWMutex
	noncePool   []string

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

// Snapshot will save out generated registrations and certs (ignoring authorizations)
func (s *State) Snapshot(filename string) error {
	fmt.Printf("[+] Saving registrations to %s\n", filename)
	snap := snapshot{}
	for i := int64(0); i < s.numRegs; i++ {
		r := s.regPool.Get()
		if r == nil {
			panic("expected to pull a registration from the pool")
		}
		reg := r.(*registration)
		snap.Registrations = append(snap.Registrations, rawRegistration{
			Certs:          reg.certs,
			FinalizedAuthz: reg.finalizedAuthz,
			RawKey:         x509.MarshalPKCS1PrivateKey(reg.key),
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
		key, err := x509.ParsePKCS1PrivateKey(r.RawKey)
		if err != nil {
			continue
		}
		key.Precompute()
		signer, err := jose.NewSigner(jose.RS256, key)
		if err != nil {
			continue
		}
		signer.SetNonceSource(s)
		s.addRegistration(&registration{
			key:    key,
			signer: signer,
			certs:  r.Certs,
			//			auths:  r.Auths,
		})
	}
	return nil
}

// New returns a pointer to a new State struct, or an error
func New(apiBase string, keySize int, domainBase string, realIP string, maxRegs int, latencyPath string, userEmail string) (*State, error) {
	certKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	latencyFile, err := latency.New(latencyPath)
	if err != nil {
		return nil, err
	}
	return &State{
		nMu:         new(sync.RWMutex),
		client:      client,
		apiBase:     apiBase,
		certKey:     certKey,
		domainBase:  domainBase,
		callLatency: latencyFile,
		wg:          new(sync.WaitGroup),
		realIP:      realIP,
		maxRegs:     maxRegs,
		email:       userEmail,
	}, nil
}

// Run runs the WFE load-generator for either the specified runtime/rate or the execution plan
func (s *State) Run(httpOneAddr string, tlsOneAddr string, p Plan) error {
	s.challSrv = newChallSrv(httpOneAddr, tlsOneAddr)
	s.challSrv.run()
	fmt.Printf("[+] Started challenge servers, http-01: %q, tls-sni-01: %q\n", httpOneAddr, tlsOneAddr)

	if p.delta != nil {
		go func() {
			for {
				time.Sleep(p.delta.period)
				atomic.AddInt64(&p.rate, p.delta.inc)
			}
		}()
	}

	// Run sending loop
	stop := make(chan bool, 1)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("[+] Beginning execution plan")
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				s.wg.Add(1)
				go s.sendCall()
				time.Sleep(time.Duration(time.Second.Nanoseconds() / atomic.LoadInt64(&p.rate)))
			}
		}
	}()

	select {
	case <-time.After(p.runtime):
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

func (s *State) post(endpoint string, payload []byte) (*http.Response, error) {
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Add("X-Real-IP", s.realIP)
	req.Header.Add("User-Agent", "boulder load-generator -- heyo ^_^")
	resp, err := s.client.Do(req)
	if resp != nil {
		if newNonce := resp.Header.Get("Replay-Nonce"); newNonce != "" {
			s.addNonce(newNonce)
		}
	}
	if err != nil {
		return nil, err
	}
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

// Nonce satisfies the interface jose.NonceSource
func (s *State) Nonce() (string, error) {
	s.nMu.RLock()
	if len(s.noncePool) == 0 {
		s.nMu.RUnlock()
		started := time.Now()
		resp, err := s.client.Head(fmt.Sprintf("%s/directory", s.apiBase))
		finished := time.Now()
		state := "good"
		defer func() { s.callLatency.Add("HEAD /directory", started, finished, state) }()
		if err != nil {
			state = "error"
			return "", err
		}
		defer resp.Body.Close()
		if nonce := resp.Header.Get("Replay-Nonce"); nonce != "" {
			return nonce, nil
		}
		state = "error"
		return "", fmt.Errorf("Nonce header not supplied!")
	}
	s.nMu.RUnlock()
	s.nMu.Lock()
	defer s.nMu.Unlock()
	nonce := s.noncePool[0]
	if len(s.noncePool) > 1 {
		s.noncePool = s.noncePool[1:]
	} else {
		s.noncePool = []string{}
	}
	return nonce, nil
}

func (s *State) addNonce(nonce string) {
	s.nMu.Lock()
	defer s.nMu.Unlock()
	s.noncePool = append(s.noncePool, nonce)
}

func (s *State) addRegistration(reg *registration) error {
	if reg == nil {
		return errors.New("passed nil registration")
	}
	s.regPool.Put(reg)
	atomic.AddInt64(&s.numRegs, 1)
	return nil
}

func (s *State) getRegistration(ctx *context) error {
	reg := s.regPool.Get()
	if reg == nil {
		return errors.New("no registrations available")
	}
	ctx.reg = reg.(*registration)
	return nil
}

func (s *State) sendCall() {
	defer s.wg.Done()
	ctx := &context{}

	for _, op := range s.operations {
		err := op(ctx)
		if err != nil {
			// baddy
			method := runtime.FuncForPC(reflect.ValueOf(op).Pointer()).Name() // XXX: sketchy :/
			fmt.Printf("[FAILED] %s: %s\n", method, err)
			break
		}
	}
	if len(ctx.pendingAuthz) > 0 {
		// do something?
	}
	if ctx.reg != nil {
		if len(ctx.finalizedAuthz) > 0 {
			ctx.reg.finalizedAuthz = append(ctx.reg.finalizedAuthz, ctx.finalizedAuthz...)
		}
		err := s.addRegistration(ctx.reg)
		if err != nil {
			fmt.Printf("[FAILED] addRegistration: %s\n", err)
		}
	}
}
