package wfe

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"
	"github.com/letsencrypt/boulder/cmd/load-generator/latency"

	"github.com/letsencrypt/boulder/core"
)

type registration struct {
	key    *rsa.PrivateKey
	signer jose.Signer
	iMu    *sync.RWMutex
	auths  []core.Authorization
	certs  []string
}

type State struct {
	rMu     *sync.RWMutex
	regs    []*registration
	maxRegs int
	client  *http.Client
	apiBase string

	nMu       *sync.Mutex
	noncePool []string

	throughput int64

	hoMu              *sync.RWMutex
	httpOneChallenges map[string]string
	httpOnePort       int

	certKey    *rsa.PrivateKey
	domainBase string

	callLatency *latency.Map

	runtime time.Duration

	wg *sync.WaitGroup
}

type rawRegistration struct {
	Certs  []string             `json:"certs"`
	Auths  []core.Authorization `json:"auths"`
	RawKey []byte               `json:"rawKey"`
}

type snapshot struct {
	Registrations     []rawRegistration
	HttpOneChallenges map[string]string
}

func (s *State) Snapshot() ([]byte, error) {
	s.rMu.Lock()
	s.hoMu.Lock()
	defer s.rMu.Unlock()
	defer s.hoMu.Unlock()
	snap := snapshot{HttpOneChallenges: s.httpOneChallenges}
	rawRegs := []rawRegistration{}
	for _, r := range s.regs {
		rawRegs = append(rawRegs, rawRegistration{
			Certs:  r.certs,
			Auths:  r.auths,
			RawKey: x509.MarshalPKCS1PrivateKey(r.key),
		})
	}
	return json.Marshal(snap)
}

func (s *State) Restore(content []byte) error {
	s.rMu.Lock()
	s.hoMu.Lock()
	defer s.rMu.Unlock()
	defer s.hoMu.Unlock()
	snap := snapshot{}
	err := json.Unmarshal(content, &snap)
	if err != nil {
		return err
	}
	s.httpOneChallenges = snap.HttpOneChallenges
	for _, r := range snap.Registrations {
		key, err := x509.ParsePKCS1PrivateKey(r.RawKey)
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
			auths:  r.Auths,
		})
	}
	return nil
}

func New(httpOnePort int, apiBase string, rate int, maxRegs int, keySize int, domainBase string, runtime time.Duration) (*State, error) {
	certKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout:   3 * time.Second,
				KeepAlive: 0,
			}).Dial,
			TLSHandshakeTimeout: 2 * time.Second,
			DisableKeepAlives:   true,
		},
	}
	return &State{
		rMu:               new(sync.RWMutex),
		nMu:               new(sync.Mutex),
		hoMu:              new(sync.RWMutex),
		httpOneChallenges: make(map[string]string),
		httpOnePort:       httpOnePort,
		client:            client,
		apiBase:           apiBase,
		throughput:        int64(rate),
		maxRegs:           maxRegs,
		certKey:           certKey,
		domainBase:        domainBase,
		callLatency:       latency.New(),
		runtime:           runtime,
		wg:                new(sync.WaitGroup),
	}, nil
}

func (s *State) Run() {
	// Run http-0 challenge server
	go s.httpOneServer()

	// Run sending loop
	stop := make(chan bool, 1)
	s.callLatency.Started = time.Now()

	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				s.wg.Add(1)
				go s.sendCall()
				time.Sleep(time.Duration(time.Second.Nanoseconds() / atomic.LoadInt64(&s.throughput)))
			}
		}
	}()

	time.Sleep(s.runtime)
	fmt.Println("READ END")
	stop <- true
	fmt.Println("SENT STOP")
	s.wg.Wait()
	fmt.Println("ALL DONE")
	s.callLatency.Stopped = time.Now()
}

func (s *State) Dump(jsonPath string) error {
	if jsonPath != "" {
		data, err := json.Marshal(s.callLatency)
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(jsonPath, data, os.ModePerm)
		if err != nil {
			return err
		}
	}
	return nil
}

// HTTP utils

func (s *State) post(endpoint string, payload []byte) (*http.Response, error) {
	resp, err := s.client.Post(
		endpoint,
		"application/json",
		bytes.NewBuffer(payload),
	)
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
// required for the required form of JWS

func (s *State) signWithNonce(payload []byte, signer jose.Signer) ([]byte, error) {
	nonce, err := s.getNonce()
	if err != nil {
		return nil, err
	}
	jws, err := signer.Sign(payload, nonce)
	if err != nil {
		return nil, err
	}
	return json.Marshal(jws)
}

func (s *State) getNonce() (string, error) {
	s.nMu.Lock()
	defer s.nMu.Unlock()
	if len(s.noncePool) == 0 {
		started := time.Now()
		resp, err := s.client.Head(fmt.Sprintf("%s/directory", s.apiBase))
		finished := time.Now()
		state := "good"
		defer func() { s.callLatency.Add("HEAD /directory", started, finished, state) }()
		if err != nil {
			state = "error"
			return "", err
		}
		if nonce := resp.Header.Get("Replay-Nonce"); nonce != "" {
			return nonce, nil
		}
		state = "error"
		return "", fmt.Errorf("Nonce header not supplied!")
	}
	nonce := s.noncePool[0]
	s.noncePool = s.noncePool[1:]
	return nonce, nil
}

func (s *State) addNonce(nonce string) {
	s.nMu.Lock()
	defer s.nMu.Unlock()
	s.noncePool = append(s.noncePool, nonce)
}

// Reg object utils, used to add and randomly retrieve registration objects

func (s *State) addReg(reg *registration) {
	s.rMu.Lock()
	defer s.rMu.Unlock()
	s.regs = append(s.regs, reg)
}

func (s *State) getRandReg() (*registration, bool) {
	regsLength := len(s.regs)
	if regsLength == 0 {
		return nil, false
	}
	return s.regs[mrand.Intn(regsLength)], true
}

func (s *State) getReg() (*registration, bool) {
	s.rMu.RLock()
	defer s.rMu.RUnlock()
	return s.getRandReg()
}

// Call sender, it sends the calls!

func (s *State) sendCall() {
	actions := []func(*registration){}
	s.rMu.RLock()
	if len(s.regs) < s.maxRegs || s.maxRegs == 0 {
		actions = append(actions, s.newRegistration)
	}
	s.rMu.RUnlock()

	reg, found := s.getReg()
	if found {
		actions = append(actions, s.newAuthorization)
		reg.iMu.RLock()
		if len(reg.auths) > 0 {
			actions = append(actions, s.newCertificate)
		}
		if len(reg.certs) > 2 { // XXX: makes life more interesting
			actions = append(actions, s.revokeCertificate)
		}
		reg.iMu.RUnlock()
	}

	if len(actions) > 0 {
		actions[mrand.Intn(len(actions))](reg)
	} else {
		fmt.Println("wat")
	}
	s.wg.Done()
}
