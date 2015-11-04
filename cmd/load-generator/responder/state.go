package responder

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/letsencrypt/boulder/cmd/load-generator/latency"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/sa"
	"golang.org/x/crypto/ocsp"
)

type State struct {
	requests    [][]byte
	numRequests int
	maxRequests int
	ocspBase    string
	getRate     int64
	postRate    int64
	dbURI       string
	issuer      *x509.Certificate
	runtime     time.Duration
	client      *http.Client
	callLatency *latency.Map
	wg          *sync.WaitGroup
}

func New(maxRequests int, ocspBase string, getRate int, postRate int, dbURI string, issuerPath string, runtime time.Duration) (*State, error) {
	issuer, err := core.LoadCert(issuerPath)
	if err != nil {
		return nil, err
	}
	return &State{
		maxRequests: maxRequests,
		ocspBase:    ocspBase,
		getRate:     int64(getRate),
		postRate:    int64(postRate),
		dbURI:       dbURI,
		runtime:     runtime,
		client:      new(http.Client),
		issuer:      issuer,
		callLatency: latency.New(),
		wg:          new(sync.WaitGroup),
	}, nil
}

func (s *State) Run() {
	fmt.Println("warming up")
	err := s.warmup()
	if err != nil {
		fmt.Printf("warm up failed: %s\n", err)
		return
	}
	fmt.Println("finished warming up, sending requests")

	stop := make(chan bool, 2)
	if s.getRate > 0 {
		go func() {
			for {
				select {
				case <-stop:
					return
				default:
					s.wg.Add(1)
					go s.sendGET()
					time.Sleep(time.Duration(time.Second.Nanoseconds() / atomic.LoadInt64(&s.getRate)))
				}
			}
		}()
	}
	if s.postRate > 0 {
		go func() {
			for {
				select {
				case <-stop:
					return
				default:
					s.wg.Add(1)
					go s.sendPOST()
					time.Sleep(time.Duration(time.Second.Nanoseconds() / atomic.LoadInt64(&s.postRate)))
				}
			}
		}()
	}

	time.Sleep(s.runtime)
	stop <- true
	stop <- true
	fmt.Println("sent stop signals, waiting")
	s.wg.Wait()
	fmt.Println("all calls finished")
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

const query = "SELECT der FROM certificates"

func (s *State) warmup() error {
	// Load all(/some subset) of the certificates table and generate OCSP requests
	dbMap, err := sa.NewDbMap(s.dbURI)
	if err != nil {
		return err
	}

	selectQuery := query
	if s.maxRequests > 0 {
		selectQuery = fmt.Sprintf("%s LIMIT %d", selectQuery, s.maxRequests)
	}

	var certs [][]byte
	_, err = dbMap.Select(&certs, selectQuery)
	if err != nil {
		return err
	}

	var requests [][]byte
	for _, c := range certs {
		cert, err := x509.ParseCertificate(c)
		if err != nil {
			continue
		}
		req, err := ocsp.CreateRequest(cert, s.issuer, nil)
		if err != nil {
			continue
		}
		requests = append(requests, req)
	}

	s.numRequests = len(requests)
	if s.numRequests == 0 {
		return fmt.Errorf("No requests to send!")
	}
	s.requests = requests
	return nil
}

func (s *State) sendGET() {
	defer s.wg.Done()
	started := time.Now()
	resp, err := s.client.Get(s.ocspBase + base64.StdEncoding.EncodeToString(s.requests[rand.Intn(s.numRequests)]))
	finished := time.Now()
	state := "good"
	defer func() { s.callLatency.Add("GET", started, finished, state) }()
	if err != nil {
		fmt.Printf("[FAILED] GET: %s\n", err)
		state = "error"
		return
	}
	if resp.StatusCode != 200 {
		fmt.Printf("[FAILED] GET: incorrect status code %d\n", resp.StatusCode)
		state = "unexpected status"
		return
	}
	if _, err := ioutil.ReadAll(resp.Body); err != nil {
		fmt.Printf("[FAILED] GET: bad body, %s\n", err)
		state = "read error"
		return
	}
}

func (s *State) sendPOST() {
	defer s.wg.Done()
	started := time.Now()
	resp, err := s.client.Post(s.ocspBase, "application/ocsp-request", bytes.NewBuffer(s.requests[rand.Intn(s.numRequests)]))
	// doing this here seems to ignore the time it takes to read the response...
	// should it be replace with a time.Now() in the defer?
	finished := time.Now()
	state := "good"
	defer func() { s.callLatency.Add("POST", started, finished, state) }()
	if err != nil {
		fmt.Printf("[FAILED] POST: %s\n", err)
		state = "error"
		return
	}
	if resp.StatusCode != 200 {
		fmt.Printf("[FAILED] POST: incorrect status code %d\n", resp.StatusCode)
		state = "unexpected status"
		return
	}
	if _, err := ioutil.ReadAll(resp.Body); err != nil {
		fmt.Printf("[FAILED] POST: bad body, %s\n", err)
		state = "read error"
		return
	}
}
