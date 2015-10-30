package responder

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"
	"sync/atomic"
	"time"

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
					go s.sendPOST()
					time.Sleep(time.Duration(time.Second.Nanoseconds() / atomic.LoadInt64(&s.postRate)))
				}
			}
		}()
	}

	time.Sleep(s.runtime)
	stop <- true
	stop <- true
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
	_, err := s.client.Get(s.ocspBase + base64.StdEncoding.EncodeToString(s.requests[rand.Intn(s.numRequests)]))
	if err != nil {
		fmt.Printf("[FAILED] GET: %s\n", err)
		return
	}
	// fmt.Println(resp) // or you know... something
}

func (s *State) sendPOST() {
	_, err := s.client.Post(s.ocspBase, "application/ocsp-request", bytes.NewBuffer(s.requests[rand.Intn(s.numRequests)]))
	if err != nil {
		fmt.Printf("[FAILED] POST: %s\n", err)
		return
	}
	// fmt.Println(resp) // or you know... something
}
