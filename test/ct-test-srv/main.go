// This is a test server that implements the subset of RFC6962 APIs needed to
// run Boulder's CT log submission code. Currently it only implements add-chain.
// This is used by startservers.py.
package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/publisher"

	lintasn1 "github.com/globalsign/certlint/asn1"
	"github.com/globalsign/certlint/certdata"
	"github.com/globalsign/certlint/checks"
	_ "github.com/globalsign/certlint/checks/certificate/all"
	_ "github.com/globalsign/certlint/checks/extensions/all"
)

type ctSubmissionRequest struct {
	Chain []string `json:"chain"`
}

type integrationSrv struct {
	sync.Mutex
	submissions     int64
	key             *ecdsa.PrivateKey
	latencySchedule []float64
	latencyItem     int
}

// linting isn't normally the role of a CT log, but since we are submitting to
// the CT test server anyhow, it happens to be a handy place to add linting.
// If lint fails, Boulder will not be able to get a quorum of SCTs in the test
// environment, and will fail, triggering an integration test failure.
func lint(der []byte) error {
	_, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	al := new(lintasn1.Linter)
	errs := al.CheckStruct(der)
	if errs != nil {
		for _, err := range errs.List() {
			return err
		}
	}
	d, err := certdata.Load(der)
	if err != nil {
		return err
	}
	errs = checks.Certificate.Check(d)
	if errs != nil {
		for _, err := range errs.List() {
			if err.Error() != "commonName field is deprecated" {
				return err
			}
		}
	}
	return nil
}

func (is *integrationSrv) handler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/ct/v1/add-pre-chain":
		fallthrough
	case "/ct/v1/add-chain":
		if r.Method != "POST" {
			http.NotFound(w, r)
			return
		}
		bodyBytes, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		atomic.AddInt64(&is.submissions, 1)

		if is.latencySchedule != nil {
			is.Lock()
			sleepTime := time.Duration(is.latencySchedule[is.latencyItem%len(is.latencySchedule)]) * time.Second
			is.latencyItem++
			is.Unlock()
			time.Sleep(sleepTime)
		}

		var addChainReq ctSubmissionRequest
		err = json.Unmarshal(bodyBytes, &addChainReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		if len(addChainReq.Chain) == 0 {
			log.Println("no chain")
			w.WriteHeader(400)
			return
		}

		leaf, err := base64.StdEncoding.DecodeString(addChainReq.Chain[0])
		if err != nil {
			log.Println("Error decoding leaf: %s", err)
			w.WriteHeader(400)
			return
		}

		if err = lint(leaf); err != nil {
			log.Println("lint:", err)
			w.WriteHeader(400)
			return
		}

		precert := false
		if r.URL.Path == "/ct/v1/add-pre-chain" {
			precert = true
		}

		w.WriteHeader(http.StatusOK)
		w.Write(publisher.CreateTestingSignedSCT(addChainReq.Chain, is.key, precert))
	case "/submissions":
		if r.Method != "GET" {
			http.NotFound(w, r)
			return
		}

		submissions := atomic.LoadInt64(&is.submissions)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("%d", submissions)))
	default:
		http.NotFound(w, r)
		return
	}
}

type config struct {
	Personalities []Personality
}

type Personality struct {
	// Port (and optionally IP) to listen on
	Addr string
	// Private key for signing SCTs
	// Generate your own with:
	// openssl ecparam -name prime256v1 -genkey -outform der -noout | base64 -w 0
	PrivKey string
	// If present, sleep for the given number of seconds before replying. Each
	// request uses the next number in the list, eventually cycling through.
	LatencySchedule []float64
}

func runPersonality(p Personality) {
	keyDER, err := base64.StdEncoding.DecodeString(p.PrivKey)
	if err != nil {
		log.Fatal(err)
	}
	key, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		log.Fatal(err)
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	is := integrationSrv{
		key:             key,
		latencySchedule: p.LatencySchedule,
	}
	srv := &http.Server{
		Addr:    p.Addr,
		Handler: http.HandlerFunc(is.handler),
	}
	log.Printf("ct-test-srv on %s with pubkey %s", p.Addr,
		base64.StdEncoding.EncodeToString(pubKeyBytes))
	log.Fatal(srv.ListenAndServe())
}

func main() {
	configFile := flag.String("config", "", "Path to config file.")
	flag.Parse()
	data, err := ioutil.ReadFile(*configFile)
	if err != nil {
		log.Fatal(err)
	}
	var c config
	err = json.Unmarshal(data, &c)
	if err != nil {
		log.Fatal(err)
	}

	for _, p := range c.Personalities {
		go runPersonality(p)
	}
	cmd.CatchSignals(nil, nil)
}
