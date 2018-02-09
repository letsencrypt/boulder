// This is a test server that implements the subset of RFC6962 APIs needed to
// run Boulder's CT log submission code. Currently it only implements add-chain.
// This is used by startservers.py.
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	ct "github.com/google/certificate-transparency-go"
	ctTLS "github.com/google/certificate-transparency-go/tls"
	"github.com/letsencrypt/boulder/cmd"
)

func createSignedSCT(leaf []byte, k *ecdsa.PrivateKey) []byte {
	rawKey, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	pkHash := sha256.Sum256(rawKey)
	sct := ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		LogID:      ct.LogID{KeyID: pkHash},
		Timestamp:  1337,
	}
	serialized, _ := ct.SerializeSCTSignatureInput(sct, ct.LogEntry{
		Leaf: ct.MerkleTreeLeaf{
			LeafType: ct.TimestampedEntryLeafType,
			TimestampedEntry: &ct.TimestampedEntry{
				X509Entry: &ct.ASN1Cert{Data: leaf},
				EntryType: ct.X509LogEntryType,
			},
		},
	})
	hashed := sha256.Sum256(serialized)
	var ecdsaSig struct {
		R, S *big.Int
	}
	ecdsaSig.R, ecdsaSig.S, _ = ecdsa.Sign(rand.Reader, k, hashed[:])
	sig, _ := asn1.Marshal(ecdsaSig)

	ds := ct.DigitallySigned{
		Algorithm: ctTLS.SignatureAndHashAlgorithm{
			Hash:      ctTLS.SHA256,
			Signature: ctTLS.ECDSA,
		},
		Signature: sig,
	}

	var jsonSCTObj struct {
		SCTVersion ct.Version `json:"sct_version"`
		ID         string     `json:"id"`
		Timestamp  uint64     `json:"timestamp"`
		Extensions string     `json:"extensions"`
		Signature  string     `json:"signature"`
	}
	jsonSCTObj.SCTVersion = ct.V1
	jsonSCTObj.ID = base64.StdEncoding.EncodeToString(pkHash[:])
	jsonSCTObj.Timestamp = 1337
	jsonSCTObj.Signature, _ = ds.Base64String()

	jsonSCT, _ := json.Marshal(jsonSCTObj)
	return jsonSCT
}

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

func (is *integrationSrv) handler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
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
			w.WriteHeader(400)
			return
		}

		leaf, err := base64.StdEncoding.DecodeString(addChainReq.Chain[0])
		if err != nil {
			w.WriteHeader(400)
			return
		}

		w.WriteHeader(http.StatusOK)
		// id is a sha256 of a random EC key. Generate your own with:
		// openssl ecparam -name prime256v1 -genkey -outform der | openssl sha256 -binary | base64
		w.Write(createSignedSCT(leaf, is.key))
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
	PrivKey string
	// If present, sleep for the given number of seconds before replying. Each
	// request uses the next number in the list, eventually cycling through.
	LatencySchedule []float64
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
		keyDER, err := base64.StdEncoding.DecodeString(p.PrivKey)
		if err != nil {
			log.Fatal(err)
		}
		key, err := x509.ParseECPrivateKey(keyDER)
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
		go func() {
			log.Fatal(srv.ListenAndServe())
		}()
	}
	cmd.CatchSignals(nil, nil)
}
