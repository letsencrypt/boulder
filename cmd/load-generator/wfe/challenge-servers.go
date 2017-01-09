package wfe

import (
	rand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ChallSrv wraps a tiny challenge webserver
type ChallSrv struct {
	hoMu        sync.RWMutex
	httpOne     map[string]string
	httpOneAddr string

	tlsOneAddr string

	// doMu       sync.RWMutex
	// dnsOne     map[string]string
	// dnsOneAddr string
}

func newChallSrv(httpOneAddr, tlsOneAddr string) *ChallSrv {
	return &ChallSrv{
		httpOne:     make(map[string]string),
		httpOneAddr: httpOneAddr,
		tlsOneAddr:  tlsOneAddr,
	}
}

// Run runs the challenge server on the configured address
func (s *ChallSrv) run() {
	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		err := s.httpOneServer(wg)
		if err != nil {
			fmt.Printf("[!] http-0 server failed: %s\n", err)
			os.Exit(1)
		}
	}()
	wg.Add(1)
	go func() {
		err := s.tlsOneServer(wg)
		if err != nil {
			fmt.Printf("[!] tls-sni-01 server failed: %s\n", err)
			os.Exit(1)
		}
	}()
	wg.Wait()
}

func (s *ChallSrv) addHTTPOneChallenge(token, content string) {
	s.hoMu.Lock()
	defer s.hoMu.Unlock()
	s.httpOne[token] = content
}

func (s *ChallSrv) deleteHTTPOneChallenge(token string) {
	s.hoMu.Lock()
	defer s.hoMu.Unlock()
	if _, ok := s.httpOne[token]; ok {
		delete(s.httpOne, token)
	}
}

func (s *ChallSrv) getHTTPOneChallenge(token string) (string, bool) {
	s.hoMu.RLock()
	defer s.hoMu.RUnlock()
	content, present := s.httpOne[token]
	return content, present
}

func (s *ChallSrv) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestPath := r.URL.Path
	if strings.HasPrefix(requestPath, "/.well-known/acme-challenge/") {
		token := requestPath[28:]
		if auth, found := s.getHTTPOneChallenge(token); found {
			// fmt.Printf("http-0 challenge request for %s\n", token)
			fmt.Fprintf(w, "%s", auth)
			s.deleteHTTPOneChallenge(token)
		}
	}
}

func (s *ChallSrv) httpOneServer(wg *sync.WaitGroup) error {
	fmt.Println("[+] Starting http-01 server")
	srv := &http.Server{
		Addr:         s.httpOneAddr,
		Handler:      s,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	srv.SetKeepAlivesEnabled(false)
	wg.Done()
	return srv.ListenAndServe()
}

func (s *ChallSrv) tlsOneServer(wg *sync.WaitGroup) error {
	fmt.Println("[+] Starting tls-sni-01 server")

	tinyKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	l, err := tls.Listen("tcp", s.tlsOneAddr, &tls.Config{
		ClientAuth: tls.NoClientCert,
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			t := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				DNSNames:     []string{clientHello.ServerName},
				Subject:      pkix.Name{CommonName: "test"},
			}
			inner, err := x509.CreateCertificate(rand.Reader, t, t, tinyKey.Public(), tinyKey)
			if err != nil {
				fmt.Printf("[!] Failed to sign test certificate: %s\n", err)
				return nil, nil
			}
			return &tls.Certificate{Certificate: [][]byte{inner}, PrivateKey: tinyKey}, nil
		},
		NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		return err
	}
	wg.Done()
	for {
		conn, err := l.Accept()
		if err != nil {
			fmt.Printf("[!] TLS connection failed: %s\n", err)
			continue
		}
		go func() {
			defer conn.Close()
			tlsConn := conn.(*tls.Conn)
			err = tlsConn.Handshake()
			if err != nil {
				fmt.Printf("[!] TLS handshake failed: %s\n", err)
				return
			}
		}()
	}
}
