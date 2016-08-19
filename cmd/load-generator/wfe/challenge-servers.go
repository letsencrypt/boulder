package wfe

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ChallSrv wraps a tiny challenge webserver
type ChallSrv struct {
	hoMu        *sync.RWMutex
	httpOne     map[string]string
	httpOneAddr string

	rpcAddr string
}

// NewChallSrv returns a pointer to a new ChallSrv
func NewChallSrv(hoAddr, rpcAddr string) *ChallSrv {
	return &ChallSrv{
		hoMu:        new(sync.RWMutex),
		httpOne:     make(map[string]string),
		httpOneAddr: hoAddr,
		rpcAddr:     rpcAddr,
	}
}

// Run runs the challenge server on the configured address
func (s *ChallSrv) Run() {
	go func() {
		err := s.httpOneServer()
		if err != nil {
			fmt.Printf("[+] http-0 server failed: %s\n", err)
			os.Exit(1)
		}
	}()
	go func() {
		err := s.rpcServer()
		if err != nil {
			fmt.Printf("[+] RPC server failed: %s\n", err)
			os.Exit(1)
		}
	}()
	forever := make(chan struct{}, 1)
	<-forever
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

func (s *ChallSrv) httpOneServer() error {
	fmt.Println("[+] Starting http-01 server")
	srv := &http.Server{
		Addr:         s.httpOneAddr,
		Handler:      s,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	srv.SetKeepAlivesEnabled(false)
	return srv.ListenAndServe()
}

func (s *ChallSrv) hoRPC(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("[!] Failed to read RPC body: %s\n", err)
		w.WriteHeader(400)
		return
	}
	fields := strings.Split(string(body), ";;")
	s.addHTTPOneChallenge(fields[0], fields[1])
	w.WriteHeader(200)
}

func (s *ChallSrv) rpcServer() error {
	fmt.Println("[+] Starting challenge RPC server")
	http.HandleFunc("/ho", s.hoRPC)
	return http.ListenAndServe(s.rpcAddr, nil)
}
