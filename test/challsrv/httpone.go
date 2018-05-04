package challsrv

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const wellKnownPath = "/.well-known/acme-challenge/"

// AddHTTPOneChallenge adds a new HTTP-01 challenge for the given token and
// content.
func (s *ChallSrv) AddHTTPOneChallenge(token, content string) {
	s.hoMu.Lock()
	defer s.hoMu.Unlock()
	s.httpOne[token] = content
}

// DeleteHTTPOneChallenge deletes a given HTTP-01 challenge token.
func (s *ChallSrv) DeleteHTTPOneChallenge(token string) {
	s.hoMu.Lock()
	defer s.hoMu.Unlock()
	if _, ok := s.httpOne[token]; ok {
		delete(s.httpOne, token)
	}
}

// GetHTTPOneChallenge returns the HTTP-01 challenge content for the given token
// (if it exists) and a true bool. If the token does not exist then an empty
// string and a false bool are returned.
func (s *ChallSrv) GetHTTPOneChallenge(token string) (string, bool) {
	s.hoMu.RLock()
	defer s.hoMu.RUnlock()
	content, present := s.httpOne[token]
	return content, present
}

// ServeHTTP handles an HTTP request. If the request path has the ACME HTTP-01
// challenge well known prefix as a prefix and the token specified is known,
// then the challenge response contents are returned.
func (s *ChallSrv) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestPath := r.URL.Path
	if strings.HasPrefix(requestPath, wellKnownPath) {
		token := requestPath[len(wellKnownPath):]
		if auth, found := s.GetHTTPOneChallenge(token); found {
			fmt.Fprintf(w, "%s", auth)
		}
	}
}

// httpOneServer creates and starts an ACME HTTP-01 challenge server. The
// server's handler will return configured HTTP-01 challenge responses for
// tokens that have been added to the challenge server. A cleanup function is
// returned to the caller that should be used to request the clean shutdown of
// the HTTP server.
func (s *ChallSrv) httpOneServer(address string) func() {
	s.log.Printf("Starting HTTP-01 challenge server on %s\n", address)
	// Create an HTTP Server for HTTP-01 challenges
	srv := &http.Server{
		Addr:         address,
		Handler:      s,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	srv.SetKeepAlivesEnabled(false)
	// Start the HTTP server on its own Go routine
	go func() {
		err := srv.ListenAndServe()
		if err != nil {
			s.log.Print(err)
		}
	}()
	// Return a cleanup function that shuts down the HTTP server.
	return func() {
		s.log.Printf("Shutting down HTTP-01 server on %s", address)
		if err := srv.Shutdown(context.Background()); err != nil {
			s.log.Printf("Err shutting down HTTP-01 server on %s: %s", address, err)
		}
	}
}
