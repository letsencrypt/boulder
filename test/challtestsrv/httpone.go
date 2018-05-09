package challtestsrv

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
	s.challMu.Lock()
	defer s.challMu.Unlock()
	s.httpOne[token] = content
}

// DeleteHTTPOneChallenge deletes a given HTTP-01 challenge token.
func (s *ChallSrv) DeleteHTTPOneChallenge(token string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	if _, ok := s.httpOne[token]; ok {
		delete(s.httpOne, token)
	}
}

// GetHTTPOneChallenge returns the HTTP-01 challenge content for the given token
// (if it exists) and a true bool. If the token does not exist then an empty
// string and a false bool are returned.
func (s *ChallSrv) GetHTTPOneChallenge(token string) (string, bool) {
	s.challMu.RLock()
	defer s.challMu.RUnlock()
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

// challHTTPServer is a *http.Server that has a Shutdown() func that doesn't
// take a context argument. This lets us treat the HTTP server the same as the
// DNS-01 servers (which use a `dns.Server` that has `Shutdown()` with no
// context arg) by having an http.Server that implements the challengeServer
// interface.
type challHTTPServer struct {
	*http.Server
}

func (c challHTTPServer) Shutdown() error {
	return c.Server.Shutdown(context.Background())
}

// httpOneServer creates an ACME HTTP-01 challenge server. The
// server's handler will return configured HTTP-01 challenge responses for
// tokens that have been added to the challenge server.
func httpOneServer(address string, handler http.Handler) challengeServer {
	// Create an HTTP Server for HTTP-01 challenges
	srv := &http.Server{
		Addr:         address,
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	srv.SetKeepAlivesEnabled(false)
	return challHTTPServer{srv}
}
