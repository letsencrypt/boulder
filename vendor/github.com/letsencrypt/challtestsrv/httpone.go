package challtestsrv

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// wellKnownPath is the IANA registered ACME HTTP-01 challenge path. See
// https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-9.2
const wellKnownPath = "/.well-known/acme-challenge/"

// cert is a self-signed certificate issued at startup for the HTTPS HTTP-01
// server.
var cert = selfSignedCert()

// selfSignedCert issues a self-signed CA certificate to use as the leaf
// certificate for an HTTPS server serving HTTP-01 challenges. This certificate
// will not be trusted by normal TLS clients but HTTP-01 redirects to HTTPS will
// ignore certificate validation.
func selfSignedCert() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("Unable to generate HTTPS ECDSA key: %v", err))
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		panic(fmt.Sprintf("Unable to generate HTTPS cert serial number: %v", err))
	}

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "challenge test server",
		},
		SerialNumber:          serial,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		panic(fmt.Sprintf("Unable to issue HTTPS cert: %v", err))
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
}

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
	delete(s.httpOne, token)
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

// AddHTTPRedirect adds a redirect for the given path to the given URL.
func (s *ChallSrv) AddHTTPRedirect(path, targetURL string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	s.redirects[path] = targetURL
}

// DeleteHTTPRedirect deletes a redirect for the given path.
func (s *ChallSrv) DeleteHTTPRedirect(path string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	delete(s.redirects, path)
}

// GetHTTPRedirect returns the redirect target for the given path
// (if it exists) and a true bool. If the path does not have a redirect target
// then an empty string and a false bool are returned.
func (s *ChallSrv) GetHTTPRedirect(path string) (string, bool) {
	s.challMu.RLock()
	defer s.challMu.RUnlock()
	targetURL, present := s.redirects[path]
	return targetURL, present
}

// ServeHTTP handles an HTTP request. If the request path has the ACME HTTP-01
// challenge well known prefix as a prefix and the token specified is known,
// then the challenge response contents are returned.
func (s *ChallSrv) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestPath := r.URL.Path

	serverName := ""
	if r.TLS != nil {
		serverName = r.TLS.ServerName
	}

	s.AddRequestEvent(HTTPRequestEvent{
		URL:        r.URL.String(),
		Host:       r.Host,
		HTTPS:      r.TLS != nil,
		ServerName: serverName,
	})

	// If the request was not over HTTPS and we have a redirect, serve it.
	// Redirects are ignored over HTTPS so we can easily do an HTTP->HTTPS
	// redirect for a token path without creating a loop.
	if redirectTarget, found := s.GetHTTPRedirect(requestPath); found && r.TLS == nil {
		http.Redirect(w, r, redirectTarget, http.StatusFound)
		return
	}

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

// ListenAndServe for a challHTTPServer will call the underlying http.Server's
// ListenAndServeTLS if the server has a non-nil TLSConfig, otherwise it will
// use the underlying http.Server's ListenAndServe(). This allows for
// a challHTTPServer to be both a normal HTTP based HTTP-01 challenge response
// server in one configuration (nil TLSConfig) and an HTTPS based HTTP-01
// challenge response server useful for redirect targets in another
// configuration.
func (c challHTTPServer) ListenAndServe() error {
	if c.Server.TLSConfig != nil {
		// This will use the certificate and key from TLSConfig.
		return c.Server.ListenAndServeTLS("", "")
	}
	// Otherwise use HTTP
	return c.Server.ListenAndServe()
}

func (c challHTTPServer) Shutdown() error {
	return c.Server.Shutdown(context.Background())
}

// httpOneServer creates an ACME HTTP-01 challenge server. The
// server's handler will return configured HTTP-01 challenge responses for
// tokens that have been added to the challenge server. If HTTPS is true the
// resulting challengeServer will run a HTTPS server with a self-signed
// certificate useful for HTTP-01 -> HTTPS HTTP-01 redirect responses. If HTTPS
// is false the resulting challengeServer will run an HTTP server.
func httpOneServer(address string, handler http.Handler, https bool) challengeServer {
	// If HTTPS is requested build a TLS Config that uses the self-signed
	// certificate generated at startup.
	var tlsConfig *tls.Config
	if https {
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	}
	// Create an HTTP Server for HTTP-01 challenges
	srv := &http.Server{
		Addr:         address,
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		TLSConfig:    tlsConfig,
	}
	srv.SetKeepAlivesEnabled(false)
	return challHTTPServer{srv}
}
