package challtestsrv

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net/http"
	"time"
)

// ALPN protocol ID for TLS-ALPN-01 challenge
// https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-01#section-5.2
const ACMETLS1Protocol = "acme-tls/1"

// IDPeAcmeIdentifier is the identifier defined in
// https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-04#section-5.1
// id-pe OID + 31 (acmeIdentifier)
var IDPeAcmeIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

// AddTLSALPNChallenge adds a new TLS-ALPN-01 key authorization for the given host
func (s *ChallSrv) AddTLSALPNChallenge(host, content string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	s.tlsALPNOne[host] = content
}

// DeleteTLSALPNChallenge deletes the key authorization for a given host
func (s *ChallSrv) DeleteTLSALPNChallenge(host string) {
	s.challMu.Lock()
	defer s.challMu.Unlock()
	delete(s.tlsALPNOne, host)
}

// GetTLSALPNChallenge checks the s.tlsALPNOne map for the given host.
// If it is present it returns the key authorization and true, if not
// it returns an empty string and false.
func (s *ChallSrv) GetTLSALPNChallenge(host string) (string, bool) {
	s.challMu.RLock()
	defer s.challMu.RUnlock()
	content, present := s.tlsALPNOne[host]
	return content, present
}

func (s *ChallSrv) ServeChallengeCertFunc(k *ecdsa.PrivateKey) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		s.AddRequestEvent(TLSALPNRequestEvent{
			ServerName:      hello.ServerName,
			SupportedProtos: hello.SupportedProtos,
		})
		if len(hello.SupportedProtos) != 1 || hello.SupportedProtos[0] != ACMETLS1Protocol {
			return nil, fmt.Errorf(
				"ALPN failed, ClientHelloInfo.SupportedProtos: %s",
				hello.SupportedProtos)
		}

		ka, found := s.GetTLSALPNChallenge(hello.ServerName)
		if !found {
			return nil, fmt.Errorf("unknown ClientHelloInfo.ServerName: %s", hello.ServerName)
		}

		kaHash := sha256.Sum256([]byte(ka))
		extValue, err := asn1.Marshal(kaHash[:])
		if err != nil {
			return nil, fmt.Errorf("failed marshalling hash OCTET STRING: %s", err)
		}
		certTmpl := x509.Certificate{
			SerialNumber: big.NewInt(1729),
			DNSNames:     []string{hello.ServerName},
			ExtraExtensions: []pkix.Extension{
				{
					Id:       IDPeAcmeIdentifier,
					Critical: true,
					Value:    extValue,
				},
			},
		}
		certBytes, err := x509.CreateCertificate(rand.Reader, &certTmpl, &certTmpl, k.Public(), k)
		if err != nil {
			return nil, fmt.Errorf("failed creating challenge certificate: %s", err)
		}
		return &tls.Certificate{
			Certificate: [][]byte{certBytes},
			PrivateKey:  k,
		}, nil
	}
}

type challTLSServer struct {
	*http.Server
}

func (c challTLSServer) Shutdown() error {
	return c.Server.Shutdown(context.Background())
}

func (c challTLSServer) ListenAndServe() error {
	// Since we set TLSConfig.GetCertificate, the certfile and keyFile arguments
	// are ignored and we leave them blank.
	return c.Server.ListenAndServeTLS("", "")
}

func tlsALPNOneServer(address string, challSrv *ChallSrv) challengeServer {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	srv := &http.Server{
		Addr:         address,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			NextProtos:     []string{ACMETLS1Protocol},
			GetCertificate: challSrv.ServeChallengeCertFunc(key),
		},
	}
	srv.SetKeepAlivesEnabled(false)
	return challTLSServer{srv}
}
