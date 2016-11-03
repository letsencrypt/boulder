package creds

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/context"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/test"
)

func TestServerTransportCredentials(t *testing.T) {
	var bcreds *transportCredentials

	whitelist := map[string]struct{}{
		"boulder": struct{}{},
	}

	goodCert, err := core.LoadCert("../../test/grpc-creds/client.pem")
	test.AssertNotError(t, err, "core.LoadCert('../../grpc-creds/client.pem') failed")
	badCert, err := core.LoadCert("../../test/test-root.pem")
	test.AssertNotError(t, err, "core.LoadCert('../../test-root.pem') failed")

	servTLSConfig := &tls.Config{}

	// A creds with a nil serverTLSConfig should return an error if we try to use
	// it for a server handshake
	bcreds = &transportCredentials{nil, nil, whitelist}
	_, _, err = bcreds.ServerHandshake(nil)
	test.AssertEquals(t, err.Error(),
		"boulder/grpc/creds: Server-side handshake not supported without non-nil `serverConfig`")

	// A creds with a nil whitelist should consider any peer whitelisted
	bcreds = &transportCredentials{nil, servTLSConfig, nil}
	emptyState := tls.ConnectionState{}
	whitelisted, err := bcreds.peerIsWhitelisted(emptyState)
	test.AssertNotError(t, err, "peerIsWhitelisted() errored for emptyState")
	test.AssertEquals(t, whitelisted, true)

	// A creds with a whitelist should reject peers without VerifiedChains
	bcreds = &transportCredentials{nil, servTLSConfig, whitelist}
	whitelisted, err = bcreds.peerIsWhitelisted(emptyState)
	test.AssertError(t, err, "peer had zero VerifiedChains")
	test.AssertEquals(t, whitelisted, false)

	// A creds with a whitelist should reject peers that don't have any
	// VerifiedChains that begin with a whitelisted subject CN leaf cert
	wrongState := tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{[]*x509.Certificate{badCert}},
	}
	whitelisted, err = bcreds.peerIsWhitelisted(wrongState)
	test.AssertError(t, err, "peer's verified TLS chains did not include a "+
		"leaf certificate with a whitelisted subject CN")
	test.AssertEquals(t, whitelisted, false)

	// A creds with a whitelist should accept peers that have a VerifiedChains
	// chain that *does* have a whitelisted leaf cert
	rightState := tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{[]*x509.Certificate{goodCert}},
	}
	whitelisted, err = bcreds.peerIsWhitelisted(rightState)
	test.AssertNotError(t, err, "peerIsWhitelisted(rightState) failed")
	test.AssertEquals(t, whitelisted, true)

	// A creds with a whitelist should accept peers that have a VerifiedChains
	// chain that *does* have a whitelisted leaf cert, even if one of the other
	// chains does not
	twoChainzState := tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{
			[]*x509.Certificate{badCert},
			[]*x509.Certificate{goodCert},
		},
	}
	whitelisted, err = bcreds.peerIsWhitelisted(twoChainzState)
	test.AssertNotError(t, err, "peerIsWhitelisted(twoChainzState) failed")
	test.AssertEquals(t, whitelisted, true)
}

func TestClientTransportCredentials(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	test.AssertNotError(t, err, "rsa.GenerateKey failed")

	temp := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "A",
		},
		NotBefore:             time.Unix(1000, 0),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		BasicConstraintsValid: true,
		IsCA: true,
	}
	derA, err := x509.CreateCertificate(rand.Reader, temp, temp, priv.Public(), priv)
	test.AssertNotError(t, err, "x509.CreateCertificate failed")
	certA, err := x509.ParseCertificate(derA)
	test.AssertNotError(t, err, "x509.ParserCertificate failed")
	temp.Subject.CommonName = "B"
	derB, err := x509.CreateCertificate(rand.Reader, temp, temp, priv.Public(), priv)
	test.AssertNotError(t, err, "x509.CreateCertificate failed")
	certB, err := x509.ParseCertificate(derB)
	test.AssertNotError(t, err, "x509.ParserCertificate failed")
	roots := x509.NewCertPool()
	roots.AddCert(certA)
	roots.AddCert(certB)

	serverA := httptest.NewUnstartedServer(nil)
	serverA.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{derA}, PrivateKey: priv}}}
	serverB := httptest.NewUnstartedServer(nil)
	serverB.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{derB}, PrivateKey: priv}}}

	// A creds with a nil `clientConfig` should return an error if we try to use
	// it for a client handshake
	nilTC := New(nil, nil, nil)
	_, _, err = nilTC.ClientHandshake(nil, "", nil)
	test.AssertEquals(t, err.Error(),
		"boulder/grpc/creds: Client-side handshake not supported without non-nil `clientConfig`")

	clientTLSConfig := &tls.Config{
		RootCAs:      roots,
		Certificates: []tls.Certificate{},
	}
	tc := New(clientTLSConfig, nil, nil)

	serverA.StartTLS()
	defer serverA.Close()
	addrA := serverA.Listener.Addr().String()
	rawConnA, err := net.Dial("tcp", addrA)
	test.AssertNotError(t, err, "net.Dial failed")
	defer func() {
		_ = rawConnA.Close()
	}()

	conn, _, err := tc.ClientHandshake(context.Background(), "A:2020", rawConnA)
	test.AssertNotError(t, err, "tc.ClientHandshake failed")
	test.Assert(t, conn != nil, "tc.ClientHandshake returned a nil net.Conn")

	serverB.StartTLS()
	defer serverB.Close()
	addrB := serverB.Listener.Addr().String()
	rawConnB, err := net.Dial("tcp", addrB)
	test.AssertNotError(t, err, "net.Dial failed")
	defer func() {
		_ = rawConnB.Close()
	}()

	conn, _, err = tc.ClientHandshake(context.Background(), "B:3030", rawConnB)
	test.AssertNotError(t, err, "tc.ClientHandshake failed")
	test.Assert(t, conn != nil, "tc.ClientHandshake returned a nil net.Conn")

	// Test timeout
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	test.AssertNotError(t, err, "net.Listen failed")
	defer func() {
		_ = ln.Close()
	}()
	addrC := ln.Addr().String()
	stop := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = ln.Accept()
				time.Sleep(2 * time.Millisecond)
			}
		}
	}()

	rawConnC, err := net.Dial("tcp", addrC)
	test.AssertNotError(t, err, "net.Dial failed")
	defer func() {
		_ = rawConnB.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	conn, _, err = tc.ClientHandshake(ctx, "A:2020", rawConnC)
	test.AssertError(t, err, "tc.ClientHandshake didn't timeout")
	test.AssertEquals(t, err.Error(), "boulder/grpc/creds: context deadline exceeded")
	test.Assert(t, conn == nil, "tc.ClientHandshake returned a non-nil net.Conn on failure")

	stop <- struct{}{}
}
