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

	"github.com/letsencrypt/boulder/test"
)

func TestTransportCredentials(t *testing.T) {
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

	tc := New(roots, nil)

	serverA.StartTLS()
	defer serverA.Close()
	addrA := serverA.Listener.Addr().String()
	rawConnA, err := net.Dial("tcp", addrA)
	test.AssertNotError(t, err, "net.Dial failed")
	defer func() {
		_ = rawConnA.Close()
	}()

	conn, _, err := tc.ClientHandshake("A:2020", rawConnA, time.Second)
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

	conn, _, err = tc.ClientHandshake("B:3030", rawConnB, time.Second)
	test.AssertNotError(t, err, "tc.ClientHandshake failed")
	test.Assert(t, conn != nil, "tc.ClientHandshake returned a nil net.Conn")

	// Test timeout
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	test.AssertNotError(t, err, "net.Listen failed")
	defer func() {
		_ = ln.Close()
	}()
	addrC := ln.Addr().String()
	go func() {
		for {
			_, err := ln.Accept()
			test.AssertNotError(t, err, "ln.Accept failed")
			time.Sleep(time.Second)
		}
	}()

	rawConnC, err := net.Dial("tcp", addrC)
	test.AssertNotError(t, err, "net.Dial failed")
	defer func() {
		_ = rawConnB.Close()
	}()

	conn, _, err = tc.ClientHandshake("A:2020", rawConnC, time.Millisecond)
	test.AssertError(t, err, "tc.ClientHandshake didn't timeout")
	test.AssertEquals(t, err.Error(), "boulder/grpc/creds: TLS handshake timed out")
	test.Assert(t, conn == nil, "tc.ClientHandshake returned a non-nil net.Conn on failure")
}
