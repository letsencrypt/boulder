package test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/jmhodges/clock"
)

// ThrowAwayCert is a small test helper function that creates a self-signed
// certificate with one SAN. It returns the parsed certificate and its serial
// in string form for convenience.
// The certificate returned from this function is the bare minimum needed for
// most tests and isn't a robust example of a complete end entity certificate.
func ThrowAwayCert(t *testing.T, clk clock.Clock) (string, *x509.Certificate) {
	var nameBytes [3]byte
	_, _ = rand.Read(nameBytes[:])
	name := fmt.Sprintf("%s.example.com", hex.EncodeToString(nameBytes[:]))

	// Generate a random IPv6 address under the RFC 3849 space.
	// https://www.rfc-editor.org/rfc/rfc3849.txt
	var ipBytes [12]byte
	_, _ = rand.Read(ipBytes[:])
	ipPrefix, _ := hex.DecodeString("20010db8")
	ip := net.IP(bytes.Join([][]byte{ipPrefix, ipBytes[:]}, nil))

	var serialBytes [16]byte
	_, _ = rand.Read(serialBytes[:])
	serial := big.NewInt(0).SetBytes(serialBytes[:])

	key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	AssertNotError(t, err, "rsa.GenerateKey failed")

	template := &x509.Certificate{
		SerialNumber:          serial,
		DNSNames:              []string{name},
		IPAddresses:           []net.IP{ip},
		NotBefore:             clk.Now(),
		NotAfter:              clk.Now().Add(6 * 24 * time.Hour),
		IssuingCertificateURL: []string{"http://localhost:4001/issuer/1234/cert"},
		CRLDistributionPoints: []string{"http://localhost:4002/issuer/1234/crl/1"},
	}

	testCertDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	AssertNotError(t, err, "x509.CreateCertificate failed")
	testCert, err := x509.ParseCertificate(testCertDER)
	AssertNotError(t, err, "failed to parse self-signed cert DER")

	return fmt.Sprintf("%036x", serial), testCert
}
