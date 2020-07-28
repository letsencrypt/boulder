package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/test"
)

func TestGenerateCRLTimeBounds(t *testing.T) {
	_, err := generateCRL(nil, nil, time.Time{}.Add(time.Hour), time.Time{}, 1, nil)
	test.AssertError(t, err, "generateCRL did not fail")
	test.AssertEquals(t, err.Error(), "thisUpdate must be before nextUpdate")

	_, err = generateCRL(nil, &x509.Certificate{
		NotBefore: time.Time{}.Add(time.Hour),
		NotAfter:  time.Time{},
	}, time.Time{}, time.Time{}, 1, nil)
	test.AssertError(t, err, "generateCRL did not fail")
	test.AssertEquals(t, err.Error(), "thisUpdate is before issuing certificate's notBefore")

	_, err = generateCRL(nil, &x509.Certificate{
		NotBefore: time.Time{},
		NotAfter:  time.Time{}.Add(time.Hour * 2),
	}, time.Time{}.Add(time.Hour), time.Time{}.Add(time.Hour*3), 1, nil)
	test.AssertError(t, err, "generateCRL did not fail")
	test.AssertEquals(t, err.Error(), "nextUpdate is after issuing certificate's notAfter")
}

func TestGenerateCRLLength(t *testing.T) {
	_, err := generateCRL(nil, &x509.Certificate{
		NotBefore: time.Time{},
		NotAfter:  time.Time{}.Add(time.Hour * 24 * 366),
	}, time.Time{}, time.Time{}.Add(time.Hour*24*366), 1, nil)
	test.AssertError(t, err, "generateCRL did not fail")
	test.AssertEquals(t, err.Error(), "nextUpdate must be less than 12 months after thisUpdate")
}

type emptySigner struct{}

func (p emptySigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func (p emptySigner) Public() crypto.PublicKey {
	return &rsa.PublicKey{N: big.NewInt(1), E: 1}
}

func TestGenerateCRL(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "failed to generate test key")

	template := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "asd"},
		SerialNumber: big.NewInt(7),
		NotBefore:    time.Time{},
		NotAfter:     time.Time{}.Add(time.Hour * 3),
		KeyUsage:     x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{1, 2, 3},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, k.Public(), k)
	test.AssertNotError(t, err, "failed to generate test cert")
	cert, err := x509.ParseCertificate(certBytes)
	test.AssertNotError(t, err, "failed to parse test cert")

	signer := emptySigner{}
	// TODO(#4988): Validate output.
	_, err = generateCRL(signer, cert, time.Time{}.Add(time.Hour), time.Time{}.Add(time.Hour*2), 1, nil)
	test.AssertNotError(t, err, "generateCRL failed with valid profile")
}
