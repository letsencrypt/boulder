package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/test"
)

func TestGenerateCRL(t *testing.T) {
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

	_, err = generateCRL(k, cert, time.Time{}.Add(time.Hour), time.Time{}.Add(time.Hour*2), 1, nil)
	test.AssertNotError(t, err, "generateCRL failed with valid profile")
}
