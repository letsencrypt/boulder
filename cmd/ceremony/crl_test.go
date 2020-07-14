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

	"github.com/letsencrypt/boulder/pkcs11helpers"
	"github.com/letsencrypt/boulder/test"
	"github.com/miekg/pkcs11"
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

	ctx := pkcs11helpers.MockCtx{}
	ctx.SignInitFunc = func(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
		return nil
	}
	ctx.SignFunc = func(_ pkcs11.SessionHandle, digest []byte) ([]byte, error) {
		r, s, err := ecdsa.Sign(rand.Reader, k, digest[:])
		if err != nil {
			return nil, err
		}
		rBytes := r.Bytes()
		sBytes := s.Bytes()
		// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html
		// Section 2.3.1: EC Signatures
		// "If r and s have different octet length, the shorter of both must be padded with
		// leading zero octets such that both have the same octet length."
		switch {
		case len(rBytes) < len(sBytes):
			padding := make([]byte, len(sBytes)-len(rBytes))
			rBytes = append(padding, rBytes...)
		case len(rBytes) > len(sBytes):
			padding := make([]byte, len(rBytes)-len(sBytes))
			sBytes = append(padding, sBytes...)
		}
		return append(rBytes, sBytes...), nil
	}

	_, err = generateCRL(&x509Signer{ctx: ctx, keyType: pkcs11helpers.ECDSAKey, pub: k.Public()}, cert, time.Time{}.Add(time.Hour), time.Time{}.Add(time.Hour*2), 1, nil)
	test.AssertNotError(t, err, "generateCRL failed with valid profile")
}
