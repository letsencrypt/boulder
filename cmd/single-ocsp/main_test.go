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

func TestSignerValidForResp(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "ecdsa.GenerateKey failed")

	now := time.Now()
	template := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "test"},
		SerialNumber: big.NewInt(1),
		NotBefore:    now,
		NotAfter:     now.Add(time.Hour * 3),
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, template, template, k.Public(), k)
	test.AssertNotError(t, err, "failed to create issuer cert")
	issuer, err := x509.ParseCertificate(issuerDER)
	test.AssertNotError(t, err, "failed to parse issuer cert")

	responderDER, err := x509.CreateCertificate(rand.Reader, template, issuer, k.Public(), k)
	test.AssertNotError(t, err, "failed to create responder cert")
	responder, err := x509.ParseCertificate(responderDER)
	test.AssertNotError(t, err, "failed to parse responder cert")

	err = signerValidForResp(issuer, responder, time.Time{}, time.Time{})
	test.AssertError(t, err, "signerValidForResp didn't fail")
	test.AssertEquals(t, err.Error(), "invalid signature on responder from issuer: x509: invalid signature: parent certificate cannot sign this kind of certificate")

	template.IsCA, template.BasicConstraintsValid = true, true
	issuerDER, err = x509.CreateCertificate(rand.Reader, template, template, k.Public(), k)
	test.AssertNotError(t, err, "failed to create issuer cert")
	issuer, err = x509.ParseCertificate(issuerDER)
	test.AssertNotError(t, err, "failed to parse issuer cert")
	err = signerValidForResp(issuer, responder, time.Time{}, time.Time{})
	test.AssertError(t, err, "signerValidForResp didn't fail")
	test.AssertEquals(t, err.Error(), "responder certificate doesn't contain OCSPSigning extended key usage")

	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	responderDER, err = x509.CreateCertificate(rand.Reader, template, issuer, k.Public(), k)
	test.AssertNotError(t, err, "failed to create responder cert")
	responder, err = x509.ParseCertificate(responderDER)
	test.AssertNotError(t, err, "failed to parse responder cert")

	err = signerValidForResp(issuer, responder, time.Time{}, time.Time{})
	test.AssertError(t, err, "signerValidForResp didn't fail")
	test.AssertEquals(t, err.Error(), "thisUpdate is before responder certificate's notBefore")

	err = signerValidForResp(issuer, responder, now.Add(time.Hour), now.Add(time.Hour*4))
	test.AssertError(t, err, "signerValidForResp didn't fail")
	test.AssertEquals(t, err.Error(), "nextUpdate is after responder certificate's notAfter")

	err = signerValidForResp(issuer, responder, now.Add(time.Hour), now.Add(time.Hour*2))
	test.AssertNotError(t, err, "signerValidForResp failed")
}
