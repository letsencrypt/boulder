package linter

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestMakeSigner_RSA(t *testing.T) {
	rsaMod, ok := big.NewInt(0).SetString(strings.Repeat("ff", 128), 16)
	test.Assert(t, ok, "failed to set RSA mod")
	realSigner := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: rsaMod,
		},
	}
	lintSigner, err := makeSigner(realSigner)
	test.AssertNotError(t, err, "makeSigner failed")
	_, ok = lintSigner.(*rsa.PrivateKey)
	test.Assert(t, ok, "lint signer is not RSA")
}

func TestMakeSigner_ECDSA(t *testing.T) {
	realSigner := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
		},
	}
	lintSigner, err := makeSigner(realSigner)
	test.AssertNotError(t, err, "makeSigner failed")
	_, ok := lintSigner.(*ecdsa.PrivateKey)
	test.Assert(t, ok, "lint signer is not ECDSA")
}

func TestMakeSigner_Unsupported(t *testing.T) {
	realSigner := ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
	_, err := makeSigner(realSigner)
	test.AssertError(t, err, "makeSigner shouldn't have succeeded")
}

func TestMakeIssuer(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		t.Fatal(err)
	}

	idRDNATrustAnchorIDExperimental := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 1}
	template := &x509.Certificate{
		Subject: pkix.Name{
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  idRDNATrustAnchorIDExperimental,
					Value: asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte("44947.4.2.1")},
				},
			},
		},
	}
	realIssuerBytes, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	realIssuer, err := x509.ParseCertificate(realIssuerBytes)
	if err != nil {
		t.Fatal(err)
	}

	expectedSubject, err := hex.DecodeString("301d311b3019060a2b0601040182da4b2f010c0b34343934372e342e322e31")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(realIssuer.RawSubject, expectedSubject) {
		t.Fatalf("realIssuer Subject: got %x, want %x", realIssuer.RawSubject, expectedSubject)
	}

	linter, err := New(realIssuer, key)
	if err != nil {
		t.Fatal(err)
	}

	eeKey, err := ecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		t.Fatal(err)
	}

	ee := &x509.Certificate{}

	lintCertBytes, err := linter.Check(ee, eeKey.Public(), nil)
	if err != nil {
		t.Fatal(err)
	}

	lintCert, err := x509.ParseCertificate(lintCertBytes)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(lintCert.RawIssuer, realIssuer.RawSubject) {
		t.Errorf("linting certificate issuer: got %x, want %x", lintCert.RawIssuer, realIssuer.RawSubject)
	}
}
