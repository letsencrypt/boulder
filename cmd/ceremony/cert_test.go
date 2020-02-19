package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"

	"github.com/letsencrypt/boulder/pkcs11helpers"
	"github.com/letsencrypt/boulder/test"
	"github.com/miekg/pkcs11"
)

func TestX509Signer(t *testing.T) {
	ctx := pkcs11helpers.MockCtx{}

	// test that x509Signer.Sign properly converts the PKCS#11 format signature to
	// the RFC 5480 format signature
	ctx.SignInitFunc = func(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
		return nil
	}
	tk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "Failed to generate test key")
	ctx.SignFunc = func(_ pkcs11.SessionHandle, digest []byte) ([]byte, error) {
		r, s, err := ecdsa.Sign(rand.Reader, tk, digest[:])
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
	digest := sha256.Sum256([]byte("hello"))
	signer := &x509Signer{ctx: ctx, keyType: pkcs11helpers.ECDSAKey, pub: tk.Public()}
	signature, err := signer.Sign(nil, digest[:], crypto.SHA256)
	test.AssertNotError(t, err, "x509Signer.Sign failed")

	var rfcFormat struct {
		R, S *big.Int
	}
	rest, err := asn1.Unmarshal(signature, &rfcFormat)
	test.AssertNotError(t, err, "asn1.Unmarshal failed trying to parse signature")
	test.Assert(t, len(rest) == 0, "Signature had trailing garbage")
	verified := ecdsa.Verify(&tk.PublicKey, digest[:], rfcFormat.R, rfcFormat.S)
	test.Assert(t, verified, "Failed to verify RFC format signature")
	// For the sake of coverage
	test.AssertEquals(t, signer.Public(), tk.Public())
}

func TestParseOID(t *testing.T) {
	_, err := parseOID("")
	test.AssertError(t, err, "parseOID accepted an empty OID")
	_, err = parseOID("a.b.c")
	test.AssertError(t, err, "parseOID accepted an OID containing non-ints")
	oid, err := parseOID("1.2.3")
	test.AssertNotError(t, err, "parseOID failed with a valid OID")
	test.Assert(t, oid.Equal(asn1.ObjectIdentifier{1, 2, 3}), "parseOID returned incorrect OID")
}

func TestMakeTemplate(t *testing.T) {
	ctx := pkcs11helpers.MockCtx{}
	profile := &certProfile{}

	profile.NotBefore = "1234"
	_, err := makeTemplate(ctx, 0, profile, nil)
	test.AssertError(t, err, "makeTemplate didn't fail with invalid not before")

	profile.NotBefore = "2018-05-18 11:31:00"
	profile.NotAfter = "1234"
	_, err = makeTemplate(ctx, 0, profile, nil)
	test.AssertError(t, err, "makeTemplate didn't fail with invalid not after")

	profile.NotAfter = "2018-05-18 11:31:00"
	profile.PolicyOIDs = []string{""}
	_, err = makeTemplate(ctx, 0, profile, nil)
	test.AssertError(t, err, "makeTemplate didn't fail with invalid policy OID")

	profile.PolicyOIDs = []string{"1.2.3"}
	profile.SignatureAlgorithm = "nope"
	_, err = makeTemplate(ctx, 0, profile, nil)
	test.AssertError(t, err, "makeTemplate didn't fail with invalid signature algorithm")

	profile.SignatureAlgorithm = "SHA256WithRSA"
	ctx.GenerateRandomFunc = func(pkcs11.SessionHandle, int) ([]byte, error) {
		return nil, errors.New("bad")
	}
	_, err = makeTemplate(ctx, 0, profile, nil)
	test.AssertError(t, err, "makeTemplate didn't fail when GenerateRandom failed")

	ctx.GenerateRandomFunc = func(_ pkcs11.SessionHandle, length int) ([]byte, error) {
		r := make([]byte, length)
		_, err := rand.Read(r)
		return r, err
	}

	_, err = makeTemplate(ctx, 0, profile, nil)
	test.AssertError(t, err, "makeTemplate didn't fail with empty key usages")

	profile.KeyUsages = []string{"asd"}
	_, err = makeTemplate(ctx, 0, profile, nil)
	test.AssertError(t, err, "makeTemplate didn't fail with invalid key usages")

	profile.KeyUsages = []string{"Digital Signature", "CRL Sign"}
	profile.CommonName = "common name"
	profile.Organization = "organization"
	profile.Country = "country"
	profile.OCSPURL = "ocsp"
	profile.CRLURL = "crl"
	profile.IssuerURL = "issuer"
	cert, err := makeTemplate(ctx, 0, profile, nil)
	test.AssertNotError(t, err, "makeTemplate failed when everything worked as expected")
	test.AssertEquals(t, cert.Subject.CommonName, profile.CommonName)
	test.AssertEquals(t, len(cert.Subject.Organization), 1)
	test.AssertEquals(t, cert.Subject.Organization[0], profile.Organization)
	test.AssertEquals(t, len(cert.Subject.Country), 1)
	test.AssertEquals(t, cert.Subject.Country[0], profile.Country)
	test.AssertEquals(t, len(cert.OCSPServer), 1)
	test.AssertEquals(t, cert.OCSPServer[0], profile.OCSPURL)
	test.AssertEquals(t, len(cert.CRLDistributionPoints), 1)
	test.AssertEquals(t, cert.CRLDistributionPoints[0], profile.CRLURL)
	test.AssertEquals(t, len(cert.IssuingCertificateURL), 1)
	test.AssertEquals(t, cert.IssuingCertificateURL[0], profile.IssuerURL)
	test.AssertEquals(t, cert.KeyUsage, x509.KeyUsageDigitalSignature|x509.KeyUsageCRLSign)
}

func TestVerifyProfile(t *testing.T) {
	for _, tc := range []struct {
		profile     certProfile
		root        bool
		expectedErr string
	}{
		{
			profile:     certProfile{},
			root:        false,
			expectedErr: "not-before is required",
		},
		{
			profile: certProfile{
				NotBefore: "a",
			},
			root:        false,
			expectedErr: "not-after is required",
		},
		{
			profile: certProfile{
				NotBefore: "a",
				NotAfter:  "b",
			},
			root:        false,
			expectedErr: "signature-algorithm is required",
		},
		{
			profile: certProfile{
				NotBefore:          "a",
				NotAfter:           "b",
				SignatureAlgorithm: "c",
			},
			root:        false,
			expectedErr: "common-name is required",
		},
		{
			profile: certProfile{
				NotBefore:          "a",
				NotAfter:           "b",
				SignatureAlgorithm: "c",
				CommonName:         "d",
			},
			root:        false,
			expectedErr: "organization is required",
		},
		{
			profile: certProfile{
				NotBefore:          "a",
				NotAfter:           "b",
				SignatureAlgorithm: "c",
				CommonName:         "d",
				Organization:       "e",
			},
			root:        false,
			expectedErr: "country is required",
		},
		{
			profile: certProfile{
				NotBefore:          "a",
				NotAfter:           "b",
				SignatureAlgorithm: "c",
				CommonName:         "d",
				Organization:       "e",
				Country:            "f",
			},
			root:        false,
			expectedErr: "ocsp-url is required for intermediates",
		},
		{
			profile: certProfile{
				NotBefore:          "a",
				NotAfter:           "b",
				SignatureAlgorithm: "c",
				CommonName:         "d",
				Organization:       "e",
				Country:            "f",
				OCSPURL:            "g",
			},
			root:        false,
			expectedErr: "crl-url is required for intermediates",
		},
		{
			profile: certProfile{
				NotBefore:          "a",
				NotAfter:           "b",
				SignatureAlgorithm: "c",
				CommonName:         "d",
				Organization:       "e",
				Country:            "f",
				OCSPURL:            "g",
				CRLURL:             "h",
			},
			root:        false,
			expectedErr: "issuer-url is required for intermediates",
		},
		{
			profile: certProfile{
				NotBefore:          "a",
				NotAfter:           "b",
				SignatureAlgorithm: "c",
				CommonName:         "d",
				Organization:       "e",
				Country:            "f",
			},
			root: true,
		},
	} {
		err := tc.profile.verifyProfile(tc.root)
		if err != nil {
			if tc.expectedErr != err.Error() {
				t.Fatalf("Expected %q, got %q", tc.expectedErr, err.Error())
			}
		} else if tc.expectedErr != "" {
			t.Fatalf("verifyProfile didn't fail, expected %q", tc.expectedErr)
		}
	}
}
