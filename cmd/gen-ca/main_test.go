package main

import (
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/letsencrypt/boulder/pkcs11helpers"
	"github.com/letsencrypt/boulder/test"
	"github.com/miekg/pkcs11"
)

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
	profile := &CertProfile{}

	profile.NotBefore = "1234"
	_, err := makeTemplate(ctx, profile, nil, 0)
	test.AssertError(t, err, "makeTemplate didn't fail with invalid not before")

	profile.NotBefore = "2018-05-18 11:31:00"
	profile.NotAfter = "1234"
	_, err = makeTemplate(ctx, profile, nil, 0)
	test.AssertError(t, err, "makeTemplate didn't fail with invalid not after")

	profile.NotAfter = "2018-05-18 11:31:00"
	profile.PolicyOIDs = []string{""}
	_, err = makeTemplate(ctx, profile, nil, 0)
	test.AssertError(t, err, "makeTemplate didn't fail with invalid policy OID")

	profile.PolicyOIDs = []string{"1.2.3"}
	profile.SignatureAlgorithm = "nope"
	_, err = makeTemplate(ctx, profile, nil, 0)
	test.AssertError(t, err, "makeTemplate didn't fail with invalid signature algorithm")

	profile.SignatureAlgorithm = "SHA256WithRSA"
	ctx.GenerateRandomFunc = func(pkcs11.SessionHandle, int) ([]byte, error) {
		return nil, errors.New("bad")
	}
	_, err = makeTemplate(ctx, profile, nil, 0)
	test.AssertError(t, err, "makeTemplate didn't fail when GenerateRandom failed")

	ctx.GenerateRandomFunc = func(_ pkcs11.SessionHandle, length int) ([]byte, error) {
		r := make([]byte, length)
		_, err := rand.Read(r)
		return r, err
	}
	profile.CommonName = "common name"
	profile.Organization = "organization"
	profile.Country = "country"
	profile.OCSPURL = "ocsp"
	profile.CRLURL = "crl"
	profile.IssuerURL = "issuer"
	cert, err := makeTemplate(ctx, profile, nil, 0)
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
}

func TestVerifyProfile(t *testing.T) {
	for _, tc := range []struct {
		profile     CertProfile
		root        bool
		expectedErr string
	}{
		{
			profile:     CertProfile{},
			root:        false,
			expectedErr: "NotBefore in profile is required",
		},
		{
			profile: CertProfile{
				NotBefore: "a",
			},
			root:        false,
			expectedErr: "NotAfter in profile is required",
		},
		{
			profile: CertProfile{
				NotBefore: "a",
				NotAfter:  "b",
			},
			root:        false,
			expectedErr: "SignatureAlgorithm in profile is required",
		},
		{
			profile: CertProfile{
				NotBefore:          "a",
				NotAfter:           "b",
				SignatureAlgorithm: "c",
			},
			root:        false,
			expectedErr: "CommonName in profile is required",
		},
		{
			profile: CertProfile{
				NotBefore:          "a",
				NotAfter:           "b",
				SignatureAlgorithm: "c",
				CommonName:         "d",
			},
			root:        false,
			expectedErr: "Organization in profile is required",
		},
		{
			profile: CertProfile{
				NotBefore:          "a",
				NotAfter:           "b",
				SignatureAlgorithm: "c",
				CommonName:         "d",
				Organization:       "e",
			},
			root:        false,
			expectedErr: "Country in profile is required",
		},
		{
			profile: CertProfile{
				NotBefore:          "a",
				NotAfter:           "b",
				SignatureAlgorithm: "c",
				CommonName:         "d",
				Organization:       "e",
				Country:            "f",
			},
			root:        false,
			expectedErr: "OCSPURL in profile is required for intermediates",
		},
		{
			profile: CertProfile{
				NotBefore:          "a",
				NotAfter:           "b",
				SignatureAlgorithm: "c",
				CommonName:         "d",
				Organization:       "e",
				Country:            "f",
				OCSPURL:            "g",
			},
			root:        false,
			expectedErr: "CRLURL in profile is required for intermediates",
		},
		{
			profile: CertProfile{
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
			expectedErr: "IssuerURL in profile is required for intermediates",
		},
		{
			profile: CertProfile{
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
		err := verifyProfile(tc.profile, tc.root)
		if err != nil {
			if tc.expectedErr != err.Error() {
				t.Fatalf("Expected %q, got %q", tc.expectedErr, err.Error())
			}
		} else if tc.expectedErr != "" {
			t.Fatalf("verifyProfile didn't fail, expected %q", tc.expectedErr)
		}
	}
}
