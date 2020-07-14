package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
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
	randReader := newRandReader(&ctx, 0)

	pubKey, err := hex.DecodeString("3059301306072a8648ce3d020106082a8648ce3d03010703420004b06745ef0375c9c54057098f077964e18d3bed0aacd54545b16eab8c539b5768cc1cea93ba56af1e22a7a01c33048c8885ed17c9c55ede70649b707072689f5e")
	test.AssertNotError(t, err, "failed to decode test public key")

	profile.NotBefore = "1234"
	_, err = makeTemplate(randReader, profile, pubKey, rootCert)
	test.AssertError(t, err, "makeTemplate didn't fail with invalid not before")

	profile.NotBefore = "2018-05-18 11:31:00"
	profile.NotAfter = "1234"
	_, err = makeTemplate(randReader, profile, pubKey, rootCert)
	test.AssertError(t, err, "makeTemplate didn't fail with invalid not after")

	profile.NotAfter = "2018-05-18 11:31:00"
	profile.SignatureAlgorithm = "nope"
	_, err = makeTemplate(randReader, profile, pubKey, rootCert)
	test.AssertError(t, err, "makeTemplate didn't fail with invalid signature algorithm")

	profile.SignatureAlgorithm = "SHA256WithRSA"
	ctx.GenerateRandomFunc = func(pkcs11.SessionHandle, int) ([]byte, error) {
		return nil, errors.New("bad")
	}
	_, err = makeTemplate(randReader, profile, pubKey, rootCert)
	test.AssertError(t, err, "makeTemplate didn't fail when GenerateRandom failed")

	ctx.GenerateRandomFunc = func(_ pkcs11.SessionHandle, length int) ([]byte, error) {
		r := make([]byte, length)
		_, err := rand.Read(r)
		return r, err
	}

	_, err = makeTemplate(randReader, profile, pubKey, rootCert)
	test.AssertError(t, err, "makeTemplate didn't fail with empty key usages")

	profile.KeyUsages = []string{"asd"}
	_, err = makeTemplate(randReader, profile, pubKey, rootCert)
	test.AssertError(t, err, "makeTemplate didn't fail with invalid key usages")

	profile.KeyUsages = []string{"Digital Signature", "CRL Sign"}
	profile.Policies = []policyInfoConfig{{}}
	_, err = makeTemplate(randReader, profile, pubKey, rootCert)
	test.AssertError(t, err, "makeTemplate didn't fail with invalid policy OID")

	profile.Policies = []policyInfoConfig{{OID: "1.2.3"}, {OID: "1.2.3.4", CPSURI: "hello"}}
	profile.CommonName = "common name"
	profile.Organization = "organization"
	profile.Country = "country"
	profile.OCSPURL = "ocsp"
	profile.CRLURL = "crl"
	profile.IssuerURL = "issuer"
	cert, err := makeTemplate(randReader, profile, pubKey, rootCert)
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
	test.AssertEquals(t, len(cert.ExtraExtensions), 1)
	test.AssertEquals(t, len(cert.ExtKeyUsage), 0)

	cert, err = makeTemplate(randReader, profile, pubKey, intermediateCert)
	test.AssertNotError(t, err, "makeTemplate failed when everything worked as expected")
	test.Assert(t, cert.MaxPathLenZero, "MaxPathLenZero not set in intermediate template")
	test.AssertEquals(t, len(cert.ExtKeyUsage), 2)
	test.AssertEquals(t, cert.ExtKeyUsage[0], x509.ExtKeyUsageClientAuth)
	test.AssertEquals(t, cert.ExtKeyUsage[1], x509.ExtKeyUsageServerAuth)
}

func TestMakeTemplateOCSP(t *testing.T) {
	ctx := pkcs11helpers.MockCtx{
		GenerateRandomFunc: func(_ pkcs11.SessionHandle, length int) ([]byte, error) {
			r := make([]byte, length)
			_, err := rand.Read(r)
			return r, err
		},
	}
	randReader := newRandReader(&ctx, 0)
	profile := &certProfile{
		SignatureAlgorithm: "SHA256WithRSA",
		CommonName:         "common name",
		Organization:       "organization",
		Country:            "country",
		OCSPURL:            "ocsp",
		CRLURL:             "crl",
		IssuerURL:          "issuer",
		NotAfter:           "2018-05-18 11:31:00",
		NotBefore:          "2018-05-18 11:31:00",
	}
	pubKey, err := hex.DecodeString("3059301306072a8648ce3d020106082a8648ce3d03010703420004b06745ef0375c9c54057098f077964e18d3bed0aacd54545b16eab8c539b5768cc1cea93ba56af1e22a7a01c33048c8885ed17c9c55ede70649b707072689f5e")
	test.AssertNotError(t, err, "failed to decode test public key")

	cert, err := makeTemplate(randReader, profile, pubKey, ocspCert)
	test.AssertNotError(t, err, "makeTemplate failed")

	test.Assert(t, !cert.IsCA, "IsCA is set")
	// Check KU is only KeyUsageDigitalSignature
	test.AssertEquals(t, cert.KeyUsage, x509.KeyUsageDigitalSignature)
	// Check there is a single EKU with id-kp-OCSPSigning
	test.AssertEquals(t, len(cert.ExtKeyUsage), 1)
	test.AssertEquals(t, cert.ExtKeyUsage[0], x509.ExtKeyUsageOCSPSigning)
	// Check ExtraExtensions contains a single id-pkix-ocsp-nocheck
	hasExt := false
	asnNULL := []byte{5, 0}
	for _, ext := range cert.ExtraExtensions {
		if ext.Id.Equal(oidOCSPNoCheck) {
			if hasExt {
				t.Error("template contains multiple id-pkix-ocsp-nocheck extensions")
			}
			hasExt = true
			if !bytes.Equal(ext.Value, asnNULL) {
				t.Errorf("id-pkix-ocsp-nocheck has unexpected content: want %x, got %x", asnNULL, ext.Value)
			}
		}
	}
	test.Assert(t, hasExt, "template doesn't contain id-pkix-ocsp-nocheck extensions")
}

func TestMakeTemplateCRL(t *testing.T) {
	ctx := pkcs11helpers.MockCtx{
		GenerateRandomFunc: func(_ pkcs11.SessionHandle, length int) ([]byte, error) {
			r := make([]byte, length)
			_, err := rand.Read(r)
			return r, err
		},
	}
	randReader := newRandReader(&ctx, 0)
	profile := &certProfile{
		SignatureAlgorithm: "SHA256WithRSA",
		CommonName:         "common name",
		Organization:       "organization",
		Country:            "country",
		OCSPURL:            "ocsp",
		CRLURL:             "crl",
		IssuerURL:          "issuer",
		NotAfter:           "2018-05-18 11:31:00",
		NotBefore:          "2018-05-18 11:31:00",
	}
	pubKey, err := hex.DecodeString("3059301306072a8648ce3d020106082a8648ce3d03010703420004b06745ef0375c9c54057098f077964e18d3bed0aacd54545b16eab8c539b5768cc1cea93ba56af1e22a7a01c33048c8885ed17c9c55ede70649b707072689f5e")
	test.AssertNotError(t, err, "failed to decode test public key")

	cert, err := makeTemplate(randReader, profile, pubKey, crlCert)
	test.AssertNotError(t, err, "makeTemplate failed")

	test.Assert(t, !cert.IsCA, "IsCA is set")
	test.AssertEquals(t, cert.KeyUsage, x509.KeyUsageCRLSign)
}

func TestVerifyProfile(t *testing.T) {
	for _, tc := range []struct {
		profile     certProfile
		certType    certType
		expectedErr string
	}{
		{
			profile:     certProfile{},
			certType:    intermediateCert,
			expectedErr: "not-before is required",
		},
		{
			profile: certProfile{
				NotBefore: "a",
			},
			certType:    intermediateCert,
			expectedErr: "not-after is required",
		},
		{
			profile: certProfile{
				NotBefore: "a",
				NotAfter:  "b",
			},
			certType:    intermediateCert,
			expectedErr: "signature-algorithm is required",
		},
		{
			profile: certProfile{
				NotBefore:          "a",
				NotAfter:           "b",
				SignatureAlgorithm: "c",
			},
			certType:    intermediateCert,
			expectedErr: "common-name is required",
		},
		{
			profile: certProfile{
				NotBefore:          "a",
				NotAfter:           "b",
				SignatureAlgorithm: "c",
				CommonName:         "d",
			},
			certType:    intermediateCert,
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
			certType:    intermediateCert,
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
			certType:    intermediateCert,
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
			certType:    intermediateCert,
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
			certType:    intermediateCert,
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
			certType: rootCert,
		},
		{
			profile: certProfile{
				NotBefore:          "a",
				NotAfter:           "b",
				SignatureAlgorithm: "c",
				CommonName:         "d",
				Organization:       "e",
				Country:            "f",
				IssuerURL:          "g",
				KeyUsages:          []string{"j"},
			},
			certType:    ocspCert,
			expectedErr: "key-usages cannot be set for a delegated signer",
		},
		{
			profile: certProfile{
				NotBefore:          "a",
				NotAfter:           "b",
				SignatureAlgorithm: "c",
				CommonName:         "d",
				Organization:       "e",
				Country:            "f",
				IssuerURL:          "g",
				CRLURL:             "i",
			},
			certType:    ocspCert,
			expectedErr: "crl-url cannot be set for a delegated signer",
		},
		{
			profile: certProfile{
				NotBefore:          "a",
				NotAfter:           "b",
				SignatureAlgorithm: "c",
				CommonName:         "d",
				Organization:       "e",
				Country:            "f",
				IssuerURL:          "g",
				OCSPURL:            "h",
			},
			certType:    ocspCert,
			expectedErr: "ocsp-url cannot be set for a delegated signer",
		},
		{
			profile: certProfile{
				NotBefore:          "a",
				NotAfter:           "b",
				SignatureAlgorithm: "c",
				CommonName:         "d",
				Organization:       "e",
				Country:            "f",
				IssuerURL:          "g",
			},
			certType: ocspCert,
		},
		{
			profile: certProfile{
				NotBefore:          "a",
				NotAfter:           "b",
				SignatureAlgorithm: "c",
				CommonName:         "d",
				Organization:       "e",
				Country:            "f",
				IssuerURL:          "g",
				KeyUsages:          []string{"j"},
			},
			certType:    crlCert,
			expectedErr: "key-usages cannot be set for a delegated signer",
		},
		{
			profile: certProfile{
				NotBefore:          "a",
				NotAfter:           "b",
				SignatureAlgorithm: "c",
				CommonName:         "d",
				Organization:       "e",
				Country:            "f",
				IssuerURL:          "g",
				CRLURL:             "i",
			},
			certType:    crlCert,
			expectedErr: "crl-url cannot be set for a delegated signer",
		},
		{
			profile: certProfile{
				NotBefore:          "a",
				NotAfter:           "b",
				SignatureAlgorithm: "c",
				CommonName:         "d",
				Organization:       "e",
				Country:            "f",
				IssuerURL:          "g",
				OCSPURL:            "h",
			},
			certType:    crlCert,
			expectedErr: "ocsp-url cannot be set for a delegated signer",
		},
		{
			profile: certProfile{
				NotBefore:          "a",
				NotAfter:           "b",
				SignatureAlgorithm: "c",
				CommonName:         "d",
				Organization:       "e",
				Country:            "f",
				IssuerURL:          "g",
			},
			certType: crlCert,
		},
	} {
		err := tc.profile.verifyProfile(tc.certType)
		if err != nil {
			if tc.expectedErr != err.Error() {
				t.Fatalf("Expected %q, got %q", tc.expectedErr, err.Error())
			}
		} else if tc.expectedErr != "" {
			t.Fatalf("verifyProfile didn't fail, expected %q", tc.expectedErr)
		}
	}
}

func TestGetKey(t *testing.T) {
	ctx := pkcs11helpers.MockCtx{}

	// test newSigner fails when pkcs11helpers.FindObject for private key handle fails
	ctx.FindObjectsInitFunc = func(pkcs11.SessionHandle, []*pkcs11.Attribute) error {
		return errors.New("broken")
	}
	_, err := newSigner(ctx, 0, "label", []byte{255, 255})
	test.AssertError(t, err, "newSigner didn't fail when pkcs11helpers.FindObject for private key handle failed")

	// test newSigner fails when GetAttributeValue fails
	ctx.FindObjectsInitFunc = func(pkcs11.SessionHandle, []*pkcs11.Attribute) error {
		return nil
	}
	ctx.FindObjectsFunc = func(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
		return []pkcs11.ObjectHandle{1}, false, nil
	}
	ctx.FindObjectsFinalFunc = func(pkcs11.SessionHandle) error {
		return nil
	}
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return nil, errors.New("broken")
	}
	_, err = newSigner(ctx, 0, "label", []byte{255, 255})
	test.AssertError(t, err, "newSigner didn't fail when GetAttributeValue for private key type failed")

	// test newSigner fails when GetAttributeValue returns no attributes
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return nil, nil
	}
	_, err = newSigner(ctx, 0, "label", []byte{255, 255})
	test.AssertError(t, err, "newSigner didn't fail when GetAttributeValue for private key type returned no attributes")

	// test newSigner fails when pkcs11helpers.FindObject for public key handle fails
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC)}, nil
	}
	ctx.FindObjectsInitFunc = func(_ pkcs11.SessionHandle, tmpl []*pkcs11.Attribute) error {
		if bytes.Equal(tmpl[0].Value, []byte{2, 0, 0, 0, 0, 0, 0, 0}) {
			return errors.New("broken")
		}
		return nil
	}
	_, err = newSigner(ctx, 0, "label", []byte{255, 255})
	test.AssertError(t, err, "newSigner didn't fail when pkcs11helpers.FindObject for public key handle failed")

	// test newSigner fails when pkcs11helpers.FindObject for private key returns unknown CKA_KEY_TYPE
	ctx.FindObjectsInitFunc = func(_ pkcs11.SessionHandle, tmpl []*pkcs11.Attribute) error {
		return nil
	}
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, []byte{2, 0, 0, 0, 0, 0, 0, 0})}, nil
	}
	_, err = newSigner(ctx, 0, "label", []byte{255, 255})
	test.AssertError(t, err, "newSigner didn't fail when GetAttributeValue for private key returned unknown key type")

	// test newSigner fails when GetRSAPublicKey fails
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, []byte{0, 0, 0, 0, 0, 0, 0, 0})}, nil
	}
	_, err = newSigner(ctx, 0, "label", []byte{255, 255})
	test.AssertError(t, err, "newSigner didn't fail when GetRSAPublicKey fails")

	// test newSigner fails when GetECDSAPublicKey fails
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, []byte{3, 0, 0, 0, 0, 0, 0, 0})}, nil
	}
	_, err = newSigner(ctx, 0, "label", []byte{255, 255})
	test.AssertError(t, err, "newSigner didn't fail when GetECDSAPublicKey fails")

	// test newSigner works when everything... works
	ctx.GetAttributeValueFunc = func(_ pkcs11.SessionHandle, _ pkcs11.ObjectHandle, attrs []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		var returns []*pkcs11.Attribute
		for _, attr := range attrs {
			switch attr.Type {
			case pkcs11.CKA_KEY_TYPE:
				returns = append(returns, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, []byte{0, 0, 0, 0, 0, 0, 0, 0}))
			case pkcs11.CKA_PUBLIC_EXPONENT:
				returns = append(returns, pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 2, 3}))
			case pkcs11.CKA_MODULUS:
				returns = append(returns, pkcs11.NewAttribute(pkcs11.CKA_MODULUS, []byte{4, 5, 6}))
			default:
				return nil, errors.New("GetAttributeValue got unexpected attribute type")
			}
		}
		return returns, nil
	}
	_, err = newSigner(ctx, 0, "label", []byte{255, 255})
	test.AssertNotError(t, err, "newSigner failed when everything worked properly")
}
