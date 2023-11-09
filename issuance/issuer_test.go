package issuance

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/ctpolicy/loglist"
	"github.com/letsencrypt/boulder/linter"
	"github.com/letsencrypt/boulder/test"
)

func defaultProfileConfig() ProfileConfig {
	return ProfileConfig{
		AllowCommonName:     true,
		AllowCTPoison:       true,
		AllowSCTList:        true,
		AllowMustStaple:     true,
		MaxValidityPeriod:   config.Duration{Duration: time.Hour},
		MaxValidityBackdate: config.Duration{Duration: time.Hour},
	}
}

func defaultIssuerConfig() IssuerConfig {
	return IssuerConfig{
		UseForECDSALeaves: true,
		UseForRSALeaves:   true,
		IssuerURL:         "http://issuer-url",
		OCSPURL:           "http://ocsp-url",
	}
}

func defaultProfile() *Profile {
	p, _ := NewProfile(defaultProfileConfig(), defaultIssuerConfig())
	return p
}

var issuerCert *Certificate
var issuerSigner *ecdsa.PrivateKey

func TestMain(m *testing.M) {
	tk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cmd.FailOnError(err, "failed to generate test key")
	issuerSigner = tk
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(123),
		BasicConstraintsValid: true,
		IsCA:                  true,
		Subject: pkix.Name{
			CommonName: "big ca",
		},
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	issuer, err := x509.CreateCertificate(rand.Reader, template, template, tk.Public(), tk)
	cmd.FailOnError(err, "failed to generate test issuer")
	cert, err := x509.ParseCertificate(issuer)
	cmd.FailOnError(err, "failed to parse test issuer")
	issuerCert = &Certificate{Certificate: cert}
	os.Exit(m.Run())
}

func TestNewProfileNoIssuerURL(t *testing.T) {
	_, err := NewProfile(ProfileConfig{}, IssuerConfig{})
	test.AssertError(t, err, "NewProfile didn't fail with no issuer URL")
	test.AssertEquals(t, err.Error(), "Issuer URL is required")
}

func TestNewProfileNoOCSPURL(t *testing.T) {
	_, err := NewProfile(ProfileConfig{}, IssuerConfig{IssuerURL: "issuer-url"})
	test.AssertError(t, err, "NewProfile didn't fail with no OCSP URL")
	test.AssertEquals(t, err.Error(), "OCSP URL is required")
}

func TestRequestValid(t *testing.T) {
	fc := clock.NewFake()
	fc.Add(time.Hour * 24)
	tests := []struct {
		name          string
		profile       *Profile
		request       *IssuanceRequest
		expectedError string
	}{
		{
			name:          "unsupported key type",
			profile:       &Profile{},
			request:       &IssuanceRequest{PublicKey: &dsa.PublicKey{}},
			expectedError: "unsupported public key type",
		},
		{
			name:          "cannot sign rsa",
			profile:       &Profile{},
			request:       &IssuanceRequest{PublicKey: &rsa.PublicKey{}},
			expectedError: "cannot sign RSA public keys",
		},
		{
			name:          "cannot sign ecdsa",
			profile:       &Profile{},
			request:       &IssuanceRequest{PublicKey: &ecdsa.PublicKey{}},
			expectedError: "cannot sign ECDSA public keys",
		},
		{
			name: "must staple not allowed",
			profile: &Profile{
				useForECDSALeaves: true,
			},
			request: &IssuanceRequest{
				PublicKey:         &ecdsa.PublicKey{},
				IncludeMustStaple: true,
			},
			expectedError: "must-staple extension cannot be included",
		},
		{
			name: "ct poison not allowed",
			profile: &Profile{
				useForECDSALeaves: true,
			},
			request: &IssuanceRequest{
				PublicKey:       &ecdsa.PublicKey{},
				IncludeCTPoison: true,
			},
			expectedError: "ct poison extension cannot be included",
		},
		{
			name: "sct list not allowed",
			profile: &Profile{
				useForECDSALeaves: true,
			},
			request: &IssuanceRequest{
				PublicKey: &ecdsa.PublicKey{},
				sctList:   []ct.SignedCertificateTimestamp{},
			},
			expectedError: "sct list extension cannot be included",
		},
		{
			name: "sct list and ct poison not allowed",
			profile: &Profile{
				useForECDSALeaves: true,
				allowCTPoison:     true,
				allowSCTList:      true,
			},
			request: &IssuanceRequest{
				PublicKey:       &ecdsa.PublicKey{},
				IncludeCTPoison: true,
				sctList:         []ct.SignedCertificateTimestamp{},
			},
			expectedError: "cannot include both ct poison and sct list extensions",
		},
		{
			name: "common name not allowed",
			profile: &Profile{
				useForECDSALeaves: true,
			},
			request: &IssuanceRequest{
				PublicKey:  &ecdsa.PublicKey{},
				CommonName: "cn",
			},
			expectedError: "common name cannot be included",
		},
		{
			name: "negative validity",
			profile: &Profile{
				useForECDSALeaves: true,
			},
			request: &IssuanceRequest{
				PublicKey: &ecdsa.PublicKey{},
				NotBefore: fc.Now().Add(time.Hour),
				NotAfter:  fc.Now(),
			},
			expectedError: "NotAfter must be after NotBefore",
		},
		{
			name: "validity larger than max",
			profile: &Profile{
				useForECDSALeaves: true,
				maxValidity:       time.Minute,
			},
			request: &IssuanceRequest{
				PublicKey: &ecdsa.PublicKey{},
				NotBefore: fc.Now(),
				NotAfter:  fc.Now().Add(time.Hour - time.Second),
			},
			expectedError: "validity period is more than the maximum allowed period (1h0m0s>1m0s)",
		},
		{
			name: "validity larger than max due to inclusivity",
			profile: &Profile{
				useForECDSALeaves: true,
				maxValidity:       time.Hour,
			},
			request: &IssuanceRequest{
				PublicKey: &ecdsa.PublicKey{},
				NotBefore: fc.Now(),
				NotAfter:  fc.Now().Add(time.Hour),
			},
			expectedError: "validity period is more than the maximum allowed period (1h0m1s>1h0m0s)",
		},
		{
			name: "validity backdated more than max",
			profile: &Profile{
				useForECDSALeaves: true,
				maxValidity:       time.Hour * 2,
				maxBackdate:       time.Hour,
			},
			request: &IssuanceRequest{
				PublicKey: &ecdsa.PublicKey{},
				NotBefore: fc.Now().Add(-time.Hour * 2),
				NotAfter:  fc.Now().Add(-time.Hour),
			},
			expectedError: "NotBefore is backdated more than the maximum allowed period (2h0m0s>1h0m0s)",
		},
		{
			name: "validity is forward dated",
			profile: &Profile{
				useForECDSALeaves: true,
				maxValidity:       time.Hour * 2,
				maxBackdate:       time.Hour,
			},
			request: &IssuanceRequest{
				PublicKey: &ecdsa.PublicKey{},
				NotBefore: fc.Now().Add(time.Hour),
				NotAfter:  fc.Now().Add(time.Hour * 2),
			},
			expectedError: "NotBefore is in the future",
		},
		{
			name: "serial too short",
			profile: &Profile{
				useForECDSALeaves: true,
				maxValidity:       time.Hour * 2,
			},
			request: &IssuanceRequest{
				PublicKey: &ecdsa.PublicKey{},
				NotBefore: fc.Now(),
				NotAfter:  fc.Now().Add(time.Hour),
				Serial:    []byte{0, 1, 2, 3, 4, 5, 6, 7},
			},
			expectedError: "serial must be between 9 and 19 bytes",
		},
		{
			name: "serial too long",
			profile: &Profile{
				useForECDSALeaves: true,
				maxValidity:       time.Hour * 2,
			},
			request: &IssuanceRequest{
				PublicKey: &ecdsa.PublicKey{},
				NotBefore: fc.Now(),
				NotAfter:  fc.Now().Add(time.Hour),
				Serial:    []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			},
			expectedError: "serial must be between 9 and 19 bytes",
		},
		{
			name: "good",
			profile: &Profile{
				useForECDSALeaves: true,
				maxValidity:       time.Hour * 2,
			},
			request: &IssuanceRequest{
				PublicKey: &ecdsa.PublicKey{},
				NotBefore: fc.Now(),
				NotAfter:  fc.Now().Add(time.Hour),
				Serial:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.profile.requestValid(fc, tc.request)
			if err != nil {
				if tc.expectedError == "" {
					t.Errorf("failed with unexpected error: %s", err)
				} else if tc.expectedError != err.Error() {
					t.Errorf("failed with unexpected error, wanted: %q, got: %q", tc.expectedError, err.Error())
				}
				return
			} else if tc.expectedError != "" {
				t.Errorf("didn't fail, expected %q", tc.expectedError)
			}
		})
	}
}

func TestGenerateTemplate(t *testing.T) {
	tests := []struct {
		name             string
		profile          *Profile
		expectedTemplate *x509.Certificate
	}{
		{
			name: "crl url",
			profile: &Profile{
				crlURL: "crl-url",
				sigAlg: x509.SHA256WithRSA,
			},
			expectedTemplate: &x509.Certificate{
				BasicConstraintsValid: true,
				SignatureAlgorithm:    x509.SHA256WithRSA,
				ExtKeyUsage:           defaultEKU,
				IssuingCertificateURL: []string{""},
				OCSPServer:            []string{""},
				CRLDistributionPoints: []string{"crl-url"},
				PolicyIdentifiers:     []asn1.ObjectIdentifier{{2, 23, 140, 1, 2, 1}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			template := tc.profile.generateTemplate()
			test.AssertDeepEquals(t, *template, *tc.expectedTemplate)
		})
	}
}

func TestNewIssuer(t *testing.T) {
	_, err := NewIssuer(
		issuerCert,
		issuerSigner,
		defaultProfile(),
		&linter.Linter{},
		clock.NewFake(),
	)
	test.AssertNotError(t, err, "NewIssuer failed")
}

func TestNewIssuerUnsupportedKeyType(t *testing.T) {
	_, err := NewIssuer(
		&Certificate{
			Certificate: &x509.Certificate{
				PublicKey: &ed25519.PublicKey{},
			},
		},
		&ed25519.PrivateKey{},
		defaultProfile(),
		&linter.Linter{},
		clock.NewFake(),
	)
	test.AssertError(t, err, "NewIssuer didn't fail")
	test.AssertEquals(t, err.Error(), "unsupported issuer key type")
}

func TestNewIssuerNoCertSign(t *testing.T) {
	_, err := NewIssuer(
		&Certificate{
			Certificate: &x509.Certificate{
				PublicKey: &ecdsa.PublicKey{
					Curve: elliptic.P256(),
				},
				KeyUsage: 0,
			},
		},
		issuerSigner,
		defaultProfile(),
		&linter.Linter{},
		clock.NewFake(),
	)
	test.AssertError(t, err, "NewIssuer didn't fail")
	test.AssertEquals(t, err.Error(), "end-entity signing cert does not have keyUsage certSign")
}

func TestNewIssuerNoDigitalSignature(t *testing.T) {
	_, err := NewIssuer(
		&Certificate{
			Certificate: &x509.Certificate{
				PublicKey: &ecdsa.PublicKey{
					Curve: elliptic.P256(),
				},
				KeyUsage: x509.KeyUsageCertSign,
			},
		},
		issuerSigner,
		defaultProfile(),
		&linter.Linter{},
		clock.NewFake(),
	)
	test.AssertError(t, err, "NewIssuer didn't fail")
	test.AssertEquals(t, err.Error(), "end-entity ocsp signing cert does not have keyUsage digitalSignature")
}

func TestNewIssuerOCSPOnly(t *testing.T) {
	p := defaultProfile()
	p.useForRSALeaves = false
	p.useForECDSALeaves = false
	_, err := NewIssuer(
		&Certificate{
			Certificate: &x509.Certificate{
				PublicKey: &ecdsa.PublicKey{
					Curve: elliptic.P256(),
				},
				KeyUsage: x509.KeyUsageDigitalSignature,
			},
		},
		issuerSigner,
		p,
		&linter.Linter{},
		clock.NewFake(),
	)
	test.AssertNotError(t, err, "NewIssuer failed")
}

func TestIssue(t *testing.T) {
	for _, tc := range []struct {
		name         string
		generateFunc func() (crypto.Signer, error)
		ku           x509.KeyUsage
	}{
		{
			name: "RSA",
			generateFunc: func() (crypto.Signer, error) {
				return rsa.GenerateKey(rand.Reader, 2048)
			},
			ku: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		},
		{
			name: "ECDSA",
			generateFunc: func() (crypto.Signer, error) {
				return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			},
			ku: x509.KeyUsageDigitalSignature,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fc := clock.NewFake()
			fc.Set(time.Now())
			linter, err := linter.New(
				issuerCert.Certificate,
				issuerSigner,
				[]string{
					"w_ct_sct_policy_count_unsatisfied",
					"e_scts_from_same_operator",
					"n_subject_common_name_included",
				},
			)
			test.AssertNotError(t, err, "failed to create linter")
			signer, err := NewIssuer(issuerCert, issuerSigner, defaultProfile(), linter, fc)
			test.AssertNotError(t, err, "NewIssuer failed")
			pk, err := tc.generateFunc()
			test.AssertNotError(t, err, "failed to generate test key")
			lintCertBytes, issuanceToken, err := signer.Prepare(&IssuanceRequest{
				PublicKey:       pk.Public(),
				Serial:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
				CommonName:      "example.com",
				DNSNames:        []string{"example.com"},
				NotBefore:       fc.Now(),
				NotAfter:        fc.Now().Add(time.Hour - time.Second),
				IncludeCTPoison: true,
			})
			test.AssertNotError(t, err, "Prepare failed")
			_, err = x509.ParseCertificate(lintCertBytes)
			test.AssertNotError(t, err, "failed to parse certificate")
			certBytes, err := signer.Issue(issuanceToken)
			test.AssertNotError(t, err, "Issue failed")
			cert, err := x509.ParseCertificate(certBytes)
			test.AssertNotError(t, err, "failed to parse certificate")
			err = cert.CheckSignatureFrom(issuerCert.Certificate)
			test.AssertNotError(t, err, "signature validation failed")
			test.AssertDeepEquals(t, cert.DNSNames, []string{"example.com"})
			test.AssertEquals(t, cert.Subject.CommonName, "example.com")
			test.AssertByteEquals(t, cert.SerialNumber.Bytes(), []byte{1, 2, 3, 4, 5, 6, 7, 8, 9})
			test.AssertDeepEquals(t, cert.PublicKey, pk.Public())
			test.AssertEquals(t, len(cert.Extensions), 9) // Constraints, KU, EKU, SKID, AKID, AIA, SAN, Policies, Poison
			test.AssertEquals(t, cert.KeyUsage, tc.ku)
		})
	}
}

func TestIssueRSA(t *testing.T) {
	fc := clock.NewFake()
	fc.Set(time.Now())
	linter, err := linter.New(
		issuerCert.Certificate,
		issuerSigner,
		[]string{
			"w_ct_sct_policy_count_unsatisfied",
			"e_scts_from_same_operator",
		},
	)
	test.AssertNotError(t, err, "failed to create linter")
	signer, err := NewIssuer(issuerCert, issuerSigner, defaultProfile(), linter, fc)
	test.AssertNotError(t, err, "NewIssuer failed")
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "failed to generate test key")
	_, issuanceToken, err := signer.Prepare(&IssuanceRequest{
		PublicKey:       pk.Public(),
		Serial:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
		DNSNames:        []string{"example.com"},
		NotBefore:       fc.Now(),
		NotAfter:        fc.Now().Add(time.Hour - time.Second),
		IncludeCTPoison: true,
	})
	test.AssertNotError(t, err, "failed to prepare lint certificate")
	certBytes, err := signer.Issue(issuanceToken)
	test.AssertNotError(t, err, "failed to parse certificate")
	cert, err := x509.ParseCertificate(certBytes)
	test.AssertNotError(t, err, "failed to parse certificate")
	err = cert.CheckSignatureFrom(issuerCert.Certificate)
	test.AssertNotError(t, err, "signature validation failed")
	test.AssertByteEquals(t, cert.SerialNumber.Bytes(), []byte{1, 2, 3, 4, 5, 6, 7, 8, 9})
	test.AssertDeepEquals(t, cert.PublicKey, pk.Public())
	test.AssertEquals(t, len(cert.Extensions), 9) // Constraints, KU, EKU, SKID, AKID, AIA, SAN, Policies, Poison
	test.AssertEquals(t, cert.KeyUsage, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment)
}

func TestIssueCommonName(t *testing.T) {
	fc := clock.NewFake()
	fc.Set(time.Now())
	linter, err := linter.New(
		issuerCert.Certificate,
		issuerSigner,
		[]string{
			"w_ct_sct_policy_count_unsatisfied",
			"e_scts_from_same_operator",
			"n_subject_common_name_included",
		},
	)
	test.AssertNotError(t, err, "failed to create linter")
	signer, err := NewIssuer(issuerCert, issuerSigner, defaultProfile(), linter, fc)
	test.AssertNotError(t, err, "NewIssuer failed")
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "failed to generate test key")
	ir := &IssuanceRequest{
		PublicKey:       pk.Public(),
		Serial:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
		CommonName:      "example.com",
		DNSNames:        []string{"example.com", "www.example.com"},
		NotBefore:       fc.Now(),
		NotAfter:        fc.Now().Add(time.Hour - time.Second),
		IncludeCTPoison: true,
	}

	_, issuanceToken, err := signer.Prepare(ir)
	test.AssertNotError(t, err, "Prepare failed")
	certBytes, err := signer.Issue(issuanceToken)
	test.AssertNotError(t, err, "Issue failed")
	cert, err := x509.ParseCertificate(certBytes)
	test.AssertNotError(t, err, "failed to parse certificate")
	test.AssertEquals(t, cert.Subject.CommonName, "example.com")

	signer.Profile.allowCommonName = false
	_, _, err = signer.Prepare(ir)
	test.AssertError(t, err, "Prepare should have failed")

	ir.CommonName = ""
	_, issuanceToken, err = signer.Prepare(ir)
	test.AssertNotError(t, err, "Prepare failed")
	certBytes, err = signer.Issue(issuanceToken)
	test.AssertNotError(t, err, "Issue failed")
	cert, err = x509.ParseCertificate(certBytes)
	test.AssertNotError(t, err, "failed to parse certificate")
	test.AssertEquals(t, cert.Subject.CommonName, "")
	test.AssertDeepEquals(t, cert.DNSNames, []string{"example.com", "www.example.com"})
}

func TestIssueCTPoison(t *testing.T) {
	fc := clock.NewFake()
	fc.Set(time.Now())
	linter, err := linter.New(
		issuerCert.Certificate,
		issuerSigner,
		[]string{
			"w_ct_sct_policy_count_unsatisfied",
			"e_scts_from_same_operator",
		},
	)
	test.AssertNotError(t, err, "failed to create linter")
	signer, err := NewIssuer(issuerCert, issuerSigner, defaultProfile(), linter, fc)
	test.AssertNotError(t, err, "NewIssuer failed")
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "failed to generate test key")
	_, issuanceToken, err := signer.Prepare(&IssuanceRequest{
		PublicKey:       pk.Public(),
		Serial:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
		DNSNames:        []string{"example.com"},
		IncludeCTPoison: true,
		NotBefore:       fc.Now(),
		NotAfter:        fc.Now().Add(time.Hour - time.Second),
	})
	test.AssertNotError(t, err, "Prepare failed")
	certBytes, err := signer.Issue(issuanceToken)
	test.AssertNotError(t, err, "Issue failed")
	cert, err := x509.ParseCertificate(certBytes)
	test.AssertNotError(t, err, "failed to parse certificate")
	err = cert.CheckSignatureFrom(issuerCert.Certificate)
	test.AssertNotError(t, err, "signature validation failed")
	test.AssertByteEquals(t, cert.SerialNumber.Bytes(), []byte{1, 2, 3, 4, 5, 6, 7, 8, 9})
	test.AssertDeepEquals(t, cert.PublicKey, pk.Public())
	test.AssertEquals(t, len(cert.Extensions), 9) // Constraints, KU, EKU, SKID, AKID, AIA, SAN, Policies, CT Poison
	test.AssertDeepEquals(t, cert.Extensions[8], ctPoisonExt)
}

func mustDecodeB64(b string) []byte {
	out, err := base64.StdEncoding.DecodeString(b)
	if err != nil {
		panic(err)
	}
	return out
}

func TestIssueSCTList(t *testing.T) {
	fc := clock.NewFake()
	fc.Set(time.Now())
	err := loglist.InitLintList("../test/ct-test-srv/log_list.json")
	test.AssertNotError(t, err, "failed to load log list")
	linter, err := linter.New(
		issuerCert.Certificate,
		issuerSigner,
		[]string{},
	)
	test.AssertNotError(t, err, "failed to create linter")
	signer, err := NewIssuer(issuerCert, issuerSigner, defaultProfile(), linter, fc)
	test.AssertNotError(t, err, "NewIssuer failed")
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "failed to generate test key")
	_, issuanceToken, err := signer.Prepare(&IssuanceRequest{
		PublicKey:       pk.Public(),
		Serial:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
		DNSNames:        []string{"example.com"},
		NotBefore:       fc.Now(),
		NotAfter:        fc.Now().Add(time.Hour - time.Second),
		IncludeCTPoison: true,
	})
	test.AssertNotError(t, err, "Prepare failed")
	precertBytes, err := signer.Issue(issuanceToken)
	test.AssertNotError(t, err, "Issue failed")
	precert, err := x509.ParseCertificate(precertBytes)
	test.AssertNotError(t, err, "failed to parse certificate")

	sctList := []ct.SignedCertificateTimestamp{
		{
			SCTVersion: ct.V1,
			LogID:      ct.LogID{KeyID: *(*[32]byte)(mustDecodeB64("OJiMlNA1mMOTLd/pI7q68npCDrlsQeFaqAwasPwEvQM="))},
		},
		{
			SCTVersion: ct.V1,
			LogID:      ct.LogID{KeyID: *(*[32]byte)(mustDecodeB64("UtToynGEyMkkXDMQei8Ll54oMwWHI0IieDEKs12/Td4="))},
		},
	}

	request2, err := RequestFromPrecert(precert, sctList)
	test.AssertNotError(t, err, "generating request from precert")

	_, issuanceToken2, err := signer.Prepare(request2)
	test.AssertNotError(t, err, "preparing final cert issuance")

	finalCertBytes, err := signer.Issue(issuanceToken2)
	test.AssertNotError(t, err, "Issue failed")

	finalCert, err := x509.ParseCertificate(finalCertBytes)
	test.AssertNotError(t, err, "failed to parse certificate")

	err = finalCert.CheckSignatureFrom(issuerCert.Certificate)
	test.AssertNotError(t, err, "signature validation failed")
	test.AssertByteEquals(t, finalCert.SerialNumber.Bytes(), []byte{1, 2, 3, 4, 5, 6, 7, 8, 9})
	test.AssertDeepEquals(t, finalCert.PublicKey, pk.Public())
	test.AssertEquals(t, len(finalCert.Extensions), 9) // Constraints, KU, EKU, SKID, AKID, AIA, SAN, Policies, SCT list
	test.AssertDeepEquals(t, finalCert.Extensions[8], pkix.Extension{
		Id: sctListOID,
		Value: []byte{
			4, 100, 0, 98, 0, 47, 0, 56, 152, 140, 148, 208, 53, 152, 195, 147, 45,
			223, 233, 35, 186, 186, 242, 122, 66, 14, 185, 108, 65, 225, 90, 168, 12,
			26, 176, 252, 4, 189, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 47,
			0, 82, 212, 232, 202, 113, 132, 200, 201, 36, 92, 51, 16, 122, 47, 11,
			151, 158, 40, 51, 5, 135, 35, 66, 34, 120, 49, 10, 179, 93, 191, 77, 222,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		},
	})
}

func TestIssueMustStaple(t *testing.T) {
	fc := clock.NewFake()
	fc.Set(time.Now())
	linter, err := linter.New(
		issuerCert.Certificate,
		issuerSigner,
		[]string{
			"w_ct_sct_policy_count_unsatisfied",
			"e_scts_from_same_operator",
		},
	)
	test.AssertNotError(t, err, "failed to create linter")
	signer, err := NewIssuer(issuerCert, issuerSigner, defaultProfile(), linter, fc)
	test.AssertNotError(t, err, "NewIssuer failed")
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "failed to generate test key")
	_, issuanceToken, err := signer.Prepare(&IssuanceRequest{
		PublicKey:         pk.Public(),
		Serial:            []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
		DNSNames:          []string{"example.com"},
		IncludeMustStaple: true,
		NotBefore:         fc.Now(),
		NotAfter:          fc.Now().Add(time.Hour - time.Second),
		IncludeCTPoison:   true,
	})
	test.AssertNotError(t, err, "Prepare failed")
	certBytes, err := signer.Issue(issuanceToken)
	test.AssertNotError(t, err, "Issue failed")
	cert, err := x509.ParseCertificate(certBytes)
	test.AssertNotError(t, err, "failed to parse certificate")
	err = cert.CheckSignatureFrom(issuerCert.Certificate)
	test.AssertNotError(t, err, "signature validation failed")
	test.AssertByteEquals(t, cert.SerialNumber.Bytes(), []byte{1, 2, 3, 4, 5, 6, 7, 8, 9})
	test.AssertDeepEquals(t, cert.PublicKey, pk.Public())
	test.AssertEquals(t, len(cert.Extensions), 10) // Constraints, KU, EKU, SKID, AKID, AIA, SAN, Policies, Must-Staple, Poison
	test.AssertDeepEquals(t, cert.Extensions[9], mustStapleExt)
}

func TestIssueBadLint(t *testing.T) {
	fc := clock.NewFake()
	fc.Set(time.Now())
	lint, err := linter.New(issuerCert.Certificate, issuerSigner, []string{})
	test.AssertNotError(t, err, "failed to create linter")
	signer, err := NewIssuer(issuerCert, issuerSigner, defaultProfile(), lint, fc)
	test.AssertNotError(t, err, "NewIssuer failed")
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "failed to generate test key")
	_, _, err = signer.Prepare(&IssuanceRequest{
		PublicKey:       pk.Public(),
		Serial:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
		DNSNames:        []string{"example-com"},
		NotBefore:       fc.Now(),
		NotAfter:        fc.Now().Add(time.Hour - time.Second),
		IncludeCTPoison: true,
	})
	test.AssertError(t, err, "Prepare didn't fail")
	test.AssertErrorIs(t, err, linter.ErrLinting)
	test.AssertContains(t, err.Error(), "tbsCertificate linting failed: failed lint(s)")
}

func TestLoadChain_Valid(t *testing.T) {
	chain, err := LoadChain([]string{
		"../test/test-ca-cross.pem",
		"../test/test-root2.pem",
	})
	test.AssertNotError(t, err, "Should load valid chain")

	expectedIssuer, err := core.LoadCert("../test/test-ca-cross.pem")
	test.AssertNotError(t, err, "Failed to load test issuer")

	chainIssuer := chain[0]
	test.AssertNotNil(t, chainIssuer, "Failed to decode chain PEM")

	test.AssertByteEquals(t, chainIssuer.Raw, expectedIssuer.Raw)
}

func TestLoadChain_TooShort(t *testing.T) {
	_, err := LoadChain([]string{"/path/to/one/cert.pem"})
	test.AssertError(t, err, "Should reject too-short chain")
}

func TestLoadChain_Unloadable(t *testing.T) {
	_, err := LoadChain([]string{
		"does-not-exist.pem",
		"../test/test-root2.pem",
	})
	test.AssertError(t, err, "Should reject unloadable chain")

	_, err = LoadChain([]string{
		"../test/test-ca-cross.pem",
		"does-not-exist.pem",
	})
	test.AssertError(t, err, "Should reject unloadable chain")

	invalidPEMFile, _ := os.CreateTemp("", "invalid.pem")
	err = os.WriteFile(invalidPEMFile.Name(), []byte(""), 0640)
	test.AssertNotError(t, err, "Error writing invalid PEM tmp file")
	_, err = LoadChain([]string{
		invalidPEMFile.Name(),
		"../test/test-root2.pem",
	})
	test.AssertError(t, err, "Should reject unloadable chain")
}

func TestLoadChain_InvalidSig(t *testing.T) {
	_, err := LoadChain([]string{
		"../test/test-root2.pem",
		"../test/test-ca-cross.pem",
	})
	test.AssertError(t, err, "Should reject invalid signature")
	test.Assert(t, strings.Contains(err.Error(), "test-ca-cross.pem"),
		fmt.Sprintf("Expected error to mention filename, got: %s", err))
	test.Assert(t, strings.Contains(err.Error(), "signature from \"CN=happy hacker fake CA\""),
		fmt.Sprintf("Expected error to mention subject, got: %s", err))
}

func TestIssuanceToken(t *testing.T) {
	fc := clock.NewFake()
	linter, err := linter.New(issuerCert.Certificate, issuerSigner, []string{})
	test.AssertNotError(t, err, "failed to create linter")
	signer, err := NewIssuer(issuerCert, issuerSigner, defaultProfile(), linter, fc)
	test.AssertNotError(t, err, "NewIssuer failed")

	_, err = signer.Issue(&issuanceToken{})
	test.AssertError(t, err, "expected issuance with a zero token to fail")

	_, err = signer.Issue(nil)
	test.AssertError(t, err, "expected issuance with a nil token to fail")

	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	test.AssertNotError(t, err, "failed to generate test key")
	_, issuanceToken, err := signer.Prepare(&IssuanceRequest{
		PublicKey:       pk.Public(),
		Serial:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
		DNSNames:        []string{"example.com"},
		NotBefore:       fc.Now(),
		NotAfter:        fc.Now().Add(time.Hour - time.Second),
		IncludeCTPoison: true,
	})
	test.AssertNotError(t, err, "expected Prepare to succeed")
	_, err = signer.Issue(issuanceToken)
	test.AssertNotError(t, err, "expected first issuance to succeed")

	_, err = signer.Issue(issuanceToken)
	test.AssertError(t, err, "expected second issuance with the same issuance token to fail")
	test.AssertContains(t, err.Error(), "issuance token already redeemed")

	_, issuanceToken, err = signer.Prepare(&IssuanceRequest{
		PublicKey:       pk.Public(),
		Serial:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
		DNSNames:        []string{"example.com"},
		NotBefore:       fc.Now(),
		NotAfter:        fc.Now().Add(time.Hour - time.Second),
		IncludeCTPoison: true,
	})
	test.AssertNotError(t, err, "expected Prepare to succeed")

	signer2, err := NewIssuer(issuerCert, issuerSigner, defaultProfile(), linter, fc)
	test.AssertNotError(t, err, "NewIssuer failed")

	_, err = signer2.Issue(issuanceToken)
	test.AssertError(t, err, "expected redeeming an issuance token with the wrong issuer to fail")
	test.AssertContains(t, err.Error(), "wrong issuer")
}

func TestInvalidProfile(t *testing.T) {
	fc := clock.NewFake()
	fc.Set(time.Now())
	err := loglist.InitLintList("../test/ct-test-srv/log_list.json")
	test.AssertNotError(t, err, "failed to load log list")
	linter, err := linter.New(
		issuerCert.Certificate,
		issuerSigner,
		[]string{},
	)
	test.AssertNotError(t, err, "failed to create linter")
	signer, err := NewIssuer(issuerCert, issuerSigner, defaultProfile(), linter, fc)
	test.AssertNotError(t, err, "NewIssuer failed")
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "failed to generate test key")
	_, _, err = signer.Prepare(&IssuanceRequest{
		PublicKey:       pk.Public(),
		Serial:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
		DNSNames:        []string{"example.com"},
		NotBefore:       fc.Now(),
		NotAfter:        fc.Now().Add(time.Hour - time.Second),
		IncludeCTPoison: true,
		precertDER:      []byte{6, 6, 6},
	})
	test.AssertError(t, err, "Invalid IssuanceRequest")

	_, _, err = signer.Prepare(&IssuanceRequest{
		PublicKey: pk.Public(),
		Serial:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
		DNSNames:  []string{"example.com"},
		NotBefore: fc.Now(),
		NotAfter:  fc.Now().Add(time.Hour - time.Second),
		sctList: []ct.SignedCertificateTimestamp{
			{
				SCTVersion: ct.V1,
				LogID:      ct.LogID{KeyID: *(*[32]byte)(mustDecodeB64("OJiMlNA1mMOTLd/pI7q68npCDrlsQeFaqAwasPwEvQM="))},
			},
		},
		precertDER: []byte{},
	})
	test.AssertError(t, err, "Invalid IssuanceRequest")
}

// Generate a precert from one profile and a final cert from another, and verify
// that the final cert errors out when linted because the lint cert doesn't
// corresponding with the precert.
func TestMismatchedProfiles(t *testing.T) {
	fc := clock.NewFake()
	fc.Set(time.Now())
	err := loglist.InitLintList("../test/ct-test-srv/log_list.json")
	test.AssertNotError(t, err, "failed to load log list")
	linter, err := linter.New(
		issuerCert.Certificate,
		issuerSigner,
		[]string{"n_subject_common_name_included"},
	)
	test.AssertNotError(t, err, "failed to create linter")

	issuer1, err := NewIssuer(issuerCert, issuerSigner, defaultProfile(), linter, fc)
	test.AssertNotError(t, err, "NewIssuer failed")
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "failed to generate test key")
	_, issuanceToken, err := issuer1.Prepare(&IssuanceRequest{
		PublicKey:       pk.Public(),
		Serial:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
		CommonName:      "example.com",
		DNSNames:        []string{"example.com"},
		NotBefore:       fc.Now(),
		NotAfter:        fc.Now().Add(time.Hour - time.Second),
		IncludeCTPoison: true,
	})
	test.AssertNotError(t, err, "making IssuanceRequest")

	precertDER, err := issuer1.Issue(issuanceToken)
	test.AssertNotError(t, err, "signing precert")

	// Create a new profile that differs slightly (no common name)
	profileConfig := defaultProfileConfig()
	profileConfig.AllowCommonName = false
	p, err := NewProfile(profileConfig, defaultIssuerConfig())
	test.AssertNotError(t, err, "NewProfile failed")
	issuer2, err := NewIssuer(issuerCert, issuerSigner, p, linter, fc)
	test.AssertNotError(t, err, "NewIssuer failed")

	sctList := []ct.SignedCertificateTimestamp{
		{
			SCTVersion: ct.V1,
			LogID:      ct.LogID{KeyID: *(*[32]byte)(mustDecodeB64("OJiMlNA1mMOTLd/pI7q68npCDrlsQeFaqAwasPwEvQM="))},
		},
		{
			SCTVersion: ct.V1,
			LogID:      ct.LogID{KeyID: *(*[32]byte)(mustDecodeB64("UtToynGEyMkkXDMQei8Ll54oMwWHI0IieDEKs12/Td4="))},
		},
	}

	precert, err := x509.ParseCertificate(precertDER)
	test.AssertNotError(t, err, "parsing precert")

	request2, err := RequestFromPrecert(precert, sctList)
	test.AssertNotError(t, err, "RequestFromPrecert")
	request2.CommonName = ""

	_, _, err = issuer2.Prepare(request2)
	test.AssertError(t, err, "preparing final cert issuance")
	test.AssertContains(t, err.Error(), "precert does not correspond to linted final cert")
}
