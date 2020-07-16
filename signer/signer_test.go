package signer

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/test"
)

func TestNewProfilePolicies(t *testing.T) {
	profile, err := newProfile(ProfileConfig{
		AllowRSAKeys:     true,
		AllowECDSAKeys:   true,
		AllowMustStaple:  true,
		AllowCTPoison:    true,
		AllowSCTList:     true,
		IssuerURL:        "issuer-url",
		CRLURL:           "crl-url",
		OCSPURL:          "ocsp-url",
		ValidityPeriod:   time.Hour,
		ValidityBackdate: time.Minute,
		Policies: []PolicyInformation{
			{
				OID: "1.2.3",
			},
			{
				OID: "1.2.3.4",
				Qualifiers: []PolicyQualifier{
					{
						Type:  "id-qt-cps",
						Value: "cps-url",
					},
				},
			},
		},
	})
	test.AssertNotError(t, err, "newProfile failed")
	test.AssertDeepEquals(t, *profile, signingProfile{
		allowRSAKeys:    true,
		allowECDSAKeys:  true,
		allowMustStaple: true,
		allowCTPoison:   true,
		allowSCTList:    true,
		issuerURL:       "issuer-url",
		crlURL:          "crl-url",
		ocspURL:         "ocsp-url",
		validityPeriod:  time.Hour,
		backdate:        time.Minute,
		policies: &pkix.Extension{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 32},
			Value: []byte{48, 36, 48, 4, 6, 2, 42, 3, 48, 28, 6, 3, 42, 3, 4, 48, 21, 48, 19, 6, 8, 43, 6, 1, 5, 5, 7, 2, 1, 22, 7, 99, 112, 115, 45, 117, 114, 108},
		},
	})
	var policies []policyInformation
	_, err = asn1.Unmarshal(profile.policies.Value, &policies)
	test.AssertNotError(t, err, "failed to parse policies extension")
	test.AssertEquals(t, len(policies), 2)
	test.AssertDeepEquals(t, policies[0], policyInformation{
		Policy: asn1.ObjectIdentifier{1, 2, 3},
	})
	test.AssertDeepEquals(t, policies[1], policyInformation{
		Policy: asn1.ObjectIdentifier{1, 2, 3, 4},
		Qualifiers: []policyQualifier{{
			OID:   asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1},
			Value: "cps-url",
		}},
	})
}

func TestNewProfileNoIssuerURL(t *testing.T) {
	_, err := newProfile(ProfileConfig{})
	test.AssertError(t, err, "newProfile didn't fail with no issuer URL")
	test.AssertEquals(t, err.Error(), "Issuer URL is required")
}

func TestNewProfileNoOCSPURL(t *testing.T) {
	_, err := newProfile(ProfileConfig{IssuerURL: "issuer-url"})
	test.AssertError(t, err, "newProfile didn't fail with no OCSP URL")
	test.AssertEquals(t, err.Error(), "OCSP URL is required")
}

func TestNewProfileInvalidOID(t *testing.T) {
	_, err := newProfile(ProfileConfig{
		IssuerURL: "issuer-url",
		OCSPURL:   "ocsp-url",
		Policies: []PolicyInformation{{
			OID: "a.b.c",
		}},
	})
	test.AssertError(t, err, "newProfile didn't fail with unknown policy qualifier type")
	test.AssertEquals(t, err.Error(), "failed parsing policy OID \"a.b.c\": strconv.Atoi: parsing \"a\": invalid syntax")
}

func TestNewProfileUnknownQualifierType(t *testing.T) {
	_, err := newProfile(ProfileConfig{
		IssuerURL: "issuer-url",
		OCSPURL:   "ocsp-url",
		Policies: []PolicyInformation{{
			OID: "1.2.3",
			Qualifiers: []PolicyQualifier{{
				Type:  "asd",
				Value: "bad",
			}},
		}},
	})
	test.AssertError(t, err, "newProfile didn't fail with unknown policy qualifier type")
	test.AssertEquals(t, err.Error(), "unknown qualifier type: asd")
}

func TestRequestValid(t *testing.T) {
	tests := []struct {
		name          string
		profile       *signingProfile
		request       *IssuanceRequest
		expectedError string
	}{
		{
			name:          "unsupported key type",
			profile:       &signingProfile{},
			request:       &IssuanceRequest{PublicKey: &dsa.PublicKey{}},
			expectedError: "unsupported public key type",
		},
		{
			name:          "rsa keys not allowed",
			profile:       &signingProfile{},
			request:       &IssuanceRequest{PublicKey: &rsa.PublicKey{}},
			expectedError: "RSA keys not allowed",
		},
		{
			name:          "ecdsa keys not allowed",
			profile:       &signingProfile{},
			request:       &IssuanceRequest{PublicKey: &ecdsa.PublicKey{}},
			expectedError: "ECDSA keys not allowed",
		},
		{
			name: "must staple not allowed",
			profile: &signingProfile{
				allowECDSAKeys: true,
			},
			request: &IssuanceRequest{
				PublicKey:         &ecdsa.PublicKey{},
				IncludeMustStaple: true,
			},
			expectedError: "must-staple extension cannot be included",
		},
		{
			name: "ct poison not allowed",
			profile: &signingProfile{
				allowECDSAKeys: true,
			},
			request: &IssuanceRequest{
				PublicKey:       &ecdsa.PublicKey{},
				IncludeCTPoison: true,
			},
			expectedError: "ct poison extension cannot be included",
		},
		{
			name: "sct list not allowed",
			profile: &signingProfile{
				allowECDSAKeys: true,
			},
			request: &IssuanceRequest{
				PublicKey:      &ecdsa.PublicKey{},
				IncludeSCTList: []ct.SignedCertificateTimestamp{},
			},
			expectedError: "sct list extension cannot be included",
		},
		{
			name: "sct list and ct poison not allowed",
			profile: &signingProfile{
				allowECDSAKeys: true,
				allowCTPoison:  true,
				allowSCTList:   true,
			},
			request: &IssuanceRequest{
				PublicKey:       &ecdsa.PublicKey{},
				IncludeCTPoison: true,
				IncludeSCTList:  []ct.SignedCertificateTimestamp{},
			},
			expectedError: "cannot include both ct poison and sct list extensions",
		},
		{
			name: "good",
			profile: &signingProfile{
				allowECDSAKeys: true,
			},
			request: &IssuanceRequest{
				PublicKey: &ecdsa.PublicKey{},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.profile.requestValid(tc.request)
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
		profile          *signingProfile
		expectedTemplate *x509.Certificate
	}{
		{
			name: "crl url",
			profile: &signingProfile{
				crlURL:         "crl-url",
				sigAlg:         x509.SHA256WithRSA,
				keyUsage:       x509.KeyUsageDigitalSignature,
				validityPeriod: time.Hour,
			},
			expectedTemplate: &x509.Certificate{
				SignatureAlgorithm:    x509.SHA256WithRSA,
				KeyUsage:              x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           defaultEKU,
				IssuingCertificateURL: []string{""},
				OCSPServer:            []string{""},
				NotBefore:             time.Time{}.Add(time.Hour),
				NotAfter:              time.Time{}.Add(time.Hour * 2),
				CRLDistributionPoints: []string{"crl-url"},
			},
		},
		{
			name: "backdate",
			profile: &signingProfile{
				sigAlg:         x509.SHA256WithRSA,
				keyUsage:       x509.KeyUsageDigitalSignature,
				validityPeriod: time.Hour,
				backdate:       time.Minute * 30,
			},
			expectedTemplate: &x509.Certificate{
				SignatureAlgorithm:    x509.SHA256WithRSA,
				KeyUsage:              x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           defaultEKU,
				IssuingCertificateURL: []string{""},
				OCSPServer:            []string{""},
				NotBefore:             time.Time{}.Add(time.Minute * 30),
				NotAfter:              time.Time{}.Add(time.Minute * 90),
			},
		},
		{
			name: "include policies",
			profile: &signingProfile{
				sigAlg:         x509.SHA256WithRSA,
				keyUsage:       x509.KeyUsageDigitalSignature,
				validityPeriod: time.Hour,
				policies: &pkix.Extension{
					Id:    asn1.ObjectIdentifier{1, 2, 3},
					Value: []byte{4, 5, 6},
				},
			},
			expectedTemplate: &x509.Certificate{
				SignatureAlgorithm:    x509.SHA256WithRSA,
				KeyUsage:              x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           defaultEKU,
				IssuingCertificateURL: []string{""},
				OCSPServer:            []string{""},
				NotBefore:             time.Time{}.Add(time.Hour),
				NotAfter:              time.Time{}.Add(time.Hour * 2),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{1, 2, 3},
						Value: []byte{4, 5, 6},
					},
				},
			},
		},
	}
	fc := clock.NewFake()
	fc.Set(time.Time{}.Add(time.Hour))
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			template := tc.profile.generateTemplate(fc)
			test.AssertDeepEquals(t, *template, *tc.expectedTemplate)
		})
	}
}

func TestNewSignerUnsupportedKeyType(t *testing.T) {
	_, err := NewSigner(&SignerConfig{
		Profile: ProfileConfig{
			IssuerURL: "issuer-url",
			OCSPURL:   "ocsp-url",
		},
		Issuer: &x509.Certificate{
			PublicKey: &dsa.PublicKey{},
		},
	})
	test.AssertError(t, err, "NewSigner didn't fail")
	test.AssertEquals(t, err.Error(), "unsupported issuer key type")
}

func TestNewSignerRSAKey(t *testing.T) {
	mod, ok := big.NewInt(0).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	test.Assert(t, ok, "failed to set mod")
	signer, err := NewSigner(&SignerConfig{
		Profile: ProfileConfig{
			IssuerURL: "issuer-url",
			OCSPURL:   "ocsp-url",
		},
		Issuer: &x509.Certificate{
			PublicKey: &rsa.PublicKey{
				N: mod,
			},
		},
	})
	test.AssertNotError(t, err, "NewSigner failed")
	test.AssertEquals(t, signer.profile.keyUsage, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment)
	_, ok = signer.lintKey.(*rsa.PrivateKey)
	test.Assert(t, ok, "lint key is not RSA")
}

func TestNewSignerECDSAKey(t *testing.T) {
	signer, err := NewSigner(&SignerConfig{
		Profile: ProfileConfig{
			IssuerURL: "issuer-url",
			OCSPURL:   "ocsp-url",
		},
		Issuer: &x509.Certificate{
			PublicKey: &ecdsa.PublicKey{
				Curve: elliptic.P256(),
			},
		},
	})
	test.AssertNotError(t, err, "NewSigner failed")
	test.AssertEquals(t, signer.profile.keyUsage, x509.KeyUsageDigitalSignature)
	_, ok := signer.lintKey.(*ecdsa.PrivateKey)
	test.Assert(t, ok, "lint key is not ECDSA")
}

var issuerCert *x509.Certificate
var issuerSigner *ecdsa.PrivateKey

func TestMain(m *testing.M) {
	tk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cmd.FailOnError(err, "failed to generate test key")
	issuerSigner = tk
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(123),
		PublicKey:             tk.Public(),
		BasicConstraintsValid: true,
		IsCA:                  true,
		Subject: pkix.Name{
			CommonName: "big ca",
		},
		KeyUsage:     x509.KeyUsageCertSign,
		SubjectKeyId: []byte{1, 2, 3},
	}
	issuer, err := x509.CreateCertificate(rand.Reader, template, template, tk.Public(), tk)
	cmd.FailOnError(err, "failed to generate test issuer")
	issuerCert, err = x509.ParseCertificate(issuer)
	cmd.FailOnError(err, "failed to parse test issuer")
	os.Exit(m.Run())
}

func TestIssue(t *testing.T) {
	fc := clock.NewFake()
	fc.Set(time.Now())
	signer, err := NewSigner(&SignerConfig{
		Issuer: issuerCert,
		Signer: issuerSigner,
		Clk:    fc,
		Profile: ProfileConfig{
			AllowECDSAKeys: true,
			ValidityPeriod: time.Hour,
			IssuerURL:      "http://issuer-url",
			OCSPURL:        "http://ocsp-url",
			Policies: []PolicyInformation{
				{OID: "1.2.3"},
			},
		},
		IgnoredLints: []string{"w_ct_sct_policy_count_unsatisfied"},
	})
	test.AssertNotError(t, err, "NewSigner failed")
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "failed to generate test key")
	certBytes, err := signer.Issue(&IssuanceRequest{
		PublicKey: pk.Public(),
		Serial:    []byte{1, 2, 3},
		DNSNames:  []string{"example.com"},
	})
	test.AssertNotError(t, err, "Issue failed")
	cert, err := x509.ParseCertificate(certBytes)
	test.AssertNotError(t, err, "failed to parse certificate")
	err = cert.CheckSignatureFrom(issuerCert)
	test.AssertNotError(t, err, "signature validation failed")
	test.AssertByteEquals(t, cert.SerialNumber.Bytes(), []byte{1, 2, 3})
	test.AssertDeepEquals(t, cert.PublicKey, pk.Public())
	test.AssertEquals(t, len(cert.Extensions), 7) // KU, EKU, SKID, AKID, AIA, SAN, Policies
}

func TestIssueCTPoison(t *testing.T) {
	fc := clock.NewFake()
	fc.Set(time.Now())
	signer, err := NewSigner(&SignerConfig{
		Issuer: issuerCert,
		Signer: issuerSigner,
		Clk:    fc,
		Profile: ProfileConfig{
			AllowECDSAKeys: true,
			AllowCTPoison:  true,
			ValidityPeriod: time.Hour,
			IssuerURL:      "http://issuer-url",
			OCSPURL:        "http://ocsp-url",
			Policies: []PolicyInformation{
				{OID: "1.2.3"},
			},
		},
		IgnoredLints: []string{"w_ct_sct_policy_count_unsatisfied"},
	})
	test.AssertNotError(t, err, "NewSigner failed")
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "failed to generate test key")
	certBytes, err := signer.Issue(&IssuanceRequest{
		PublicKey:       pk.Public(),
		Serial:          []byte{1, 2, 3},
		DNSNames:        []string{"example.com"},
		IncludeCTPoison: true,
	})
	test.AssertNotError(t, err, "Issue failed")
	cert, err := x509.ParseCertificate(certBytes)
	test.AssertNotError(t, err, "failed to parse certificate")
	err = cert.CheckSignatureFrom(issuerCert)
	test.AssertNotError(t, err, "signature validation failed")
	test.AssertByteEquals(t, cert.SerialNumber.Bytes(), []byte{1, 2, 3})
	test.AssertDeepEquals(t, cert.PublicKey, pk.Public())
	test.AssertEquals(t, len(cert.Extensions), 8) // KU, EKU, SKID, AKID, AIA, SAN, Policies, CT Poison
	test.AssertDeepEquals(t, cert.Extensions[7], ctPoisonExt)
}

func TestIssueSCTList(t *testing.T) {
	fc := clock.NewFake()
	fc.Set(time.Now())
	signer, err := NewSigner(&SignerConfig{
		Issuer: issuerCert,
		Signer: issuerSigner,
		Clk:    fc,
		Profile: ProfileConfig{
			AllowECDSAKeys: true,
			AllowSCTList:   true,
			ValidityPeriod: time.Hour,
			IssuerURL:      "http://issuer-url",
			OCSPURL:        "http://ocsp-url",
			Policies: []PolicyInformation{
				{OID: "1.2.3"},
			},
		},
		IgnoredLints: []string{"w_ct_sct_policy_count_unsatisfied"},
	})
	test.AssertNotError(t, err, "NewSigner failed")
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "failed to generate test key")
	certBytes, err := signer.Issue(&IssuanceRequest{
		PublicKey: pk.Public(),
		Serial:    []byte{1, 2, 3},
		DNSNames:  []string{"example.com"},
		IncludeSCTList: []ct.SignedCertificateTimestamp{
			{},
		},
	})
	test.AssertNotError(t, err, "Issue failed")
	cert, err := x509.ParseCertificate(certBytes)
	test.AssertNotError(t, err, "failed to parse certificate")
	err = cert.CheckSignatureFrom(issuerCert)
	test.AssertNotError(t, err, "signature validation failed")
	test.AssertByteEquals(t, cert.SerialNumber.Bytes(), []byte{1, 2, 3})
	test.AssertDeepEquals(t, cert.PublicKey, pk.Public())
	test.AssertEquals(t, len(cert.Extensions), 8) // KU, EKU, SKID, AKID, AIA, SAN, Policies, SCT list
	test.AssertDeepEquals(t, cert.Extensions[7], pkix.Extension{
		Id:    sctListOID,
		Value: []byte{4, 51, 0, 49, 0, 47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	})
}

func TestIssueMustStaple(t *testing.T) {
	fc := clock.NewFake()
	fc.Set(time.Now())
	signer, err := NewSigner(&SignerConfig{
		Issuer: issuerCert,
		Signer: issuerSigner,
		Clk:    fc,
		Profile: ProfileConfig{
			AllowECDSAKeys:  true,
			AllowMustStaple: true,
			ValidityPeriod:  time.Hour,
			IssuerURL:       "http://issuer-url",
			OCSPURL:         "http://ocsp-url",
			Policies: []PolicyInformation{
				{OID: "1.2.3"},
			},
		},
		IgnoredLints: []string{"w_ct_sct_policy_count_unsatisfied"},
	})
	test.AssertNotError(t, err, "NewSigner failed")
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "failed to generate test key")
	certBytes, err := signer.Issue(&IssuanceRequest{
		PublicKey:         pk.Public(),
		Serial:            []byte{1, 2, 3},
		DNSNames:          []string{"example.com"},
		IncludeMustStaple: true,
	})
	test.AssertNotError(t, err, "Issue failed")
	cert, err := x509.ParseCertificate(certBytes)
	test.AssertNotError(t, err, "failed to parse certificate")
	err = cert.CheckSignatureFrom(issuerCert)
	test.AssertNotError(t, err, "signature validation failed")
	test.AssertByteEquals(t, cert.SerialNumber.Bytes(), []byte{1, 2, 3})
	test.AssertDeepEquals(t, cert.PublicKey, pk.Public())
	test.AssertEquals(t, len(cert.Extensions), 8) // KU, EKU, SKID, AKID, AIA, SAN, Policies, Must-Staple
	test.AssertDeepEquals(t, cert.Extensions[7], mustStapleExt)
}

func TestIssueBadLint(t *testing.T) {
	fc := clock.NewFake()
	fc.Set(time.Now())
	signer, err := NewSigner(&SignerConfig{
		Issuer: issuerCert,
		Signer: issuerSigner,
		Clk:    fc,
		Profile: ProfileConfig{
			AllowECDSAKeys: true,
			ValidityPeriod: time.Hour,
			IssuerURL:      "http://issuer-url",
			OCSPURL:        "http://ocsp-url",
			Policies: []PolicyInformation{
				{OID: "1.2.3"},
			},
		},
	})
	test.AssertNotError(t, err, "NewSigner failed")
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "failed to generate test key")
	_, err = signer.Issue(&IssuanceRequest{
		PublicKey: pk.Public(),
		Serial:    []byte{1, 2, 3},
		DNSNames:  []string{"example.com"},
	})
	test.AssertError(t, err, "Issue didn't fail")
	test.AssertEquals(t, err.Error(), "tbsCertificate linting failed: w_ct_sct_policy_count_unsatisfied")
}
