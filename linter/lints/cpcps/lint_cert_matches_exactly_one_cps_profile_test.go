package cpcps

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/zmap/zlint/v3/lint"
)

func TestCertMatchesExactlyOneCPSProfile(t *testing.T) {
	t.Parallel()

	rootKey := testKey(t, elliptic.P384())
	rootTmpl := testRootTemplate(t, rootKey.Public())
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("creating test root: %s", err)
	}

	intKey := testKey(t, elliptic.P384())
	intTmpl := testIntermediateTemplate(t, intKey.Public())
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, rootTmpl, intKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("creating test intermediate: %s", err)
	}

	crossKey := testKey(t, elliptic.P384())
	existingDER, err := x509.CreateCertificate(rand.Reader, testCrossCertTemplate(t, crossKey.Public()), testCrossCertTemplate(t, crossKey.Public()), crossKey.Public(), crossKey)
	if err != nil {
		t.Fatalf("creating existing CA certificate: %s", err)
	}
	crossDER, err := x509.CreateCertificate(rand.Reader, testCrossCertTemplate(t, crossKey.Public()), rootTmpl, crossKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("creating test cross-certificate: %s", err)
	}

	leafKey := testKey(t, elliptic.P256())
	leafDER, err := x509.CreateCertificate(rand.Reader, testLeafTemplate(t), intTmpl, leafKey.Public(), intKey)
	if err != nil {
		t.Fatalf("creating test leaf: %s", err)
	}

	precertDER, err := x509.CreateCertificate(rand.Reader, testPrecertTemplate(t), intTmpl, leafKey.Public(), intKey)
	if err != nil {
		t.Fatalf("creating test precertificate: %s", err)
	}

	// An end-entity certificate which matches no profile: not a server auth
	// cert, because it asserts only the emailProtection EKU and carries no
	// Baseline Requirements policy OID.
	smimeTmpl := testLeafTemplate(t)
	smimeTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
	smimeTmpl.Policies = nil
	smimeDER, err := x509.CreateCertificate(rand.Reader, smimeTmpl, intTmpl, leafKey.Public(), intKey)
	if err != nil {
		t.Fatalf("creating test smime leaf: %s", err)
	}

	// A self-signed end-entity certificate matches no profile: it is neither
	// a CA (so not the Root CA profile) nor a subscriber cert (zcrypto
	// considers subscriber certs to be non-self-signed).
	selfSignedTmpl := testLeafTemplate(t)
	selfSignedDER, err := x509.CreateCertificate(rand.Reader, selfSignedTmpl, selfSignedTmpl, leafKey.Public(), leafKey)
	if err != nil {
		t.Fatalf("creating test self-signed leaf: %s", err)
	}

	existingConfig := &SharedConfig{ExistingCertificatePEM: testPEM(t, existingDER)}

	testCases := []struct {
		name       string
		der        []byte
		config     *SharedConfig
		want       lint.LintStatus
		wantSubStr string
	}{
		{
			name:   "root_ca",
			der:    rootDER,
			config: &SharedConfig{},
			want:   lint.Pass,
		},
		{
			name:   "tls_subordinate_ca",
			der:    intDER,
			config: &SharedConfig{},
			want:   lint.Pass,
		},
		{
			name:   "cross_certified_subordinate_ca",
			der:    crossDER,
			config: existingConfig,
			want:   lint.Pass,
		},
		{
			// Profile selection for subordinate CA certificates is driven by
			// the lint configuration, not by the certificate contents: with an
			// existing certificate configured, a subordinate CA certificate is
			// covered by the Cross-Certified profile, so it still matches
			// exactly one profile.
			name:   "tls_subordinate_ca_with_existing_config",
			der:    intDER,
			config: existingConfig,
			want:   lint.Pass,
		},
		{
			// The lint must not panic when it was never configured; a nil
			// Config means no existing certificate, i.e. the TLS Subordinate
			// CA profile.
			name:   "tls_subordinate_ca_nil_config",
			der:    intDER,
			config: nil,
			want:   lint.Pass,
		},
		{
			name:   "subscriber",
			der:    leafDER,
			config: &SharedConfig{},
			want:   lint.Pass,
		},
		{
			name:   "precertificate",
			der:    precertDER,
			config: &SharedConfig{},
			want:   lint.Pass,
		},
		{
			name:       "smime_leaf_matches_no_profile",
			der:        smimeDER,
			config:     &SharedConfig{},
			want:       lint.Error,
			wantSubStr: "cert does not match any CPS profile",
		},
		{
			name:       "self_signed_leaf_matches_no_profile",
			der:        selfSignedDER,
			config:     &SharedConfig{},
			want:       lint.Error,
			wantSubStr: "cert does not match any CPS profile",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cert := testParseZCert(t, tc.der)

			l := &certMatchesExactlyOneCPSProfile{Config: tc.config}
			if !l.CheckApplies(cert) {
				t.Fatal("lint does not apply to test certificate")
			}

			res := l.Execute(cert)
			if res.Status != tc.want {
				t.Errorf("got status %s (%q), want %s", res.Status, res.Details, tc.want)
			}
			if !strings.Contains(res.Details, tc.wantSubStr) {
				t.Errorf("got details %q, want substring %q", res.Details, tc.wantSubStr)
			}
		})
	}
}
