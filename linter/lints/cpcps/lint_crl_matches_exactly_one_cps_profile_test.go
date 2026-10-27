package cpcps

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"golang.org/x/crypto/cryptobyte"
)

func TestCRLMatchesExactlyOneCPSProfile(t *testing.T) {
	t.Parallel()

	rootKey := testKey(t, elliptic.P384())
	rootTmpl := testRootTemplate(t, rootKey.Public())
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("creating test issuer: %s", err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parsing test issuer: %s", err)
	}

	testCases := []struct {
		name       string
		tmpl       func(t *testing.T) *x509.RevocationList
		mod        func(t *testing.T, tmpl *x509.RevocationList)
		want       lint.LintStatus
		wantSubStr string
	}{
		{
			name: "ca_crl",
			tmpl: testCACRLTemplate,
			want: lint.Pass,
		},
		{
			name: "subscriber_crl",
			tmpl: testSubscriberCRLTemplate,
			want: lint.Pass,
		},
		{
			name: "no_idp",
			tmpl: testCACRLTemplate,
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				tmpl.ExtraExtensions = nil
			},
			want:       lint.Error,
			wantSubStr: "CRL does not match any CPS profile",
		},
		{
			// A distributionPoint alone declares no restriction on the CRL's
			// scope, so this CRL's scope would include both CA and Subscriber
			// Certificates.
			name: "idp_without_scope",
			tmpl: testSubscriberCRLTemplate,
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				tmpl.ExtraExtensions = []pkix.Extension{testIDPExt(true, func(b *cryptobyte.Builder) {
					addIDPDistributionPoint(b, "http://e99.c.lencr.org/1.crl")
				})}
			},
			want:       lint.Error,
			wantSubStr: "CRL does not match any CPS profile",
		},
		{
			name: "idp_unparsable",
			tmpl: testCACRLTemplate,
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				tmpl.ExtraExtensions = []pkix.Extension{testIDPExt(true, func(b *cryptobyte.Builder) {
					// An onlyContainsCACerts field whose length runs past the end
					// of the SEQUENCE.
					b.AddBytes([]byte{0x82, 0x05})
				})}
			},
			want:       lint.Error,
			wantSubStr: "CRL does not match any CPS profile",
		},
		{
			name: "idp_both_scopes",
			tmpl: testCACRLTemplate,
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				tmpl.ExtraExtensions = []pkix.Extension{testIDPExt(true, func(b *cryptobyte.Builder) {
					addIDPBoolean(b, 1, true)
					addIDPBoolean(b, 2, true)
				})}
			},
			want:       lint.Error,
			wantSubStr: "CRL matches multiple CPS profiles",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tmpl := tc.tmpl(t)
			if tc.mod != nil {
				tc.mod(t, tmpl)
			}

			der, err := x509.CreateRevocationList(rand.Reader, tmpl, root, rootKey)
			if err != nil {
				t.Fatalf("creating test CRL: %s", err)
			}
			crl := testParseZCRL(t, der)

			l := &crlMatchesExactlyOneCPSProfile{}
			if !l.CheckApplies(crl) {
				t.Fatal("lint does not apply to test CRL")
			}

			res := l.Execute(crl)
			if res.Status != tc.want {
				t.Errorf("got status %s (%q), want %s", res.Status, res.Details, tc.want)
			}
			if !strings.Contains(res.Details, tc.wantSubStr) {
				t.Errorf("got details %q, want substring %q", res.Details, tc.wantSubStr)
			}
		})
	}
}
