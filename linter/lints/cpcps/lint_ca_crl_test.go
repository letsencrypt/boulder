package cpcps

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	zx509 "github.com/zmap/zcrypto/x509"
	zpkix "github.com/zmap/zcrypto/x509/pkix"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestCACRLMatchesCPSProfile(t *testing.T) {
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
		name string
		mod  func(t *testing.T, tmpl *x509.RevocationList)
		// parsedMod modifies the CRL after it has been parsed, to represent
		// malformations which crypto/x509 refuses to produce.
		parsedMod  func(t *testing.T, crl *zx509.RevocationList)
		want       lint.LintStatus
		wantSubStr string
	}{
		{
			name: "good",
			want: lint.Pass,
		},
		{
			name: "good_no_entries",
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				tmpl.RevokedCertificateEntries = nil
			},
			want: lint.Pass,
		},
		{
			name: "tbs_malformed",
			parsedMod: func(t *testing.T, crl *zx509.RevocationList) {
				crl.RawTBSRevocationList = []byte{}
			},
			want:       lint.Error,
			wantSubStr: "failed to parse tbsCertList",
		},
		{
			// zcrypto refuses to parse a CRL whose version is not v2, so this and
			// the following cases replace the parsed tbsCertList with a truncated
			// one.
			name: "version_missing",
			parsedMod: func(t *testing.T, crl *zx509.RevocationList) {
				// A tbsCertList whose first field is the signature SEQUENCE.
				crl.RawTBSRevocationList = []byte{0x30, 0x02, 0x30, 0x00}
			},
			want:       lint.Error,
			wantSubStr: "version is not v2",
		},
		{
			name: "version_v3",
			parsedMod: func(t *testing.T, crl *zx509.RevocationList) {
				crl.RawTBSRevocationList = []byte{0x30, 0x03, 0x02, 0x01, 0x02}
			},
			want:       lint.Error,
			wantSubStr: "version is not v2",
		},
		{
			name: "version_malformed",
			parsedMod: func(t *testing.T, crl *zx509.RevocationList) {
				// A version INTEGER with no contents.
				crl.RawTBSRevocationList = []byte{0x30, 0x02, 0x02, 0x00}
			},
			want:       lint.Error,
			wantSubStr: "failed to parse tbsCertList.version",
		},
		{
			name: "signature_missing",
			parsedMod: func(t *testing.T, crl *zx509.RevocationList) {
				// A tbsCertList containing only a version.
				crl.RawTBSRevocationList = []byte{0x30, 0x03, 0x02, 0x01, 0x01}
			},
			want:       lint.Error,
			wantSubStr: "failed to parse tbsCertList.signature",
		},
		{
			name: "next_update_too_late",
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				// One second past the maximum of 365 days.
				tmpl.NextUpdate = tmpl.ThisUpdate.Add(365*24*time.Hour + time.Second)
			},
			want:       lint.Error,
			wantSubStr: "nextUpdate is more than 365 days after thisUpdate",
		},
		{
			name: "next_update_missing",
			parsedMod: func(t *testing.T, crl *zx509.RevocationList) {
				crl.NextUpdate = time.Time{}
			},
			want:       lint.Error,
			wantSubStr: "nextUpdate is not present",
		},
		{
			name: "next_update_before_this_update",
			parsedMod: func(t *testing.T, crl *zx509.RevocationList) {
				crl.NextUpdate = crl.ThisUpdate.Add(-time.Second)
			},
			want:       lint.Error,
			wantSubStr: "nextUpdate is before thisUpdate",
		},
		{
			name: "empty_revoked_certificates",
			parsedMod: func(t *testing.T, crl *zx509.RevocationList) {
				crl.RevokedCertificates = []zx509.RevokedCertificate{}
			},
			want:       lint.Error,
			wantSubStr: "revokedCertificates is present but contains no entries",
		},
		{
			name: "serial_not_positive",
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				tmpl.RevokedCertificateEntries[0].SerialNumber = big.NewInt(0)
			},
			want:       lint.Error,
			wantSubStr: "serialNumber is not a positive integer",
		},
		{
			name: "good_revocation_at_this_update",
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				tmpl.RevokedCertificateEntries[0].RevocationTime = tmpl.ThisUpdate
			},
			want: lint.Pass,
		},
		{
			name: "revocation_after_this_update",
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				tmpl.RevokedCertificateEntries[0].RevocationTime = tmpl.ThisUpdate.Add(time.Second)
			},
			want:       lint.Error,
			wantSubStr: "revocationDate is later than thisUpdate",
		},
		{
			name: "good_reason_codes",
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				tmpl.RevokedCertificateEntries = nil
				for _, reason := range []int{1, 4, 5, 9} {
					tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{
						SerialNumber:   testSerial(t, 16),
						RevocationTime: tmpl.ThisUpdate.Add(-time.Hour),
						ReasonCode:     reason,
					})
				}
			},
			want: lint.Pass,
		},
		{
			// crypto/x509 omits the reasonCode extension for unspecified (0).
			name: "missing_reason_code",
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				tmpl.RevokedCertificateEntries[0].ReasonCode = 0
			},
			want:       lint.Error,
			wantSubStr: "reasonCode extension is not present",
		},
		{
			name: "reason_code_ca_compromise",
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				tmpl.RevokedCertificateEntries[0].ReasonCode = 2
			},
			want:       lint.Error,
			wantSubStr: "reasonCode 2 is not one of 1, 4, 5, or 9",
		},
		{
			name: "reason_code_affiliation_changed",
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				tmpl.RevokedCertificateEntries[0].ReasonCode = 3
			},
			want:       lint.Error,
			wantSubStr: "reasonCode 3 is not one of 1, 4, 5, or 9",
		},
		{
			name: "critical_reason_code",
			parsedMod: func(t *testing.T, crl *zx509.RevocationList) {
				criticalizeZExt(crl.RevokedCertificates[0].Extensions, util.ReasonCodeOID)
			},
			want:       lint.Error,
			wantSubStr: "reasonCode extension is critical",
		},
		{
			name: "entry_extra_extension",
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				// An invalidityDate extension.
				invalidityDate, err := asn1.MarshalWithParams(tmpl.ThisUpdate.Add(-24*time.Hour), "generalized")
				if err != nil {
					t.Fatalf("marshalling invalidityDate: %s", err)
				}
				tmpl.RevokedCertificateEntries[0].ExtraExtensions = []pkix.Extension{
					{Id: asn1.ObjectIdentifier{2, 5, 29, 24}, Value: invalidityDate},
				}
			},
			want:       lint.Error,
			wantSubStr: "unexpected extension 2.5.29.24",
		},
		{
			name: "entry_duplicate_reason_code",
			parsedMod: func(t *testing.T, crl *zx509.RevocationList) {
				entry := &crl.RevokedCertificates[0]
				entry.Extensions = append(entry.Extensions, entry.Extensions[0])
			},
			want:       lint.Error,
			wantSubStr: "duplicate extension 2.5.29.21",
		},
		{
			name: "missing_aki",
			parsedMod: func(t *testing.T, crl *zx509.RevocationList) {
				crl.Extensions = removeZExt(crl.Extensions, util.AuthkeyOID)
			},
			want:       lint.Error,
			wantSubStr: "authorityKeyIdentifier extension is not present",
		},
		{
			name: "critical_aki",
			parsedMod: func(t *testing.T, crl *zx509.RevocationList) {
				criticalizeZExt(crl.Extensions, util.AuthkeyOID)
			},
			want:       lint.Error,
			wantSubStr: "authorityKeyIdentifier extension is critical",
		},
		{
			name: "aki_without_key_identifier",
			parsedMod: func(t *testing.T, crl *zx509.RevocationList) {
				crl.Extensions = removeZExt(crl.Extensions, util.AuthkeyOID)
				// An empty AuthorityKeyIdentifier SEQUENCE.
				crl.Extensions = append(crl.Extensions, zpkix.Extension{Id: util.AuthkeyOID, Value: []byte{0x30, 0x00}})
			},
			want:       lint.Error,
			wantSubStr: "authorityKeyIdentifier does not contain a keyIdentifier",
		},
		{
			name: "aki_malformed",
			parsedMod: func(t *testing.T, crl *zx509.RevocationList) {
				crl.Extensions = removeZExt(crl.Extensions, util.AuthkeyOID)
				// An OCTET STRING, rather than an AuthorityKeyIdentifier SEQUENCE.
				crl.Extensions = append(crl.Extensions, zpkix.Extension{Id: util.AuthkeyOID, Value: []byte{0x04, 0x00}})
			},
			want:       lint.Error,
			wantSubStr: "failed to parse authorityKeyIdentifier",
		},
		{
			name: "aki_trailing_data",
			parsedMod: func(t *testing.T, crl *zx509.RevocationList) {
				crl.Extensions = removeZExt(crl.Extensions, util.AuthkeyOID)
				// An empty AuthorityKeyIdentifier SEQUENCE, followed by a stray byte.
				crl.Extensions = append(crl.Extensions, zpkix.Extension{Id: util.AuthkeyOID, Value: []byte{0x30, 0x00, 0x00}})
			},
			want:       lint.Error,
			wantSubStr: "failed to parse authorityKeyIdentifier",
		},
		{
			name: "aki_key_identifier_malformed",
			parsedMod: func(t *testing.T, crl *zx509.RevocationList) {
				crl.Extensions = removeZExt(crl.Extensions, util.AuthkeyOID)
				// A keyIdentifier whose length runs past the end of the SEQUENCE.
				crl.Extensions = append(crl.Extensions, zpkix.Extension{Id: util.AuthkeyOID, Value: []byte{0x30, 0x02, 0x80, 0x05}})
			},
			want:       lint.Error,
			wantSubStr: "failed to parse authorityKeyIdentifier keyIdentifier",
		},
		{
			name: "missing_crl_number",
			parsedMod: func(t *testing.T, crl *zx509.RevocationList) {
				crl.Extensions = removeZExt(crl.Extensions, util.CRLNumberOID)
			},
			want:       lint.Error,
			wantSubStr: "CRLNumber extension is not present",
		},
		{
			name: "critical_crl_number",
			parsedMod: func(t *testing.T, crl *zx509.RevocationList) {
				criticalizeZExt(crl.Extensions, util.CRLNumberOID)
			},
			want:       lint.Error,
			wantSubStr: "CRLNumber extension is critical",
		},
		{
			name: "crl_number_zero",
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				tmpl.Number = big.NewInt(0)
			},
			want:       lint.Error,
			wantSubStr: "CRLNumber is not a positive integer",
		},
		{
			name: "crl_number_negative",
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				tmpl.Number = big.NewInt(-1)
			},
			want:       lint.Error,
			wantSubStr: "CRLNumber is not a positive integer",
		},
		{
			name: "good_crl_number_max",
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				tmpl.Number = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 159), big.NewInt(1))
			},
			want: lint.Pass,
		},
		{
			// crypto/x509 refuses to encode a CRLNumber this large.
			name: "crl_number_too_large",
			parsedMod: func(t *testing.T, crl *zx509.RevocationList) {
				crl.Number = new(big.Int).Lsh(big.NewInt(1), 159)
			},
			want:       lint.Error,
			wantSubStr: "CRLNumber is not less than 2^159",
		},
		{
			name: "idp_not_critical",
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				tmpl.ExtraExtensions = []pkix.Extension{testIDPExt(false, func(b *cryptobyte.Builder) {
					addIDPBoolean(b, 2, true)
				})}
			},
			want:       lint.Error,
			wantSubStr: "issuingDistributionPoint extension is not critical",
		},
		{
			name: "idp_trailing_data",
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				tmpl.ExtraExtensions[0].Value = append(tmpl.ExtraExtensions[0].Value, 0x00)
			},
			want:       lint.Error,
			wantSubStr: "failed to parse issuingDistributionPoint",
		},
		{
			name: "idp_with_distribution_point",
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				tmpl.ExtraExtensions = []pkix.Extension{testIDPExt(true, func(b *cryptobyte.Builder) {
					addIDPDistributionPoint(b, "http://x99.c.lencr.org/")
					addIDPBoolean(b, 2, true)
				})}
			},
			want:       lint.Error,
			wantSubStr: "issuingDistributionPoint distributionPoint is present",
		},
		{
			name: "idp_with_only_some_reasons",
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				tmpl.ExtraExtensions = []pkix.Extension{testIDPExt(true, func(b *cryptobyte.Builder) {
					addIDPBoolean(b, 2, true)
					addIDPOnlySomeReasons(b)
				})}
			},
			want:       lint.Error,
			wantSubStr: "issuingDistributionPoint contains fields other than onlyContainsCACerts",
		},
		{
			name: "idp_with_indirect_crl",
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				tmpl.ExtraExtensions = []pkix.Extension{testIDPExt(true, func(b *cryptobyte.Builder) {
					addIDPBoolean(b, 2, true)
					addIDPBoolean(b, 4, true)
				})}
			},
			want:       lint.Error,
			wantSubStr: "issuingDistributionPoint contains fields other than onlyContainsCACerts",
		},
		{
			// DER forbids encoding a field with its DEFAULT value, so an
			// explicit FALSE onlyContainsUserCerts is still a second field.
			name: "idp_with_explicit_false_user_certs",
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				tmpl.ExtraExtensions = []pkix.Extension{testIDPExt(true, func(b *cryptobyte.Builder) {
					addIDPBoolean(b, 1, false)
					addIDPBoolean(b, 2, true)
				})}
			},
			want:       lint.Error,
			wantSubStr: "issuingDistributionPoint onlyContainsUserCerts is present",
		},
		{
			name: "extra_extension",
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
					Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44947, 999}, Value: []byte{0x05, 0x00},
				})
			},
			want:       lint.Error,
			wantSubStr: "unexpected extension",
		},
		{
			name: "duplicate_extension",
			mod: func(t *testing.T, tmpl *x509.RevocationList) {
				// crypto/x509 always produces a CRLNumber extension, and appends
				// the ExtraExtensions after it.
				number, err := asn1.Marshal(tmpl.Number)
				if err != nil {
					t.Fatalf("marshalling CRLNumber: %s", err)
				}
				tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
					Id: asn1.ObjectIdentifier(util.CRLNumberOID), Value: number,
				})
			},
			want:       lint.Error,
			wantSubStr: "duplicate extension 2.5.29.20",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tmpl := testCACRLTemplate(t)
			if tc.mod != nil {
				tc.mod(t, tmpl)
			}

			der, err := x509.CreateRevocationList(rand.Reader, tmpl, root, rootKey)
			if err != nil {
				t.Fatalf("creating test CRL: %s", err)
			}
			crl := testParseZCRL(t, der)
			if tc.parsedMod != nil {
				tc.parsedMod(t, crl)
			}

			l := &caCRLMatchesCPSProfile{Config: &SharedConfig{IssuerCertificatePEM: testPEM(t, rootDER)}}
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

func TestCACRLMatchesCPSProfileCheckApplies(t *testing.T) {
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

	makeCRL := func(tmpl *x509.RevocationList) *zx509.RevocationList {
		der, err := x509.CreateRevocationList(rand.Reader, tmpl, root, rootKey)
		if err != nil {
			t.Fatalf("creating test CRL: %s", err)
		}
		return testParseZCRL(t, der)
	}

	l := &caCRLMatchesCPSProfile{}

	if !l.CheckApplies(makeCRL(testCACRLTemplate(t))) {
		t.Error("lint does not apply to CRL asserting onlyContainsCACerts")
	}

	if l.CheckApplies(makeCRL(testSubscriberCRLTemplate(t))) {
		t.Error("lint applies to CRL asserting onlyContainsUserCerts")
	}

	noIDP := testCACRLTemplate(t)
	noIDP.ExtraExtensions = nil
	if l.CheckApplies(makeCRL(noIDP)) {
		t.Error("lint applies to CRL with no issuingDistributionPoint")
	}

	malformedIDP := testCACRLTemplate(t)
	malformedIDP.ExtraExtensions = []pkix.Extension{testIDPExt(true, func(b *cryptobyte.Builder) {
		// onlyContainsCACerts, but with a BER (not DER) encoding of TRUE.
		b.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddUint8(0x01)
		})
	})}
	if l.CheckApplies(makeCRL(malformedIDP)) {
		t.Error("lint applies to CRL with a malformed issuingDistributionPoint")
	}
}
