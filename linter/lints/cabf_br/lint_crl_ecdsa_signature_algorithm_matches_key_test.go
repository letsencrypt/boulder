package cabfbr

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/zmap/zlint/v3/lint"

	"github.com/letsencrypt/boulder/linter/lints/test"
)

func TestCrlECDSASignatureAlgorithmMatchesKey(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		wantApplies bool
		want        lint.LintStatus
		wantSubStr  string
	}{
		{
			name:        "good",
			wantApplies: true,
			want:        lint.Pass,
		},
		{
			name:        "ecdsa_p256_sha256",
			wantApplies: true,
			want:        lint.Pass,
		},
		{
			name:        "ecdsa_p384_sha384",
			wantApplies: true,
			want:        lint.Pass,
		},
		{
			name:        "ecdsa_p521_sha512",
			wantApplies: true,
			want:        lint.Pass,
		},
		{
			name:        "ecdsa_p384_sha256",
			wantApplies: true,
			want:        lint.Error,
			wantSubStr:  "CRL signature field is 300a06082a8648ce3d040302, but signing key on P-384 requires 300a06082a8648ce3d040303",
		},
		{
			name:        "ecdsa_p256_sha384",
			wantApplies: true,
			want:        lint.Error,
			wantSubStr:  "CRL signature field is 300a06082a8648ce3d040303, but signing key on P-256 requires 300a06082a8648ce3d040302",
		},
		{
			name:        "rsa_sha256",
			wantApplies: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l := NewCrlECDSASignatureAlgorithmMatchesKey()
			c := test.LoadPEMCRL(t, fmt.Sprintf("testdata/crl_%s.pem", tc.name))

			applies := l.CheckApplies(c)
			if applies != tc.wantApplies {
				t.Fatalf("expected CheckApplies %t, got %t", tc.wantApplies, applies)
			}
			if !applies {
				return
			}

			r := l.Execute(c)
			if r.Status != tc.want {
				t.Errorf("expected %q, got %q", tc.want, r.Status)
			}
			if !strings.Contains(r.Details, tc.wantSubStr) {
				t.Errorf("expected %q, got %q", tc.wantSubStr, r.Details)
			}
		})
	}
}

func TestEcdsaSignatureBitLen(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		sig     string
		want    int
		wantErr bool
	}{
		{name: "small", sig: "3006020101020102", want: 2},
		// r is 0x00ff (positive, with a leading zero), s is 1.
		{name: "leading zero", sig: "3007020200ff020101", want: 8},
		{name: "trailing data", sig: "300602010102010200", wantErr: true},
		{name: "not a sequence", sig: "020101020101", wantErr: true},
		{name: "empty", sig: "", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig := mustHex(t, tc.sig)
			got, err := ecdsaSignatureBitLen(sig)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got bit length %d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if got != tc.want {
				t.Errorf("expected %d, got %d", tc.want, got)
			}
		})
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("decoding hex: %s", err)
	}
	return b
}
