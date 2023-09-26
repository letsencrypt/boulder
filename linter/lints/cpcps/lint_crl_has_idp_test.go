package cpcps

import (
	"fmt"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/linter/lints"

	lintTest "github.com/letsencrypt/boulder/linter/lints/test"
	"github.com/letsencrypt/boulder/test"
	"github.com/zmap/zlint/v3/lint"
)

func TestReadASN1BooleanWithTag(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		tagBytes []byte
		expected bool
	}{
		{
			name:     "Value true",
			tagBytes: []byte{0xFF},
			expected: true,
		},
		{
			name:     "Value false",
			tagBytes: []byte{0x00},
			expected: false,
		},
		{
			name:     "Too many bytes, true",
			tagBytes: []byte{0xFF, 0xFF},
			expected: false,
		},
		{
			name:     "Too many bytes, false",
			tagBytes: []byte{0x00, 0x00},
			expected: false,
		},
		{
			name:     "Too many bytes, mixed",
			tagBytes: []byte{0xFF, 0x00},
			expected: false,
		},
		{
			name:     "Too many bytes, not following X.690 section 8.2 rules",
			tagBytes: []byte{0xC0, 0xFF, 0xEE, 0xCA, 0xFE},
			expected: false,
		},
		{
			name:     "No bytes",
			tagBytes: []byte{},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ok := lints.ReadASN1BooleanWithTag(tc.tagBytes)
			test.AssertEquals(t, ok, tc.expected)
		})
	}
}

func TestCrlHasIDP(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		want       lint.LintStatus
		wantSubStr string
	}{
		{
			name: "good", // CRL for subscriber certs
			want: lint.Pass,
		},
		{
			name: "good_subordinate_ca",
			want: lint.Pass,
		},
		{
			name:       "no_idp",
			want:       lint.Warn,
			wantSubStr: "CRL missing IDP",
		},
		{
			name:       "idp_no_uri",
			want:       lint.Warn,
			wantSubStr: "Failed to read IDP distributionPoint",
		},
		{
			name:       "idp_two_uris",
			want:       lint.Warn,
			wantSubStr: "only one distributionPoint",
		},
		{
			name:       "idp_no_usercerts",
			want:       lint.Error,
			wantSubStr: "Failed to read IDP onlyContainsUserCerts",
		},
		{
			name:       "idp_some_reasons", // Subscriber cert
			want:       lint.Error,
			wantSubStr: "Unexpected IDP fields were found",
		},
		{
			name:       "idp_onlyCA_and_onlyUser",
			want:       lint.Error,
			wantSubStr: "Unexpected IDP fields were found",
		},
		{
			name:       "idp_distributionPoint_and_onlyCA",
			want:       lint.Error,
			wantSubStr: "Failed to read IDP onlyContainsUserCerts",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l := NewCrlHasIDP()
			c := lintTest.LoadPEMCRL(t, fmt.Sprintf("testdata/crl_%s.pem", tc.name))
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
