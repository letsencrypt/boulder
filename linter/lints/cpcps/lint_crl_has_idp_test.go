package cpcps

import (
	"fmt"
	"strings"
	"testing"

	linttest "github.com/letsencrypt/boulder/linter/lints/test"
	"github.com/zmap/zlint/v3/lint"
)

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
			wantSubStr: "CRL missing IssuingDistributionPoint",
		},

		{
			name:       "idp_no_uri",
			want:       lint.Error,
			wantSubStr: "IssuingDistributionPoint should have both DistributionPointName and onlyContainsUserCerts: TRUE",
		},
		{
			name:       "idp_two_uris",
			want:       lint.Warn,
			wantSubStr: "IssuingDistributionPoint should contain only one distributionPoint",
		},
		{
			name:       "idp_https",
			want:       lint.Error,
			wantSubStr: "IssuingDistributionPoint URI MUST use http scheme",
		},
		{
			name:       "idp_no_usercerts",
			want:       lint.Error,
			wantSubStr: "Neither onlyContainsUserCerts nor onlyContainsCACerts was set",
		},
		{
			name:       "idp_some_reasons", // Subscriber cert
			want:       lint.Error,
			wantSubStr: "Unexpected IssuingDistributionPoint fields were found",
		},
		{
			name:       "idp_distributionPoint_and_onlyCA",
			want:       lint.Error,
			wantSubStr: "IssuingDistributionPoint should not have both DistributionPointName and onlyContainsCACerts: TRUE",
		},
		{
			name:       "idp_distributionPoint_and_onlyUser_and_onlyCA",
			want:       lint.Error,
			wantSubStr: "IssuingDistributionPoint should not have both onlyContainsUserCerts: TRUE and onlyContainsCACerts: TRUE",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l := NewCrlHasIDP()
			c := linttest.LoadPEMCRL(t, fmt.Sprintf("testdata/crl_%s.pem", tc.name))
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
