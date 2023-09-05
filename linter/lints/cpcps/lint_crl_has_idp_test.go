package cpcps

import (
	"fmt"
	"strings"
	"testing"

	"github.com/zmap/zlint/v3/lint"

	"github.com/letsencrypt/boulder/linter/lints/test"
)

func TestCrlHasIDP(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		want       lint.LintStatus
		wantSubStr string
	}{
		{
			name: "good",
			want: lint.Pass,
		},
		{
			name: "no_idp",
			want: lint.Warn,
		},
		{
			name:       "idp_no_uri",
			want:       lint.Warn,
			wantSubStr: "should contain distributionPoint",
		},
		{
			name:       "idp_two_uris",
			want:       lint.Warn,
			wantSubStr: "only one distributionPoint",
		},
		{
			name:       "idp_no_usercerts",
			want:       lint.Warn,
			wantSubStr: "should contain either onlyContainsUserCerts or onlyContainsCACerts",
		},
		{
			name:       "idp_some_reasons",
			want:       lint.Warn,
			wantSubStr: "Unexpected IDP fields were found",
		},
		{
			name:       "idp_onlyCA_and_onlyUser",
			want:       lint.Warn,
			wantSubStr: "IDP should contain either onlyContainsUserCerts or onlyContainsCACerts",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l := NewCrlHasIDP()
			c := test.LoadPEMCRL(t, fmt.Sprintf("testdata/crl_%s.pem", tc.name))
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
