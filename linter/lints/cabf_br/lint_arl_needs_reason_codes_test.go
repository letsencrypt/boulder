package cabfbr

import (
	"fmt"
	"strings"
	"testing"

	"github.com/zmap/zlint/v3/lint"

	"github.com/letsencrypt/boulder/linter/lints/test"
)

func TestArlNeedsReasonCodes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		want       lint.LintStatus
		wantSubStr string
	}{
		{
			name: "good", // CRL for subscriber certs
			want: lint.NA,
		},
		{
			name: "good_subordinate_ca",
			want: lint.Pass,
		},
		{
			name:       "subordinate_ca_no_reason",
			want:       lint.Error,
			wantSubStr: "MUST include a reasonCode extension",
		},
		{
			name:       "subordinate_ca_some_reasons", // First entry has a reasonCode, second doesn't
			want:       lint.Error,
			wantSubStr: "MUST include a reasonCode extension",
		},
		{
			name:       "no_idp_no_reason",
			want:       lint.Error,
			wantSubStr: "MUST include a reasonCode extension",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l := NewArlNeedsReasonCodes()
			c := test.LoadPEMCRL(t, fmt.Sprintf("testdata/crl_%s.pem", tc.name))

			if !l.CheckApplies(c) {
				if tc.want != lint.NA {
					t.Errorf("expected lint to apply, but it did not")
				}
				return
			}
			if tc.want == lint.NA {
				t.Fatalf("expected lint not to apply, but it did")
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
