package dns

import (
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func Test_parseServiceDomain(t *testing.T) {
	tests := []struct {
		target        string
		expectService string
		expectDomain  string
		wantErr       bool
	}{
		// valid
		{"foo.bar", "foo", "bar", false},
		{"foo.bar.baz", "foo", "bar.baz", false},
		{"foo.bar.baz.", "foo", "bar.baz.", false},

		// invalid
		{"", "", "", true},
		{".", "", "", true},
		{"foo", "", "", true},
		{".foo", "", "", true},
		{"foo.", "", "", true},
		{".foo.bar.baz", "", "", true},
		{".foo.bar.baz.", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			gotService, gotDomain, err := parseServiceDomain(tt.target)
			if tt.wantErr {
				test.AssertError(t, err, "expect err got nil")
			} else {
				test.AssertNotError(t, err, "expect nil err")
				test.AssertEquals(t, gotService, tt.expectService)
				test.AssertEquals(t, gotDomain, tt.expectDomain)
			}
		})
	}
}
