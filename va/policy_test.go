package va

import (
	"testing"

	"github.com/letsencrypt/boulder/test"
)

// TestLoadPolicy tests that the MultiVAPolicy load works as expected.
func TestLoadPolicy(t *testing.T) {
	testCases := []struct {
		name             string
		yamlBytes        []byte
		expectedErr      error
		expectedDomains  []string
		expectedAccounts []int64
	}{
		{
			name:        "nil yaml bytes",
			yamlBytes:   nil,
			expectedErr: errEmptyMultiVAPolicy,
		},
		{
			name:        "empty yaml bytes",
			yamlBytes:   []byte{},
			expectedErr: errEmptyMultiVAPolicy,
		},
		{
			name: "empty policy",
			yamlBytes: []byte(`
# No domains
disabledDomains:
# No accounts
disabledAccounts:
`),
			expectedErr: errEmptyMultiVAPolicy,
		},
		{
			name: "valid policy",
			yamlBytes: []byte(`
# Some example disabled domains
disabledDomains:
  - example.com
  - lettucedecrypt.org

# An example disabled account ID
disabledAccounts:
  - 123456
`),
			expectedDomains:  []string{"example.com", "lettucedecrypt.org"},
			expectedAccounts: []int64{123456},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var policy MultiVAPolicy
			err := policy.LoadPolicy(tc.yamlBytes)
			if err != nil && tc.expectedErr != nil {
				test.AssertEquals(t, err, tc.expectedErr)
			} else if err != nil && tc.expectedErr == nil {
				t.Fatalf("unexpected error: %v\n", err)
			} else if err == nil {
				for _, d := range tc.expectedDomains {
					test.AssertEquals(t, policy.EnabledDomain(d), false)
				}
				for _, acctID := range tc.expectedAccounts {
					test.AssertEquals(t, policy.EnabledAccount(acctID), false)
				}
			}
		})
	}
}
