// +build integration

package integration

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/eggsampler/acme/v3"

	"github.com/letsencrypt/boulder/test"
)

// TestTooBigOrderError tests that submitting an order with more than 100 names
// produces the expected problem result.
func TestTooBigOrderError(t *testing.T) {
	t.Parallel()
	os.Setenv("DIRECTORY", "http://boulder:4001/directory")

	var domains []string
	for i := 0; i < 101; i++ {
		domains = append(domains, fmt.Sprintf("%d.example.com", i))
	}

	_, err := authAndIssue(nil, nil, domains)
	test.AssertError(t, err, "authAndIssue failed")

	if prob, ok := err.(acme.Problem); !ok {
		t.Fatalf("expected problem result, got %#v\n", err)
	} else {
		test.AssertEquals(t, prob.Type, "urn:ietf:params:acme:error:malformed")
		test.AssertEquals(t, prob.Detail, "Error creating new order :: Order cannot contain more than 100 DNS names")
	}
}

// TestAccountEmailError tests that registering a new account, or updating an
// account, with invalid contact information produces the expected problem
// result to ACME clients.
func TestAccountEmailError(t *testing.T) {
	t.Parallel()
	os.Setenv("DIRECTORY", "http://boulder:4001/directory")

	/*
		  // TODO(@cpu): Uncomment this when the too-long test case is re-added.
			var longStringBuf strings.Builder
			for i := 0; i < 254; i++ {
				longStringBuf.WriteRune('a')
			}
	*/

	createErrorPrefix := "Error creating new account :: "
	updateErrorPrefix := "Unable to update account :: "

	testCases := []struct {
		name               string
		contacts           []string
		expectedProbType   string
		expectedProbDetail string
	}{
		{
			name:               "empty contact",
			contacts:           []string{"mailto:valid@valid.com", ""},
			expectedProbType:   "urn:ietf:params:acme:error:invalidEmail",
			expectedProbDetail: `empty contact`,
		},
		{
			name:               "empty proto",
			contacts:           []string{"mailto:valid@valid.com", " "},
			expectedProbType:   "urn:ietf:params:acme:error:invalidEmail",
			expectedProbDetail: `contact method "" is not supported`,
		},
		{
			name:               "empty mailto",
			contacts:           []string{"mailto:valid@valid.com", "mailto:"},
			expectedProbType:   "urn:ietf:params:acme:error:invalidEmail",
			expectedProbDetail: `"" is not a valid e-mail address`,
		},
		{
			name:               "non-ascii mailto",
			contacts:           []string{"mailto:valid@valid.com", "mailto:cpu@l̴etsencrypt.org"},
			expectedProbType:   "urn:ietf:params:acme:error:invalidEmail",
			expectedProbDetail: `contact email ["mailto:cpu@l̴etsencrypt.org"] contains non-ASCII characters`,
		},
		{
			name:               "too many contacts",
			contacts:           []string{"a", "b", "c", "d"},
			expectedProbType:   "urn:ietf:params:acme:error:malformed",
			expectedProbDetail: `too many contacts provided: 4 > 3`,
		},
		{
			name:               "invalid contact",
			contacts:           []string{"mailto:valid@valid.com", "mailto:a@"},
			expectedProbType:   "urn:ietf:params:acme:error:invalidEmail",
			expectedProbDetail: `"a@" is not a valid e-mail address`,
		},
		{
			name:               "forbidden contact domain",
			contacts:           []string{"mailto:valid@valid.com", "mailto:a@example.com"},
			expectedProbType:   "urn:ietf:params:acme:error:invalidEmail",
			expectedProbDetail: "invalid contact domain. Contact emails @example.com are forbidden",
		},
		{
			name:               "contact domain invalid TLD",
			contacts:           []string{"mailto:valid@valid.com", "mailto:a@example.cpu"},
			expectedProbType:   "urn:ietf:params:acme:error:invalidEmail",
			expectedProbDetail: `contact email "a@example.cpu" has invalid domain : Domain name does not end with a valid public suffix (TLD)`,
		},
		{
			name:               "contact domain invalid",
			contacts:           []string{"mailto:valid@valid.com", "mailto:a@example./.com"},
			expectedProbType:   "urn:ietf:params:acme:error:invalidEmail",
			expectedProbDetail: "contact email \"a@example./.com\" has invalid domain : Domain name contains an invalid character",
		},
		/*
			// NOTE(@cpu): Disabled for now - causes serverInternal err when SA saves
			// contacts.
			{
				name: "too long contact",
				contacts: []string{
					fmt.Sprintf("mailto:%s@a.com", longStringBuf.String()),
				},
				expectedProbType:   "urn:ietf:params:acme:error:invalidEmail",
				expectedProbDetail: "??????",
			},
		*/
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// First try registering a new account and ensuring the expected problem occurs
			if _, err := makeClient(tc.contacts...); err != nil {
				if prob, ok := err.(acme.Problem); !ok {
					t.Fatalf("expected acme.Problem error got %#v", err)
				} else {
					test.AssertEquals(t, prob.Type, tc.expectedProbType)
					test.AssertEquals(t, prob.Detail, createErrorPrefix+tc.expectedProbDetail)
				}
			} else if err == nil {
				t.Errorf("expected %s type problem for %q, got nil",
					tc.expectedProbType, strings.Join(tc.contacts, ","))
			}

			// Next try making a client with a good contact and updating with the test
			// case contact info. The same problem should occur.
			c, err := makeClient("mailto:valid@valid.com")
			test.AssertNotError(t, err, "failed to create account with valid contact")
			if _, err := c.UpdateAccount(c.Account, tc.contacts...); err != nil {
				if prob, ok := err.(acme.Problem); !ok {
					t.Fatalf("expected acme.Problem error after updating account got %#v", err)
				} else {
					test.AssertEquals(t, prob.Type, tc.expectedProbType)
					test.AssertEquals(t, prob.Detail, updateErrorPrefix+tc.expectedProbDetail)
				}
			} else if err == nil {
				t.Errorf("expected %s type problem after updating account to %q, got nil",
					tc.expectedProbType, strings.Join(tc.contacts, ","))
			}
		})
	}
}
