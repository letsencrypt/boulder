package overriderequests

import (
	"strings"
	"testing"
)

func TestValidateOverrideRequestField(t *testing.T) {
	type testCase struct {
		name              string
		fieldName         string
		fieldValue        string
		ratelimitName     string
		expectErr         bool
		expectErrContains string
	}

	var cases []testCase
	// Empty Field
	cases = append(cases,
		testCase{"Empty field name", "", "x", "rl", true, "field name cannot be empty"},
		testCase{"Empty field value", "some", "", "rl", true, "cannot be empty"},
		testCase{"Tier without rate limit", TierFieldName, "10", "", true, "must be specified"},
		testCase{"Unknown field", "not-a-field", "x", "rl", true, "unknown field"},
	)
	// MailingListFieldName
	cases = append(cases,
		testCase{"MailingList true", MailingListFieldName, "true", "", false, ""},
		testCase{"MailingList false", MailingListFieldName, "false", "", false, ""},
		testCase{"MailingList yup", MailingListFieldName, "yup", "", true, "true or false"},
	)
	// SubscriberAgreement/PrivacyPolicy
	for _, fieldName := range []string{SubscriberAgreementFieldName, PrivacyPolicyFieldName} {
		cases = append(cases,
			testCase{fieldName + " true", fieldName, "true", "", false, ""},
			testCase{fieldName + " false", fieldName, "false", "", true, "required"},
			testCase{fieldName + " yep", fieldName, "yep", "", true, "true or false"},
		)
	}
	// FundraisingFieldName
	cases = append(cases,
		testCase{"Fundraising valid", FundraisingFieldName, FundraisingOptions[0], "", false, ""},
		testCase{"Fundraising invalid", FundraisingFieldName, "explicitly not an option", "", true, "Valid options are"},
	)
	// EmailAddressFieldName
	cases = append(cases,
		testCase{"EmailAddress valid email", EmailAddressFieldName, "foo@bar.co", "", false, ""},
		testCase{"EmailAddress invalid", EmailAddressFieldName, "foo@", "", true, "invalid"},
	)
	// OrganizationFieldName
	cases = append(cases,
		testCase{"Organization valid", OrganizationFieldName, "Big Host Inc", "", false, ""},
		testCase{"Organization too short", OrganizationFieldName, "Big", "", true, "at least five"},
	)
	// UseCaseFieldName
	cases = append(cases,
		testCase{"UseCase exactly long enough", UseCaseFieldName, strings.Repeat("x", 60), "", false, ""},
		testCase{"UseCase too short", UseCaseFieldName, strings.Repeat("x", 59), "", true, "at least 60"},
	)
	// IPAddressFieldName
	cases = append(cases,
		testCase{"IPAddress IPv4 valid", IPAddressFieldName, "64.112.11.11", "", false, ""},
		testCase{"IPAddress IPv4 invalid", IPAddressFieldName, "64.112.11.256", "", true, "invalid"},
		testCase{"IPAddress IPv6 valid", IPAddressFieldName, "2606:4700:4700::1111", "", false, ""},
		testCase{"IPAddress IPv6 invalid", IPAddressFieldName, "2606:4700:4700::1111:12345", "", true, "invalid"},
	)
	// RegisteredDomainFieldName
	cases = append(cases,
		testCase{"RegisteredDomain valid eTLD+1", RegisteredDomainFieldName, "example.com", "", false, ""},
		testCase{"RegisteredDomain bare TLD", RegisteredDomainFieldName, "com", "", true, "registered domain name is invalid"},
		testCase{"RegisteredDomain eTLD+2", RegisteredDomainFieldName, "foo.bar.example.com", "", true, "only the eTLD+1"},
		testCase{"RegisteredDomain invalid syntax", RegisteredDomainFieldName, "not even close to a domain", "", true, "invalid"},
	)
	// AccountURIFieldName
	cases = append(cases,
		testCase{"AccountURI valid", AccountURIFieldName, "https://acme-v02.api.letsencrypt.org/acme/acct/12345", "", false, ""},
		testCase{"AccountURI bad scheme", AccountURIFieldName, "http://acme-v02.api.letsencrypt.org/acme/acct/12345", "", true, "must start with"},
		testCase{"AccountURI bad host", AccountURIFieldName, "https://acme-staging-v02.api.letsencrypt.org/acme/acct/1", "", true, "must start with"},
		testCase{"AccountURI bad id", AccountURIFieldName, "https://acme-v02.api.letsencrypt.org/acme/acct/notnum", "", true, "positive integer"},
		testCase{"AccountURI bad path shape", AccountURIFieldName, "https://acme-v02.api.letsencrypt.org/acme/acct/1/extra", "", true, "path must be"},
	)
	// TierFieldName
	cases = append(cases,
		testCase{"Tier valid", TierFieldName, "1000", "NewOrdersPerAccount", false, ""},
		testCase{"Tier invalid option", TierFieldName, "999", "NewOrdersPerAccount", true, "Valid options are"},
		testCase{"Tier unknown rl", TierFieldName, "10", "DoesNotExist", true, "unknown rate limit"},
	)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateOverrideRequestField(tc.fieldName, tc.fieldValue, tc.ratelimitName)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.expectErrContains != "" && !strings.Contains(err.Error(), tc.expectErrContains) {
					t.Fatalf("Error %q does not contain %q", err.Error(), tc.expectErrContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error, got %s", err)
			}
		})
	}
}
