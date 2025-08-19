package overriderequests

import (
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/letsencrypt/boulder/iana"
	"github.com/letsencrypt/boulder/policy"
	rl "github.com/letsencrypt/boulder/ratelimits"
	"github.com/letsencrypt/boulder/sfe/zendesk"
)

const (
	APIVersion = "v1"
	APIPrefix  = "/sfe/" + APIVersion

	// Meta fields (not user-entered)
	ReviewStatusFieldName = "reviewStatus"
	RateLimitFieldName    = "rateLimit"

	// Shared user-entered fields (UI + API/Zendesk)
	OrganizationFieldName     = "organization"
	TierFieldName             = "tier"
	AccountURIFieldName       = "accountURI"
	RegisteredDomainFieldName = "registeredDomain"
	IPAddressFieldName        = "ipAddress"

	// UI-only fields
	SubscriberAgreementFieldName = "subscriberAgreement"
	PrivacyPolicyFieldName       = "privacyPolicy"
	EmailAddressFieldName        = "emailAddress"
	UseCaseFieldName             = "useCase"
	FundraisingFieldName         = "fundraising"
	MailingListFieldName         = "mailingList"

	// reviewStatusDefault is the initial status of a ticket when created.
	reviewStatusDefault = "review-status-pending"
)

var (
	// NewOrdersPerAccountTiers is the list of valid tiers for the
	// NewOrdersPerAccount rate limit override requests.
	NewOrdersPerAccountTiers = []string{"1000", "5000", "10000", "25000", "50000", "75000", "100000", "175000", "250000", "500000", "750000", "1000000"}

	// CertificatesPerDomainTiers is the list of valid tiers for the
	// CertificatesPerDomain rate limit.
	CertificatesPerDomainTiers = []string{"300", "1000", "5000", "10000", "25000", "50000", "75000", "100000", "175000", "250000", "500000", "1000000"}

	// CertificatesPerDomainPerAccountTiers is the list of valid tiers for the
	// CertificatesPerDomainPerAccount rate limit override requests.
	CertificatesPerDomainPerAccountTiers = []string{"300", "1000", "5000", "10000", "25000", "50000", "75000", "100000", "175000", "250000", "500000", "1000000", "1750000", "2500000"}

	// FundraisingOptions is the list of options for the fundraising field.
	FundraisingOptions = []string{
		"Yes, email me more information.",
		"No, not at this time.",
	}

	// tiersByRateLimit maps rate limit names to their valid tiers.
	tiersByRateLimit = map[string][]string{
		rl.NewOrdersPerAccount.String():             NewOrdersPerAccountTiers,
		rl.CertificatesPerDomain.String():           CertificatesPerDomainTiers,
		rl.CertificatesPerDomainPerAccount.String(): CertificatesPerDomainPerAccountTiers,
	}
)

func makeSubject(rateLimit rl.Name, organization string) string {
	return fmt.Sprintf("%s rate limit override request for %s", rateLimit.String(), organization)
}

func makeInitialComment(organization, useCase, tier string) string {
	return fmt.Sprintf(
		"Use case: %s\n\nRequested Override Tier: %s\n\nOrganization: %s",
		useCase, tier, organization,
	)
}

// CreateNewOrdersPerAccountOverrideTicket creates a new Zendesk ticket for a
// NewOrdersPerAccount override request. All fields are required.
func CreateNewOrdersPerAccountOverrideTicket(client *zendesk.Client, requesterEmail, useCase, organization, tier, accountID string) (int64, error) {
	return client.CreateTicket(
		requesterEmail,
		makeSubject(rl.NewOrdersPerAccount, organization),
		makeInitialComment(organization, useCase, tier),
		map[string]string{
			RateLimitFieldName:    rl.NewOrdersPerAccount.String(),
			ReviewStatusFieldName: reviewStatusDefault,
			OrganizationFieldName: organization,
			TierFieldName:         tier,
			AccountURIFieldName:   accountID,
		},
	)
}

// CreateCertificatesPerDomainOverrideTicket creates a new Zendesk ticket for a
// CertificatesPerDomain override request. Only registeredDomain or ipAddress
// should be provided, not both. All other fields are required.
func CreateCertificatesPerDomainOverrideTicket(client *zendesk.Client, requesterEmail, useCase, organization, tier, registeredDomain, ipAddress string) (int64, error) {
	return client.CreateTicket(
		requesterEmail,
		makeSubject(rl.CertificatesPerDomain, organization),
		makeInitialComment(organization, useCase, tier),
		map[string]string{
			RateLimitFieldName:        rl.CertificatesPerDomain.String(),
			ReviewStatusFieldName:     reviewStatusDefault,
			OrganizationFieldName:     organization,
			TierFieldName:             tier,
			RegisteredDomainFieldName: registeredDomain,
			IPAddressFieldName:        ipAddress,
		},
	)
}

// CreateCertificatesPerDomainPerAccountOverrideTicket creates a new Zendesk
// ticket for a CertificatesPerDomainPerAccount override request. All fields are
// required.
func CreateCertificatesPerDomainPerAccountOverrideTicket(client *zendesk.Client, requesterEmail, useCase, organization, tier, accountID string) (int64, error) {
	return client.CreateTicket(
		requesterEmail,
		makeSubject(rl.CertificatesPerDomainPerAccount, organization),
		makeInitialComment(organization, useCase, tier),
		map[string]string{
			RateLimitFieldName:    rl.CertificatesPerDomainPerAccount.String(),
			ReviewStatusFieldName: reviewStatusDefault,
			OrganizationFieldName: organization,
			TierFieldName:         tier,
			AccountURIFieldName:   accountID,
		},
	)
}

// ValidateOverrideRequestField validates the provided field and value against
// the specified rate limit name. It returns nil if the field is valid, or an error if it is not.
func ValidateOverrideRequestField(fieldName, fieldValue, rateLimit string) error {
	if fieldName == "" {
		return fmt.Errorf("field name cannot be empty")
	}
	if fieldValue == "" {
		return fmt.Errorf("%q cannot be empty", fieldName)
	}
	if rateLimit == "" && fieldName == TierFieldName {
		return fmt.Errorf("a rate limit name must be specified")
	}

	switch fieldName {
	case MailingListFieldName:
		// This field is optional, so we only validate it is a boolean.
		if fieldValue != "true" && fieldValue != "false" {
			return fmt.Errorf("mailing list field must be true or false")
		}
		return nil
	case SubscriberAgreementFieldName, PrivacyPolicyFieldName:
		agreed, err := strconv.ParseBool(fieldValue)
		if err != nil {
			return fmt.Errorf("subscriber agreement and privacy policy must be true or false")
		}
		if !agreed {
			return fmt.Errorf("agreement with our subscriber agreement and privacy policy is required")
		}
		return nil
	case FundraisingFieldName:
		if !slices.Contains(FundraisingOptions, fieldValue) {
			return fmt.Errorf("%s is not a valid fundraising option. Valid options are: %s",
				fieldValue, strings.Join(FundraisingOptions, ", "),
			)
		}
		return nil
	case EmailAddressFieldName:
		err := policy.ValidEmail(fieldValue)
		if err == nil {
			return nil
		}
		return fmt.Errorf("email address is invalid")

	case OrganizationFieldName:
		if len(fieldValue) >= 5 {
			return nil
		}
		return fmt.Errorf("organization or project must be at least five (5) characters long")

	case UseCaseFieldName:
		if len(fieldValue) >= 60 {
			return nil
		}
		return fmt.Errorf("use case must be at least 60 characters long")

	case IPAddressFieldName:
		err := policy.ValidIP(fieldValue)
		if err == nil {
			return nil
		}
		return fmt.Errorf("IP address is invalid")

	case RegisteredDomainFieldName:
		err := policy.ValidDomain(fieldValue)
		if err != nil {
			return fmt.Errorf("registered domain name is invalid")
		}
		suffix, err := iana.ExtractSuffix(fieldValue)
		if err != nil {
			return fmt.Errorf("registered domain name is invalid")
		}
		if fieldValue == suffix {
			return fmt.Errorf("registered domain name cannot be a bare top-level domain")
		}
		base := strings.TrimSuffix(fieldValue, "."+suffix)
		if base == "" || strings.Contains(base, ".") {
			return fmt.Errorf("only the eTLD+1 (e.g., example.com) should be provided")
		}
		return nil

	case AccountURIFieldName:
		u, err := url.Parse(fieldValue)
		if err != nil {
			return fmt.Errorf("account URI is not a valid URL")
		}
		if u.Scheme != "https" || u.Host != "acme-v02.api.letsencrypt.org" || !strings.HasPrefix(u.Path, "/acme/acct/") {
			return fmt.Errorf("account URI must start with https://acme-v02.api.letsencrypt.org/acme/acct/")
		}
		segments := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(segments) != 3 || segments[0] != "acme" || segments[1] != "acct" {
			return fmt.Errorf("account URI path must be of the form /acme/acct/{id}")
		}
		_, err = strconv.ParseUint(segments[2], 10, 64)
		if err != nil {
			return fmt.Errorf("account ID must be a positive integer")
		}
		return nil

	case TierFieldName:
		valids, ok := tiersByRateLimit[rateLimit]
		if !ok {
			return fmt.Errorf("unknown rate limit name: %s", rateLimit)
		}
		if slices.Contains(valids, fieldValue) {
			return nil
		}
		return fmt.Errorf("%s is not a valid quantity for this rate limit. Valid options are: %s", fieldValue, strings.Join(valids, ", "))
	}
	return fmt.Errorf("unknown field %q", fieldName)
}
