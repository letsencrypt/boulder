package ratelimits

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
	// Not exposed via the API but used in Zendesk tickets.
	ReviewStatusFieldName = "reviewStatus"

	// Not selectable in the Web UI, but used in the API and in Zendesk tickets.
	RateLimitFieldName = "rateLimit"

	// Fields used in the Web UI and in Zendesk tickets.
	PrivacyPolicyFieldName    = "privacyPolicy"
	FundraisingFieldName      = "fundraising"
	EmailAddressFieldName     = "emailAddress"
	OrganizationFieldName     = "organization"
	UseCase                   = "useCase"
	TierFieldName             = "tier"
	AccountURIFieldName       = "accountID"
	RegisteredDomainFieldName = "registeredDomain"
	IPAddressFieldName        = "ipAddress"

	defaultReviewStatus = "pending"
	defaultComment      = "Review this override request and set the appropriate review status."
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
		"Yes, I'd like to receive an invoice.",
		"No, thank you.",
	}
)

// ValidateOverrideRequestField validates the provided field and value against
// the specified rate limit name. It returns true and an empty error message if
// the field is valid, or false and an error message if it is not.
func ValidateOverrideRequestField(field, value, rateLimit string) (bool, string) {
	if field == "" {
		return false, "field name cannot be empty"
	}
	if value == "" {
		return false, "this field is required"
	}
	if rateLimit == "" && field == TierFieldName {
		return false, "a rate limit name must be specified."
	}

	switch field {
	case PrivacyPolicyFieldName:
		agreed, err := strconv.ParseBool(value)
		if err != nil {
			// This should never happen.
			return false, "privacy policy must be true or false"
		}
		if !agreed {
			return false, "agreement with our privacy policy is required"
		}
		return true, ""
	case FundraisingFieldName:
		if !slices.Contains(FundraisingOptions, value) {
			return false, fmt.Sprintf("%s is not a valid fundraising option. Valid options are: %s",
				value, strings.Join(FundraisingOptions, ", "),
			)
		}
		return true, ""
	case EmailAddressFieldName:
		err := policy.ValidEmail(value)
		if err == nil {
			return true, ""
		}
		return false, "email address is invalid"

	case OrganizationFieldName:
		if len(value) >= 5 {
			return true, ""
		}
		return false, "organization or project must be at least five (5) characters long"

	case UseCase:
		if len(value) >= 60 {
			return true, ""
		}
		return false, "use case must be at least 60 characters long"

	case IPAddressFieldName:
		err := policy.ValidIP(value)
		if err == nil {
			return true, ""
		}
		return false, "IP address is invalid"

	case RegisteredDomainFieldName:
		err := policy.ValidDomain(value)
		if err != nil {
			return false, "registered domain name is invalid"
		}
		suffix, err := iana.ExtractSuffix(value)
		if err != nil {
			return false, "registered domain name is invalid"
		}
		if value == suffix {
			return false, "registered domain name cannot be a bare top-level domain"
		}
		base := strings.TrimSuffix(value, "."+suffix)
		if base == "" || strings.Contains(base, ".") {
			return false, "only the eTLD+1 (e.g., example.com) should be provided"
		}
		return true, ""

	case AccountURIFieldName:
		u, err := url.Parse(value)
		if err != nil {
			return false, "account URI is not a valid URL"
		}
		if u.Scheme != "https" || u.Host != "acme-v02.api.letsencrypt.org" || !strings.HasPrefix(u.Path, "/acme/acct/") {
			return false, "account URI must start with https://acme-v02.api.letsencrypt.org/acme/acct/"
		}
		segments := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(segments) != 3 || segments[0] != "acme" || segments[1] != "acct" {
			return false, "account URI path must be of the form /acme/acct/{id}"
		}
		_, err = strconv.ParseUint(segments[2], 10, 64)
		if err != nil {
			return false, "account ID must be a positive integer"
		}
		return true, ""

	case TierFieldName:
		makeinvalidTierMessage := func(tier string, valid []string) string {
			return fmt.Sprintf("%s is not a valid quantity for this rate limit. Valid options are: %s.", tier, strings.Join(valid, ", "))
		}

		switch rateLimit {
		case rl.NewOrdersPerAccount.String():
			if slices.Contains(NewOrdersPerAccountTiers, value) {
				return true, ""
			}
			return false, makeinvalidTierMessage(value, NewOrdersPerAccountTiers)

		case rl.CertificatesPerDomain.String():
			if slices.Contains(CertificatesPerDomainTiers, value) {
				return true, ""
			}
			return false, makeinvalidTierMessage(value, CertificatesPerDomainTiers)

		case rl.CertificatesPerDomainPerAccount.String():
			if slices.Contains(CertificatesPerDomainPerAccountTiers, value) {
				return true, ""
			}
			return false, makeinvalidTierMessage(value, CertificatesPerDomainPerAccountTiers)

		default:
			return false, fmt.Sprintf("unknown rate limit name: %s", rateLimit)
		}
	}
	return false, fmt.Sprintf("unknown field %q", field)
}

func NewOrdersPerAccountOverrideRequestToTicket(requesterEmail, ratelimit, reviewStatus, organization, tier, accountID string) zendesk.Ticket {
	return zendesk.Ticket{
		Requester: zendesk.Requester{Email: requesterEmail, Name: requesterEmail},
		Subject:   fmt.Sprintf("NewOrdersPerAccount rate limit override request for %s", organization),
		Comment:   zendesk.Comment{Body: defaultComment, Public: true},
		TicketFields: []zendesk.TicketField{
			{CustomField: zendesk.CustomField{Name: RateLimitFieldName}, Value: ratelimit},
			{CustomField: zendesk.CustomField{Name: ReviewStatusFieldName}, Value: defaultReviewStatus},
			{CustomField: zendesk.CustomField{Name: OrganizationFieldName}, Value: organization},
			{CustomField: zendesk.CustomField{Name: TierFieldName}, Value: tier},
			{CustomField: zendesk.CustomField{Name: AccountURIFieldName}, Value: accountID},
		},
	}
}

func CertificatesPerDomainOverrideRequestToTicket(requesterEmail, ratelimit, reviewStatus, organization, tier, registeredDomain string) zendesk.Ticket {
	return zendesk.Ticket{
		Requester: zendesk.Requester{Email: requesterEmail, Name: requesterEmail},
		Subject:   fmt.Sprintf("CertificatesPerDomain rate limit override request for %s", organization),
		Comment:   zendesk.Comment{Body: defaultComment, Public: true},
		TicketFields: []zendesk.TicketField{
			{CustomField: zendesk.CustomField{Name: RateLimitFieldName}, Value: ratelimit},
			{CustomField: zendesk.CustomField{Name: ReviewStatusFieldName}, Value: defaultReviewStatus},
			{CustomField: zendesk.CustomField{Name: OrganizationFieldName}, Value: organization},
			{CustomField: zendesk.CustomField{Name: TierFieldName}, Value: tier},
			{CustomField: zendesk.CustomField{Name: RegisteredDomainFieldName}, Value: registeredDomain},
		},
	}
}

func CertificatesPerIPOverrideRequestToTicket(requesterEmail, ratelimit, reviewStatus, organization, tier, ipAddress string) zendesk.Ticket {
	return zendesk.Ticket{
		Requester: zendesk.Requester{Email: requesterEmail, Name: requesterEmail},
		Subject:   fmt.Sprintf("CertificatesPerDomain rate limit override request for %s", organization),
		Comment:   zendesk.Comment{Body: defaultComment, Public: true},
		TicketFields: []zendesk.TicketField{
			{CustomField: zendesk.CustomField{Name: RateLimitFieldName}, Value: ratelimit},
			{CustomField: zendesk.CustomField{Name: ReviewStatusFieldName}, Value: defaultReviewStatus},
			{CustomField: zendesk.CustomField{Name: OrganizationFieldName}, Value: organization},
			{CustomField: zendesk.CustomField{Name: TierFieldName}, Value: tier},
			{CustomField: zendesk.CustomField{Name: IPAddressFieldName}, Value: ipAddress},
		},
	}
}

func CertificatesPerDomainPerAccountOverrideRequestToTicket(requesterEmail, ratelimit, reviewStatus, organization, tier, accountID string) zendesk.Ticket {
	return zendesk.Ticket{
		Requester: zendesk.Requester{Email: requesterEmail, Name: requesterEmail},
		Subject:   fmt.Sprintf("CertificatesPerDomainPerAccount rate limit override request for %s", organization),
		Comment:   zendesk.Comment{Body: defaultComment, Public: true},
		TicketFields: []zendesk.TicketField{
			{CustomField: zendesk.CustomField{Name: RateLimitFieldName}, Value: ratelimit},
			{CustomField: zendesk.CustomField{Name: ReviewStatusFieldName}, Value: defaultReviewStatus},
			{CustomField: zendesk.CustomField{Name: OrganizationFieldName}, Value: organization},
			{CustomField: zendesk.CustomField{Name: TierFieldName}, Value: tier},
			{CustomField: zendesk.CustomField{Name: AccountURIFieldName}, Value: accountID},
		},
	}
}
