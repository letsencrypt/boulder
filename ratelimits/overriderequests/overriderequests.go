package overriderequests

import (
	"fmt"

	rl "github.com/letsencrypt/boulder/ratelimits"
	"github.com/letsencrypt/boulder/sfe/zendesk"
)

const (
	// Meta fields (not user-entered)
	ReviewStatusFieldName = "reviewStatus"
	RateLimitFieldName    = "rateLimit"

	// Shared user-entered fields (UI + API/Zendesk)
	OrganizationFieldName     = "organization"
	TierFieldName             = "tier"
	AccountURIFieldName       = "accountURI"
	RegisteredDomainFieldName = "registeredDomain"
	IPAddressFieldName        = "ipAddress"

	// reviewStatusDefault is the initial status of a ticket when created.
	reviewStatusDefault = "review-status-pending"
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
