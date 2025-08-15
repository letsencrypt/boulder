package overriderequests

import (
	"fmt"

	rl "github.com/letsencrypt/boulder/ratelimits"
	"github.com/letsencrypt/boulder/sfe/zendesk"
)

const (
	// Used for the request form Web UI and in the Zendesk tickets.
	OrganizationFieldName     = "organization"
	TierFieldName             = "tier"
	RateLimitFieldName        = "rateLimit"
	ReviewStatusFieldName     = "reviewStatus"
	FundraisingFieldName      = "fundraising"
	AccountURIFieldName       = "accountURI"
	RegisteredDomainFieldName = "registeredDomain"
	IPAddressFieldName        = "ipAddress"

	// Only used for the request form Web UI.
	PrivacyPolicyFieldName = "privacyPolicy"
	EmailAddressFieldName  = "emailAddress"
	UseCase                = "useCase"

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

func CreateNewOrdersPerAccountOverrideTicket(client *zendesk.Client, requesterEmail, useCase, fundraising, organization, tier, accountID string) (int64, error) {
	return client.CreateTicket(
		requesterEmail,
		makeSubject(rl.NewOrdersPerAccount, organization),
		makeInitialComment(organization, useCase, tier),
		map[string]string{
			RateLimitFieldName:    rl.NewOrdersPerAccount.String(),
			ReviewStatusFieldName: reviewStatusDefault,
			OrganizationFieldName: organization,
			FundraisingFieldName:  fundraising,
			TierFieldName:         tier,
			AccountURIFieldName:   accountID,
		},
	)
}

func CreateCertificatesPerDomainOverrideTicket(client *zendesk.Client, requesterEmail, useCase, fundraising, organization, tier, registeredDomain, ipAddress string) (int64, error) {
	return client.CreateTicket(
		requesterEmail,
		makeSubject(rl.NewOrdersPerAccount, organization),
		makeInitialComment(organization, useCase, tier),
		map[string]string{
			RateLimitFieldName:        rl.CertificatesPerDomain.String(),
			ReviewStatusFieldName:     reviewStatusDefault,
			OrganizationFieldName:     organization,
			FundraisingFieldName:      fundraising,
			TierFieldName:             tier,
			RegisteredDomainFieldName: registeredDomain,
			IPAddressFieldName:        ipAddress,
		},
	)
}

func CreateCertificatesPerDomainPerAccountOverrideTicket(client *zendesk.Client, requesterEmail, useCase, fundraising, organization, tier, accountID string) (int64, error) {
	return client.CreateTicket(
		requesterEmail,
		makeSubject(rl.NewOrdersPerAccount, organization),
		makeInitialComment(organization, useCase, tier),
		map[string]string{
			RateLimitFieldName:    rl.CertificatesPerDomainPerAccount.String(),
			ReviewStatusFieldName: reviewStatusDefault,
			OrganizationFieldName: organization,
			FundraisingFieldName:  fundraising,
			TierFieldName:         tier,
			AccountURIFieldName:   accountID,
		},
	)
}
