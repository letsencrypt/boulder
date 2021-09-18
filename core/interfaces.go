package core

import (
	"context"
	"net/http"

	"github.com/letsencrypt/boulder/identifier"
)

// A WebFrontEnd object supplies methods that can be hooked into
// the Go http module's server functions, principally http.HandleFunc()
//
// It also provides methods to configure the base for authorization and
// certificate URLs.
//
// It is assumed that the ACME server is laid out as follows:
// * One URL for new-authorization -> NewAuthz
// * One URL for new-certificate -> NewCert
// * One path for authorizations -> Authz
// * One path for certificates -> Cert
type WebFrontEnd interface {
	// Set the base URL for authorizations
	SetAuthzBase(ctx context.Context, path string)

	// Set the base URL for certificates
	SetCertBase(ctx context.Context, path string)

	// This method represents the ACME new-registration resource
	NewRegistration(ctx context.Context, response http.ResponseWriter, request *http.Request)

	// This method represents the ACME new-authorization resource
	NewAuthz(ctx context.Context, response http.ResponseWriter, request *http.Request)

	// This method represents the ACME new-certificate resource
	NewCert(ctx context.Context, response http.ResponseWriter, request *http.Request)

	// Provide access to requests for registration resources
	Registration(ctx context.Context, response http.ResponseWriter, request *http.Request)

	// Provide access to requests for authorization resources
	Authz(ctx context.Context, response http.ResponseWriter, request *http.Request)

	// Provide access to requests for authorization resources
	Cert(ctx context.Context, response http.ResponseWriter, request *http.Request)
}

// PolicyAuthority defines the public interface for the Boulder PA
type PolicyAuthority interface {
	WillingToIssue(domain identifier.ACMEIdentifier) error
	WillingToIssueWildcards(identifiers []identifier.ACMEIdentifier) error
	ChallengesFor(domain identifier.ACMEIdentifier) ([]Challenge, error)
	ChallengeTypeEnabled(t AcmeChallenge) bool
}
