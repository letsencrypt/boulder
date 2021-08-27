package core

import (
	"context"
	"net/http"

	"google.golang.org/protobuf/types/known/emptypb"

	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/identifier"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
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

// RegistrationAuthority defines the public interface for the Boulder RA
type RegistrationAuthority interface {
	// [WebFrontEnd]
	NewRegistration(ctx context.Context, reg *corepb.Registration) (*corepb.Registration, error)

	// [WebFrontEnd]
	NewAuthorization(ctx context.Context, req *rapb.NewAuthorizationRequest) (*corepb.Authorization, error)

	// [WebFrontEnd]
	NewCertificate(ctx context.Context, req *rapb.NewCertificateRequest) (*corepb.Certificate, error)

	// [WebFrontEnd]
	UpdateRegistration(ctx context.Context, req *rapb.UpdateRegistrationRequest) (*corepb.Registration, error)

	// [WebFrontEnd]
	PerformValidation(ctx context.Context, req *rapb.PerformValidationRequest) (*corepb.Authorization, error)

	// [WebFrontEnd]
	RevokeCertificateWithReg(ctx context.Context, req *rapb.RevokeCertificateWithRegRequest) (*emptypb.Empty, error)

	// [WebFrontEnd]
	DeactivateRegistration(ctx context.Context, reg *corepb.Registration) (*emptypb.Empty, error)

	// [WebFrontEnd]
	DeactivateAuthorization(ctx context.Context, auth *corepb.Authorization) (*emptypb.Empty, error)

	// [WebFrontEnd]
	NewOrder(ctx context.Context, req *rapb.NewOrderRequest) (*corepb.Order, error)

	// [WebFrontEnd]
	FinalizeOrder(ctx context.Context, req *rapb.FinalizeOrderRequest) (*corepb.Order, error)

	// [AdminRevoker]
	AdministrativelyRevokeCertificate(ctx context.Context, req *rapb.AdministrativelyRevokeCertificateRequest) (*emptypb.Empty, error)
}

// PolicyAuthority defines the public interface for the Boulder PA
type PolicyAuthority interface {
	WillingToIssue(domain identifier.ACMEIdentifier) error
	WillingToIssueWildcards(identifiers []identifier.ACMEIdentifier) error
	ChallengesFor(domain identifier.ACMEIdentifier) ([]Challenge, error)
	ChallengeTypeEnabled(t AcmeChallenge) bool
}

// StorageGetter are the Boulder SA's read-only methods
type StorageGetter interface {
	GetRegistration(ctx context.Context, req *sapb.RegistrationID) (*corepb.Registration, error)
	GetRegistrationByKey(ctx context.Context, req *sapb.JSONWebKey) (*corepb.Registration, error)
	GetCertificate(ctx context.Context, req *sapb.Serial) (*corepb.Certificate, error)
	GetPrecertificate(ctx context.Context, req *sapb.Serial) (*corepb.Certificate, error)
	GetCertificateStatus(ctx context.Context, req *sapb.Serial) (*corepb.CertificateStatus, error)
	CountCertificatesByNames(ctx context.Context, req *sapb.CountCertificatesByNamesRequest) (*sapb.CountByNames, error)
	CountRegistrationsByIP(ctx context.Context, req *sapb.CountRegistrationsByIPRequest) (*sapb.Count, error)
	CountRegistrationsByIPRange(ctx context.Context, req *sapb.CountRegistrationsByIPRequest) (*sapb.Count, error)
	CountOrders(ctx context.Context, req *sapb.CountOrdersRequest) (*sapb.Count, error)
	CountFQDNSets(ctx context.Context, req *sapb.CountFQDNSetsRequest) (*sapb.Count, error)
	FQDNSetExists(ctx context.Context, req *sapb.FQDNSetExistsRequest) (*sapb.Exists, error)
	PreviousCertificateExists(ctx context.Context, req *sapb.PreviousCertificateExistsRequest) (exists *sapb.Exists, err error)
	GetOrder(ctx context.Context, req *sapb.OrderRequest) (*corepb.Order, error)
	GetOrderForNames(ctx context.Context, req *sapb.GetOrderForNamesRequest) (*corepb.Order, error)
	// New authz2 methods
	GetAuthorization2(ctx context.Context, req *sapb.AuthorizationID2) (*corepb.Authorization, error)
	GetAuthorizations2(ctx context.Context, req *sapb.GetAuthorizationsRequest) (*sapb.Authorizations, error)
	GetPendingAuthorization2(ctx context.Context, req *sapb.GetPendingAuthorizationRequest) (*corepb.Authorization, error)
	CountPendingAuthorizations2(ctx context.Context, req *sapb.RegistrationID) (*sapb.Count, error)
	GetValidOrderAuthorizations2(ctx context.Context, req *sapb.GetValidOrderAuthorizationsRequest) (*sapb.Authorizations, error)
	CountInvalidAuthorizations2(ctx context.Context, req *sapb.CountInvalidAuthorizationsRequest) (*sapb.Count, error)
	GetValidAuthorizations2(ctx context.Context, req *sapb.GetValidAuthorizationsRequest) (*sapb.Authorizations, error)
	KeyBlocked(ctx context.Context, req *sapb.KeyBlockedRequest) (*sapb.Exists, error)
}

// StorageAdder are the Boulder SA's write/update methods
type StorageAdder interface {
	NewRegistration(ctx context.Context, req *corepb.Registration) (*corepb.Registration, error)
	UpdateRegistration(ctx context.Context, req *corepb.Registration) (*emptypb.Empty, error)
	AddCertificate(ctx context.Context, req *sapb.AddCertificateRequest) (*sapb.AddCertificateResponse, error)
	AddPrecertificate(ctx context.Context, req *sapb.AddCertificateRequest) (*emptypb.Empty, error)
	AddSerial(ctx context.Context, req *sapb.AddSerialRequest) (*emptypb.Empty, error)
	DeactivateRegistration(ctx context.Context, req *sapb.RegistrationID) (*emptypb.Empty, error)
	NewOrder(ctx context.Context, req *sapb.NewOrderRequest) (*corepb.Order, error)
	SetOrderProcessing(ctx context.Context, req *sapb.OrderRequest) (*emptypb.Empty, error)
	FinalizeOrder(ctx context.Context, req *sapb.FinalizeOrderRequest) (*emptypb.Empty, error)
	SetOrderError(ctx context.Context, order *corepb.Order) error
	RevokeCertificate(ctx context.Context, req *sapb.RevokeCertificateRequest) (*emptypb.Empty, error)
	// New authz2 methods
	NewAuthorizations2(ctx context.Context, req *sapb.AddPendingAuthorizationsRequest) (*sapb.Authorization2IDs, error)
	FinalizeAuthorization2(ctx context.Context, req *sapb.FinalizeAuthorizationRequest) (*emptypb.Empty, error)
	DeactivateAuthorization2(ctx context.Context, req *sapb.AuthorizationID2) (*emptypb.Empty, error)
	AddBlockedKey(ctx context.Context, req *sapb.AddBlockedKeyRequest) (*emptypb.Empty, error)
}

// StorageAuthority interface represents a simple key/value
// store. The add and get interfaces contained within are divided
// for privilege separation.
type StorageAuthority interface {
	StorageGetter
	StorageAdder
}
