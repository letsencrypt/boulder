package core

import (
	"crypto/x509"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/context"
	jose "gopkg.in/square/go-jose.v2"

	caPB "github.com/letsencrypt/boulder/ca/proto"
	corepb "github.com/letsencrypt/boulder/core/proto"
	pubpb "github.com/letsencrypt/boulder/publisher/proto"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/revocation"
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
	NewRegistration(ctx context.Context, reg Registration) (Registration, error)

	// [WebFrontEnd]
	NewAuthorization(ctx context.Context, authz Authorization, regID int64) (Authorization, error)

	// [WebFrontEnd]
	NewCertificate(ctx context.Context, csr CertificateRequest, regID int64) (Certificate, error)

	// [WebFrontEnd]
	UpdateRegistration(ctx context.Context, base, updates Registration) (Registration, error)

	// [WebFrontEnd]
	PerformValidation(ctx context.Context, req *rapb.PerformValidationRequest) (*corepb.Authorization, error)

	// [WebFrontEnd]
	RevokeCertificateWithReg(ctx context.Context, cert x509.Certificate, code revocation.Reason, regID int64) error

	// [WebFrontEnd]
	DeactivateRegistration(ctx context.Context, reg Registration) error

	// [WebFrontEnd]
	DeactivateAuthorization(ctx context.Context, auth Authorization) error

	// [WebFrontEnd]
	NewOrder(ctx context.Context, req *rapb.NewOrderRequest) (*corepb.Order, error)

	// [WebFrontEnd]
	FinalizeOrder(ctx context.Context, req *rapb.FinalizeOrderRequest) (*corepb.Order, error)

	// [AdminRevoker]
	AdministrativelyRevokeCertificate(ctx context.Context, cert x509.Certificate, code revocation.Reason, adminName string) error
}

// CertificateAuthority defines the public interface for the Boulder CA
type CertificateAuthority interface {
	// [RegistrationAuthority]
	IssueCertificate(ctx context.Context, issueReq *caPB.IssueCertificateRequest) (Certificate, error)

	// [RegistrationAuthority]
	IssuePrecertificate(ctx context.Context, issueReq *caPB.IssueCertificateRequest) (*caPB.IssuePrecertificateResponse, error)

	// [RegistrationAuthority]
	IssueCertificateForPrecertificate(ctx context.Context, req *caPB.IssueCertificateForPrecertificateRequest) (Certificate, error)

	GenerateOCSP(ctx context.Context, ocspReq OCSPSigningRequest) ([]byte, error)
}

// PolicyAuthority defines the public interface for the Boulder PA
type PolicyAuthority interface {
	WillingToIssue(domain AcmeIdentifier) error
	WillingToIssueWildcard(domain AcmeIdentifier) error
	ChallengesFor(domain AcmeIdentifier) (challenges []Challenge, validCombinations [][]int, err error)
	ChallengeTypeEnabled(t string) bool
}

// StorageGetter are the Boulder SA's read-only methods
type StorageGetter interface {
	GetRegistration(ctx context.Context, regID int64) (Registration, error)
	GetRegistrationByKey(ctx context.Context, jwk *jose.JSONWebKey) (Registration, error)
	GetAuthorization(ctx context.Context, authzID string) (Authorization, error)
	GetValidAuthorizations(ctx context.Context, regID int64, domains []string, now time.Time) (map[string]*Authorization, error)
	GetPendingAuthorization(ctx context.Context, req *sapb.GetPendingAuthorizationRequest) (*Authorization, error)
	GetCertificate(ctx context.Context, serial string) (Certificate, error)
	GetCertificateStatus(ctx context.Context, serial string) (CertificateStatus, error)
	CountCertificatesByNames(ctx context.Context, domains []string, earliest, latest time.Time) (countByDomain []*sapb.CountByNames_MapElement, err error)
	CountCertificatesByExactNames(ctx context.Context, domains []string, earliest, latest time.Time) (countByDomain []*sapb.CountByNames_MapElement, err error)
	CountRegistrationsByIP(ctx context.Context, ip net.IP, earliest, latest time.Time) (int, error)
	CountRegistrationsByIPRange(ctx context.Context, ip net.IP, earliest, latest time.Time) (int, error)
	CountPendingAuthorizations(ctx context.Context, regID int64) (int, error)
	CountOrders(ctx context.Context, acctID int64, earliest, latest time.Time) (int, error)
	CountFQDNSets(ctx context.Context, window time.Duration, domains []string) (count int64, err error)
	FQDNSetExists(ctx context.Context, domains []string) (exists bool, err error)
	PreviousCertificateExists(ctx context.Context, req *sapb.PreviousCertificateExistsRequest) (exists *sapb.Exists, err error)
	GetOrder(ctx context.Context, req *sapb.OrderRequest) (*corepb.Order, error)
	GetOrderForNames(ctx context.Context, req *sapb.GetOrderForNamesRequest) (*corepb.Order, error)
	GetValidOrderAuthorizations(ctx context.Context, req *sapb.GetValidOrderAuthorizationsRequest) (map[string]*Authorization, error)
	CountInvalidAuthorizations(ctx context.Context, req *sapb.CountInvalidAuthorizationsRequest) (count *sapb.Count, err error)
	GetAuthorizations(ctx context.Context, req *sapb.GetAuthorizationsRequest) (*sapb.Authorizations, error)
	// New authz2 methods
	GetAuthorization2(ctx context.Context, req *sapb.AuthorizationID2) (*corepb.Authorization, error)
	GetAuthorizations2(ctx context.Context, req *sapb.GetAuthorizationsRequest) (*sapb.Authorizations, error)
	GetPendingAuthorization2(ctx context.Context, req *sapb.GetPendingAuthorizationRequest) (*corepb.Authorization, error)
	CountPendingAuthorizations2(ctx context.Context, req *sapb.RegistrationID) (*sapb.Count, error)
	GetValidOrderAuthorizations2(ctx context.Context, req *sapb.GetValidOrderAuthorizationsRequest) (*sapb.Authorizations, error)
	CountInvalidAuthorizations2(ctx context.Context, req *sapb.CountInvalidAuthorizationsRequest) (*sapb.Count, error)
	GetValidAuthorizations2(ctx context.Context, req *sapb.GetValidAuthorizationsRequest) (*sapb.Authorizations, error)
}

// StorageAdder are the Boulder SA's write/update methods
type StorageAdder interface {
	NewRegistration(ctx context.Context, reg Registration) (created Registration, err error)
	UpdateRegistration(ctx context.Context, reg Registration) error
	NewPendingAuthorization(ctx context.Context, authz Authorization) (Authorization, error)
	FinalizeAuthorization(ctx context.Context, authz Authorization) error
	MarkCertificateRevoked(ctx context.Context, serial string, reasonCode revocation.Reason) error
	AddCertificate(ctx context.Context, der []byte, regID int64, ocsp []byte, issued *time.Time) (digest string, err error)
	RevokeAuthorizationsByDomain(ctx context.Context, domain AcmeIdentifier) (finalized, pending int64, err error)
	DeactivateRegistration(ctx context.Context, id int64) error
	DeactivateAuthorization(ctx context.Context, id string) error
	NewOrder(ctx context.Context, order *corepb.Order) (*corepb.Order, error)
	SetOrderProcessing(ctx context.Context, order *corepb.Order) error
	FinalizeOrder(ctx context.Context, order *corepb.Order) error
	AddPendingAuthorizations(ctx context.Context, req *sapb.AddPendingAuthorizationsRequest) (*sapb.AuthorizationIDs, error)
	SetOrderError(ctx context.Context, order *corepb.Order) error
	RevokeCertificate(ctx context.Context, req *sapb.RevokeCertificateRequest) error
	// New authz2 methods
	NewAuthorization(ctx context.Context, req *corepb.Authorization) (*sapb.AuthorizationID2, error)
	NewAuthorizations(ctx context.Context, req *sapb.AddPendingAuthorizationsRequest) (*sapb.AuthorizationIDs, error)
	FinalizeAuthorization2(ctx context.Context, req *sapb.FinalizeAuthorizationRequest) error
	DeactivateAuthorization2(ctx context.Context, req *sapb.AuthorizationID2) error
	RevokeAuthorizationsByDomain2(ctx context.Context, req *sapb.RevokeAuthorizationsByDomainRequest) (*sapb.RevokeAuthorizationsByDomainResponse, error)
}

// StorageAuthority interface represents a simple key/value
// store.  It is divided into StorageGetter and StorageUpdater
// interfaces for privilege separation.
type StorageAuthority interface {
	StorageGetter
	StorageAdder
}

// Publisher defines the public interface for the Boulder Publisher
type Publisher interface {
	SubmitToSingleCTWithResult(ctx context.Context, req *pubpb.Request) (*pubpb.Result, error)
}
