package core

import (
	"crypto/x509"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/context"
	jose "gopkg.in/square/go-jose.v1"

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
	UpdateAuthorization(ctx context.Context, authz Authorization, challengeIndex int, response Challenge) (Authorization, error)

	// [WebFrontEnd]
	RevokeCertificateWithReg(ctx context.Context, cert x509.Certificate, code revocation.Reason, regID int64) error

	// [WebFrontEnd]
	DeactivateRegistration(ctx context.Context, reg Registration) error

	// [WebFrontEnd]
	DeactivateAuthorization(ctx context.Context, auth Authorization) error

	// [AdminRevoker]
	AdministrativelyRevokeCertificate(ctx context.Context, cert x509.Certificate, code revocation.Reason, adminName string) error
}

// CertificateAuthority defines the public interface for the Boulder CA
type CertificateAuthority interface {
	// [RegistrationAuthority]
	IssueCertificate(ctx context.Context, csr x509.CertificateRequest, regID int64) (Certificate, error)
	GenerateOCSP(ctx context.Context, ocspReq OCSPSigningRequest) ([]byte, error)
}

// PolicyAuthority defines the public interface for the Boulder PA
type PolicyAuthority interface {
	WillingToIssue(domain AcmeIdentifier) error
	ChallengesFor(domain AcmeIdentifier) (challenges []Challenge, validCombinations [][]int)
}

// StorageGetter are the Boulder SA's read-only methods
type StorageGetter interface {
	GetRegistration(ctx context.Context, regID int64) (Registration, error)
	GetRegistrationByKey(ctx context.Context, jwk *jose.JsonWebKey) (Registration, error)
	GetAuthorization(ctx context.Context, authzID string) (Authorization, error)
	GetValidAuthorizations(ctx context.Context, regID int64, domains []string, now time.Time) (map[string]*Authorization, error)
	GetCertificate(ctx context.Context, serial string) (Certificate, error)
	GetCertificateStatus(ctx context.Context, serial string) (CertificateStatus, error)
	CountCertificatesRange(ctx context.Context, earliest, latest time.Time) (int64, error)
	CountCertificatesByNames(ctx context.Context, domains []string, earliest, latest time.Time) (countByDomain []*sapb.CountByNames_MapElement, err error)
	CountCertificatesByExactNames(ctx context.Context, domains []string, earliest, latest time.Time) (countByDomain []*sapb.CountByNames_MapElement, err error)
	CountRegistrationsByIP(ctx context.Context, ip net.IP, earliest, latest time.Time) (int, error)
	CountRegistrationsByIPRange(ctx context.Context, ip net.IP, earliest, latest time.Time) (int, error)
	CountPendingAuthorizations(ctx context.Context, regID int64) (int, error)
	GetSCTReceipt(ctx context.Context, serial, logID string) (SignedCertificateTimestamp, error)
	CountFQDNSets(ctx context.Context, window time.Duration, domains []string) (count int64, err error)
	FQDNSetExists(ctx context.Context, domains []string) (exists bool, err error)
}

// StorageAdder are the Boulder SA's write/update methods
type StorageAdder interface {
	NewRegistration(ctx context.Context, reg Registration) (created Registration, err error)
	UpdateRegistration(ctx context.Context, reg Registration) error
	NewPendingAuthorization(ctx context.Context, authz Authorization) (Authorization, error)
	UpdatePendingAuthorization(ctx context.Context, authz Authorization) error
	FinalizeAuthorization(ctx context.Context, authz Authorization) error
	MarkCertificateRevoked(ctx context.Context, serial string, reasonCode revocation.Reason) error
	AddCertificate(ctx context.Context, der []byte, regID int64, ocsp []byte) (digest string, err error)
	AddSCTReceipt(ctx context.Context, sct SignedCertificateTimestamp) error
	RevokeAuthorizationsByDomain(ctx context.Context, domain AcmeIdentifier) (finalized, pending int64, err error)
	DeactivateRegistration(ctx context.Context, id int64) error
	DeactivateAuthorization(ctx context.Context, id string) error
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
	SubmitToCT(ctx context.Context, der []byte) error
	SubmitToSingleCT(ctx context.Context, logURL, logPublicKey string, der []byte) error
}
