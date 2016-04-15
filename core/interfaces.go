// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"crypto/x509"
	"net"
	"net/http"
	"time"

	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/square/go-jose"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/golang.org/x/net/context"
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
	NewRegistration(context.Context, Registration) (Registration, error)

	// [WebFrontEnd]
	NewAuthorization(context.Context, Authorization, int64) (Authorization, error)

	// [WebFrontEnd]
	NewCertificate(context.Context, CertificateRequest, int64) (Certificate, error)

	// [WebFrontEnd]
	UpdateRegistration(context.Context, Registration, Registration) (Registration, error)

	// [WebFrontEnd]
	UpdateAuthorization(context.Context, Authorization, int, Challenge) (Authorization, error)

	// [WebFrontEnd]
	RevokeCertificateWithReg(context.Context, x509.Certificate, RevocationCode, int64) error

	// [AdminRevoker]
	AdministrativelyRevokeCertificate(context.Context, x509.Certificate, RevocationCode, string) error

	// [ValidationAuthority]
	OnValidationUpdate(context.Context, Authorization) error
}

// CertificateAuthority defines the public interface for the Boulder CA
type CertificateAuthority interface {
	// [RegistrationAuthority]
	IssueCertificate(context.Context, x509.CertificateRequest, int64) (Certificate, error)
	GenerateOCSP(context.Context, OCSPSigningRequest) ([]byte, error)
}

// PolicyAuthority defines the public interface for the Boulder PA
type PolicyAuthority interface {
	WillingToIssue(ctx context.Context, id AcmeIdentifier, regID int64) error
	ChallengesFor(context.Context, AcmeIdentifier, *jose.JsonWebKey) ([]Challenge, [][]int)
}

// StorageGetter are the Boulder SA's read-only methods
type StorageGetter interface {
	GetRegistration(context.Context, int64) (Registration, error)
	GetRegistrationByKey(context.Context, jose.JsonWebKey) (Registration, error)
	GetAuthorization(context.Context, string) (Authorization, error)
	GetLatestValidAuthorization(context.Context, int64, AcmeIdentifier) (Authorization, error)
	GetValidAuthorizations(context.Context, int64, []string, time.Time) (map[string]*Authorization, error)
	GetCertificate(context.Context, string) (Certificate, error)
	GetCertificateStatus(context.Context, string) (CertificateStatus, error)
	AlreadyDeniedCSR(context.Context, []string) (bool, error)
	CountCertificatesRange(context.Context, time.Time, time.Time) (int64, error)
	CountCertificatesByNames(context.Context, []string, time.Time, time.Time) (map[string]int, error)
	CountRegistrationsByIP(context.Context, net.IP, time.Time, time.Time) (int, error)
	CountPendingAuthorizations(ctx context.Context, regID int64) (int, error)
	GetSCTReceipt(context.Context, string, string) (SignedCertificateTimestamp, error)
	CountFQDNSets(context.Context, time.Duration, []string) (int64, error)
	FQDNSetExists(context.Context, []string) (bool, error)
}

// StorageAdder are the Boulder SA's write/update methods
type StorageAdder interface {
	NewRegistration(context.Context, Registration) (Registration, error)
	UpdateRegistration(context.Context, Registration) error
	NewPendingAuthorization(context.Context, Authorization) (Authorization, error)
	UpdatePendingAuthorization(context.Context, Authorization) error
	FinalizeAuthorization(context.Context, Authorization) error
	MarkCertificateRevoked(ctx context.Context, serial string, reasonCode RevocationCode) error
	UpdateOCSP(ctx context.Context, serial string, ocspResponse []byte) error
	AddCertificate(context.Context, []byte, int64) (string, error)
	AddSCTReceipt(context.Context, SignedCertificateTimestamp) error
	RevokeAuthorizationsByDomain(context.Context, AcmeIdentifier) (int64, int64, error)
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
	SubmitToCT(context.Context, []byte) error
}
