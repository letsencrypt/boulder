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

	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"
	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"
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
	SetAuthzBase(path string)

	// Set the base URL for certificates
	SetCertBase(path string)

	// This method represents the ACME new-registration resource
	NewRegistration(response http.ResponseWriter, request *http.Request)

	// This method represents the ACME new-authorization resource
	NewAuthz(response http.ResponseWriter, request *http.Request)

	// This method represents the ACME new-certificate resource
	NewCert(response http.ResponseWriter, request *http.Request)

	// Provide access to requests for registration resources
	Registration(response http.ResponseWriter, request *http.Request)

	// Provide access to requests for authorization resources
	Authz(response http.ResponseWriter, request *http.Request)

	// Provide access to requests for authorization resources
	Cert(response http.ResponseWriter, request *http.Request)
}

// RegistrationAuthority defines the public interface for the Boulder RA
type RegistrationAuthority interface {
	// [WebFrontEnd]
	NewRegistration(Registration) (Registration, error)

	// [WebFrontEnd]
	NewAuthorization(Authorization, int64) (Authorization, error)

	// [WebFrontEnd]
	NewCertificate(CertificateRequest, int64) (Certificate, error)

	// [WebFrontEnd]
	UpdateRegistration(Registration, Registration) (Registration, error)

	// [WebFrontEnd]
	UpdateAuthorization(Authorization, int, Challenge) (Authorization, error)

	// [WebFrontEnd]
	RevokeCertificateWithReg(x509.Certificate, RevocationCode, int64) error

	// [AdminRevoker]
	AdministrativelyRevokeCertificate(x509.Certificate, RevocationCode, string) error

	// [ValidationAuthority]
	OnValidationUpdate(Authorization) error
}

// ValidationAuthority defines the public interface for the Boulder VA
type ValidationAuthority interface {
	// [RegistrationAuthority]
	UpdateValidations(Authorization, int) error
	CheckCAARecords(AcmeIdentifier) (bool, bool, error)
}

// CertificateAuthority defines the public interface for the Boulder CA
type CertificateAuthority interface {
	// [RegistrationAuthority]
	IssueCertificate(x509.CertificateRequest, int64) (Certificate, error)
	RevokeCertificate(string, RevocationCode) error
	GenerateOCSP(OCSPSigningRequest) ([]byte, error)
}

// PolicyAuthority defines the public interface for the Boulder PA
type PolicyAuthority interface {
	WillingToIssue(AcmeIdentifier) error
	ChallengesFor(AcmeIdentifier) ([]Challenge, [][]int)
}

// StorageGetter are the Boulder SA's read-only methods
type StorageGetter interface {
	GetRegistration(int64) (Registration, error)
	GetRegistrationByKey(jose.JsonWebKey) (Registration, error)
	GetAuthorization(string) (Authorization, error)
	GetLatestValidAuthorization(int64, AcmeIdentifier) (Authorization, error)
	GetCertificate(string) (Certificate, error)
	GetCertificateStatus(string) (CertificateStatus, error)
	AlreadyDeniedCSR([]string) (bool, error)
	CountCertificatesRange(time.Time, time.Time) (int64, error)
	CountCertificatesByNames([]string, time.Time, time.Time) (map[string]int, error)
	GetSCTReceipt(string, string) (SignedCertificateTimestamp, error)
}

// StorageAdder are the Boulder SA's write/update methods
type StorageAdder interface {
	NewRegistration(Registration) (Registration, error)
	UpdateRegistration(Registration) error

	NewPendingAuthorization(Authorization) (Authorization, error)
	UpdatePendingAuthorization(Authorization) error
	FinalizeAuthorization(Authorization) error
	MarkCertificateRevoked(serial string, ocspResponse []byte, reasonCode RevocationCode) error
	UpdateOCSP(serial string, ocspResponse []byte) error

	AddCertificate([]byte, int64) (string, error)

	AddSCTReceipt(SignedCertificateTimestamp) error
}

// StorageAuthority interface represents a simple key/value
// store.  It is divided into StorageGetter and StorageUpdater
// interfaces for privilege separation.
type StorageAuthority interface {
	StorageGetter
	StorageAdder
}

// CertificateAuthorityDatabase represents an atomic sequence source
type CertificateAuthorityDatabase interface {
	IncrementAndGetSerial(*gorp.Transaction) (int64, error)
	Begin() (*gorp.Transaction, error)
}

// DNSResolver defines methods used for DNS resolution
type DNSResolver interface {
	ExchangeOne(string, uint16) (*dns.Msg, time.Duration, error)
	LookupTXT(string) ([]string, time.Duration, error)
	LookupHost(string) ([]net.IP, time.Duration, error)
	LookupCNAME(string) (string, time.Duration, error)
	LookupDNAME(string) (string, time.Duration, error)
	LookupCAA(string) ([]*dns.CAA, time.Duration, error)
	LookupMX(string) ([]string, time.Duration, error)
}

// Publisher defines the public interface for the Boulder Publisher
type Publisher interface {
	SubmitToCT([]byte) error
}
