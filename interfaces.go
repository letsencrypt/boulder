// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package anvil

import (
	"crypto/x509"
	"github.com/bifurcation/gose"
	"net/http"
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

	// This method represents the ACME new-authorization resource
	NewAuthz(response http.ResponseWriter, request *http.Request)

	// This method represents the ACME new-certificate resource
	NewCert(response http.ResponseWriter, request *http.Request)

	// Provide access to requests for authorization resources
	Authz(response http.ResponseWriter, request *http.Request)

	// Provide access to requests for authorization resources
	Cert(response http.ResponseWriter, request *http.Request)
}

type RegistrationAuthority interface {
	// [WebFrontEnd]
	NewAuthorization(Authorization, jose.JsonWebKey) (Authorization, error)

	// [WebFrontEnd]
	NewCertificate(CertificateRequest, jose.JsonWebKey) (Certificate, error)

	// [WebFrontEnd]
	UpdateAuthorization(Authorization) (Authorization, error)

	// [WebFrontEnd]
	RevokeCertificate(x509.Certificate) error

	// [ValidationAuthority]
	OnValidationUpdate(Authorization)
}

type ValidationAuthority interface {
	// [RegistrationAuthority]
	UpdateValidations(Authorization) error
}

type CertificateAuthority interface {
	// [RegistrationAuthority]
	IssueCertificate(x509.CertificateRequest) ([]byte, error)
}

type StorageGetter interface {
	Get(string) (interface{}, error)
}

type StorageUpdater interface {
	Update(string, interface{}) error
}

// The StorageAuthority interface represnts a simple key/value
// store.  It is divided into StorageGetter and StorageUpdater
// interfaces for privilege separation.
type StorageAuthority interface {
	StorageGetter
	StorageUpdater
}
