// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"crypto/x509"
	"encoding/json"
	"github.com/letsencrypt/boulder/jose"
	"time"
)

type IdentifierType string
type AcmeStatus string
type Buffer []byte

const (
	StatusUnknown    = AcmeStatus("unknown")    // Unknown status; the default
	StatusPending    = AcmeStatus("pending")    // In process; client has next action
	StatusProcessing = AcmeStatus("processing") // In process; server has next action
	StatusValid      = AcmeStatus("valid")      // Validation succeeded
	StatusInvalid    = AcmeStatus("invalid")    // Validation failed
	StatusRevoked    = AcmeStatus("revoked")    // Object no longer valid
)

const (
	ChallengeTypeSimpleHTTPS   = "simpleHTTPS"
	ChallengeTypeDVSNI         = "dvsni"
	ChallengeTypeDNS           = "dns"
	ChallengeTypeRecoveryToken = "recoveryToken"
)

const (
	IdentifierDNS = IdentifierType("dns")
)

// An AcmeIdentifier encodes an identifier that can
// be validated by ACME.  The protocol allows for different
// types of identifier to be supported (DNS names, IP
// addresses, etc.), but currently we only support
// domain names.
type AcmeIdentifier struct {
	Type  IdentifierType `json:"type"`  // The type of identifier being encoded
	Value string         `json:"value"` // The identifier itself
}

// An ACME certificate request is just a CSR together with
// URIs pointing to authorizations that should collectively
// authorize the certificate being requsted.
//
// This type is never marshaled, since we only ever receive
// it from the client.  So it carries some additional information
// that is useful internally.  (We rely on Go's case-insensitive
// JSON unmarshal to properly unmarshal client requests.)
type CertificateRequest struct {
	CSR            *x509.CertificateRequest // The CSR
	Authorizations []AcmeURL                // Links to Authorization over the account key
}

type rawCertificateRequest struct {
	CSR            jose.JsonBuffer `json:"csr"`            // The encoded CSR
	Authorizations []AcmeURL       `json:"authorizations"` // Authorizations
}

func (cr *CertificateRequest) UnmarshalJSON(data []byte) error {
	var raw rawCertificateRequest
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	csr, err := x509.ParseCertificateRequest(raw.CSR)
	if err != nil {
		return err
	}

	cr.CSR = csr
	cr.Authorizations = raw.Authorizations
	return nil
}

func (cr CertificateRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(rawCertificateRequest{
		CSR:            cr.CSR.Raw,
		Authorizations: cr.Authorizations,
	})
}

// Registration objects represent non-public metadata attached
// to account keys.
type Registration struct {
	// Unique identifier
	ID string `json:"-"`

	// Account key to which the details are attached
	Key jose.JsonWebKey `json:"key"`

	// Recovery Token is used to prove connection to an earlier transaction
	RecoveryToken string `json:"recoveryToken"`

	// Contact URIs
	Contact []AcmeURL `json:"contact,omitempty"`

	// Agreement with terms of service
	Agreement string `json:"agreement,omitempty"`
}

func (r *Registration) MergeUpdate(input Registration) {
	if len(input.Contact) > 0 {
		r.Contact = input.Contact
	}

	// TODO: Test to make sure this has the proper value
	if len(input.Agreement) > 0 {
		r.Agreement = input.Agreement
	}
}

// Rather than define individual types for different types of
// challenge, we just throw all the elements into one bucket,
// together with the common metadata elements.
type Challenge struct {
	// The type of challenge
	Type string `json:"type"`

	// The status of this challenge
	Status AcmeStatus `json:"status,omitempty"`

	// If successful, the time at which this challenge
	// was completed by the server.
	Validated *time.Time `json:"validated,omitempty"`

	// A URI to which a response can be POSTed
	URI AcmeURL `json:"uri"`

	// Used by simpleHTTPS, recoveryToken, and dns challenges
	Token string `json:"token,omitempty"`

	// Used by simpleHTTPS challenges
	Path string `json:"path,omitempty"`

	// Used by dvsni challenges
	R     string `json:"r,omitempty"`
	S     string `json:"s,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

// Merge a client-provide response to a challenge with the issued challenge
// TODO: Remove return type from this method
func (ch Challenge) MergeResponse(resp Challenge) Challenge {
	// Only override fields that are supposed to be client-provided
	if len(ch.Path) == 0 {
		ch.Path = resp.Path
	}

	if len(ch.S) == 0 {
		ch.S = resp.S
	}

	return ch
}

// An ACME authorization object represents the authorization
// of an account key holder to act on behalf of a domain.  This
// struct is intended to be used both internally and for JSON
// marshaling on the wire.  Any fields that should be suppressed
// on the wire (e.g., ID) must be made empty before marshaling.
type Authorization struct {
	// An identifier for this authorization, unique across
	// authorizations and certificates within this instance.
	ID string `json:"id,omitempty"`

	// The identifier for which authorization is being given
	Identifier AcmeIdentifier `json:"identifier,omitempty"`

	// The account key that is authorized for the identifier
	Key jose.JsonWebKey `json:"key,omitempty"`

	// The status of the validation of this authorization
	Status AcmeStatus `json:"status,omitempty"`

	// The date after which this authorization will be no
	// longer be considered valid
	Expires time.Time `json:"expires,omitempty"`

	// An array of challenges objects used to validate the
	// applicant's control of the identifier.  For authorizations
	// in process, these are challenges to be fulfilled; for
	// final authorizations, they describe the evidence that
	// the server used in support of granting the authorization.
	Challenges []Challenge `json:"challenges,omitempty"`

	// The server may suggest combinations of challenges if it
	// requires more than one challenge to be completed.
	Combinations [][]int `json:"combinations,omitempty"`

	// The client may provide contact URIs to allow the server
	// to push information to it.
	Contact []AcmeURL `json:"contact,omitempty"`
}

// Certificate objects are entirely internal to the server.  The only
// thing exposed on the wire is the certificate itself.
type Certificate struct {
	// An identifier for this authorization, unique across
	// authorizations and certificates within this instance.
	ID string

	// The certificate itself
	DER jose.JsonBuffer

	// The revocation status of the certificate.
	// * "valid" - not revoked
	// * "revoked" - revoked
	Status AcmeStatus
}
