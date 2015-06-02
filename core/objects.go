// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/square/go-jose"
	"sort"
	"strings"
	"time"
)

type IdentifierType string
type AcmeStatus string
type OCSPStatus string
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
	OCSPStatusGood    = OCSPStatus("good")
	OCSPStatusRevoked = OCSPStatus("revoked")
)

const (
	ChallengeTypeSimpleHTTPS   = "simpleHttps"
	ChallengeTypeDVSNI         = "dvsni"
	ChallengeTypeDNS           = "dns"
	ChallengeTypeRecoveryToken = "recoveryToken"
)

const (
	CertActionRevoke = "revoke"
)

const (
	IdentifierDNS = IdentifierType("dns")
)

func cmpStrSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func cmpExtKeyUsageSlice(a, b []x509.ExtKeyUsage) bool {
	if len(a) != len(b) {
		return false
	}
	intA := make([]int, len(a))
	intB := make([]int, len(b))
	for i := range a {
		intA[i] = int(a[i])
		intB[i] = int(b[i])
	}
	sort.Ints(intA)
	sort.Ints(intB)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

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
	CSR            JsonBuffer `json:"csr"`            // The encoded CSR
	Authorizations []AcmeURL  `json:"authorizations"` // Authorizations
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

// An ACME Certificate Action Request is a message that is POSTed
// to a certificate URL to request some action on that certificate.
type CertActionRequest struct {
	// Right now, the only action is "revoke"
	Action string `json:"action"`

	// The SHA-256 fingerprint of the cert to be acted on, to prevent
	// replay between certificate URLs
	Fingerprint JsonBuffer `json:"fingerprint"`
}

// Registration objects represent non-public metadata attached
// to account keys.
type Registration struct {
	// Unique identifier
	ID int64 `json:"id" db:"id"`

	// Account key to which the details are attached
	Key jose.JsonWebKey `json:"key" db:"jwk"`

	// Recovery Token is used to prove connection to an earlier transaction
	RecoveryToken string `json:"recoveryToken" db:"recoveryToken"`

	// Contact URIs
	Contact []AcmeURL `json:"contact,omitempty" db:"contact"`

	// Agreement with terms of service
	Agreement string `json:"agreement,omitempty" db:"agreement"`

	LockCol int64 `json:"-"`
}

func (r *Registration) MergeUpdate(input Registration) {
	if len(input.Contact) > 0 {
		r.Contact = input.Contact
	}

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

// Check the sanity of a challenge object before issued to the client (completed = false)
// and before validation (completed = true).
func (ch Challenge) IsSane(completed bool) bool {
	if ch.Status != StatusPending {
		return false
	}

	switch ch.Type {
	case ChallengeTypeSimpleHTTPS:
		// check extra fields aren't used
		if ch.R != "" || ch.S != "" || ch.Nonce != "" {
			return false
		}

		// If the client has marked the challenge as completed, there should be a
		// non-empty path provided. Otherwise there should be no default path.
		if completed {
			if ch.Path == "" {
				return false
			}
		} else {
			if ch.Path != "" {
				return false
			}
		}

		// check token is present, corrent length, and contains b64 encoded string
		if ch.Token == "" || len(ch.Token) != 43 {
			return false
		}
		if _, err := B64dec(ch.Token); err != nil {
			return false
		}
	case ChallengeTypeDVSNI:
		// check extra fields aren't used
		if ch.Path != "" || ch.Token != "" {
			return false
		}

		if ch.Nonce == "" || len(ch.Nonce) != 32 {
			return false
		}
		if _, err := hex.DecodeString(ch.Nonce); err != nil {
			return false
		}

		// Check R & S are sane
		if ch.R == "" || len(ch.R) != 43 {
			return false
		}
		if _, err := B64dec(ch.R); err != nil {
			return false
		}

		if completed {
			if ch.S == "" || len(ch.S) != 43 {
				return false
			}
			if _, err := B64dec(ch.S); err != nil {
				return false
			}
		} else {
			if ch.S != "" {
				return false
			}
		}
	default:
		return false
	}

	return true
}

// Merge a client-provide response to a challenge with the issued challenge
// Note: This method does not update the challenge on the left side of the '.'
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
// on the wire (e.g., ID, regID) must be made empty before marshaling.
type Authorization struct {
	// An identifier for this authorization, unique across
	// authorizations and certificates within this instance.
	ID string `json:"id,omitempty" db:"id"`

	// The identifier for which authorization is being given
	Identifier AcmeIdentifier `json:"identifier,omitempty" db:"identifier"`

	// The registration ID associated with the authorization
	RegistrationID int64 `json:"regId,omitempty" db:"registrationID"`

	// The status of the validation of this authorization
	Status AcmeStatus `json:"status,omitempty" db:"status"`

	// The date after which this authorization will be no
	// longer be considered valid
	Expires time.Time `json:"-" db:"expires"`

	// This field is used only for marshaling, because time.Time
	// does not have proper omitempty behavior (see below)
	RawExpires *time.Time `json:"expires,omitempty" db:"-"`

	// An array of challenges objects used to validate the
	// applicant's control of the identifier.  For authorizations
	// in process, these are challenges to be fulfilled; for
	// final authorizations, they describe the evidence that
	// the server used in support of granting the authorization.
	Challenges []Challenge `json:"challenges,omitempty" db:"challenges"`

	// The server may suggest combinations of challenges if it
	// requires more than one challenge to be completed.
	Combinations [][]int `json:"combinations,omitempty" db:"combinations"`
}

// This method needs to be called before marshaling an Authorization
// object for public consumption, in order suppress various fields.
// With regard to "expires" in particular: The Go time.Time type does
// not have proper behavior with respect to omitempty
// https://github.com/golang/go/issues/4357
func (authz *Authorization) PrepareForPublicMarshal() {
	authz.ID = ""
	authz.RegistrationID = 0

	if !authz.Expires.IsZero() {
		t := authz.Expires
		authz.RawExpires = &t
	}
}

// Fields of this type get encoded and decoded JOSE-style, in base64url encoding
// with stripped padding.
type JsonBuffer []byte

// Url-safe base64 encode that strips padding
func base64URLEncode(data []byte) string {
	var result = base64.URLEncoding.EncodeToString(data)
	return strings.TrimRight(result, "=")
}

// Url-safe base64 decoder that adds padding
func base64URLDecode(data string) ([]byte, error) {
	var missing = (4 - len(data)%4) % 4
	data += strings.Repeat("=", missing)
	return base64.URLEncoding.DecodeString(data)
}

func (jb JsonBuffer) MarshalJSON() (result []byte, err error) {
	return json.Marshal(base64URLEncode(jb))
}

func (jb *JsonBuffer) UnmarshalJSON(data []byte) (err error) {
	var str string
	err = json.Unmarshal(data, &str)
	if err != nil {
		return err
	}
	*jb, err = base64URLDecode(str)
	return
}

// Certificate objects are entirely internal to the server.  The only
// thing exposed on the wire is the certificate itself.
type Certificate struct {
	RegistrationID int64 `db:"registrationID"`

	// The revocation status of the certificate.
	// * "valid" - not revoked
	// * "revoked" - revoked
	Status AcmeStatus `db:"status"`

	Serial  string     `db:"serial"`
	Digest  string     `db:"digest"`
	DER     JsonBuffer `db:"der"`
	Issued  time.Time  `db:"issued"`
	Expires time.Time  `db:"expires"`
}

func (cert Certificate) MatchesCSR(csr *x509.CertificateRequest, earliestExpiry time.Time) (err error) {
	parsedCertificate, err := x509.ParseCertificate([]byte(cert.DER))
	if err != nil {
		return
	}

	// Check issued certificate matches what was expected from the CSR
	hostNames := make([]string, len(csr.DNSNames))
	copy(hostNames, csr.DNSNames)
	if len(csr.Subject.CommonName) > 0 {
		hostNames = append(hostNames, csr.Subject.CommonName)
	}
	hostNames = UniqueNames(hostNames)

	if !KeyDigestEquals(parsedCertificate.PublicKey, csr.PublicKey) {
		err = InternalServerError("Generated certificate public key doesn't match CSR public key")
		return
	}
	if len(csr.Subject.CommonName) > 0 && parsedCertificate.Subject.CommonName != csr.Subject.CommonName {
		err = InternalServerError("Generated certificate CommonName doesn't match CSR CommonName")
		return
	}
	if !cmpStrSlice(parsedCertificate.DNSNames, hostNames) {
		err = InternalServerError("Generated certificate DNSNames don't match CSR DNSNames")
		return
	}
	if parsedCertificate.NotAfter.After(earliestExpiry) {
		err = InternalServerError("Generated certificate expires before earliest expiration")
		return
	}
	now := time.Now()
	if now.Sub(parsedCertificate.NotBefore) > time.Hour*24 {
		err = InternalServerError(fmt.Sprintf("Generated certificate is back dated %s", now.Sub(parsedCertificate.NotBefore)))
		return
	}
	if !parsedCertificate.BasicConstraintsValid {
		err = InternalServerError("Generated certificate doesn't have basic constraints set")
		return
	}
	if parsedCertificate.IsCA {
		err = InternalServerError("Generated certificate can sign other certificates")
		return
	}
	if !cmpExtKeyUsageSlice(parsedCertificate.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}) {
		err = InternalServerError("Generated certificate doesn't have correct key usage extensions")
		return
	}

	return
}

// CertificateStatus structs are internal to the server. They represent the
// latest data about the status of the certificate, required for OCSP updating
// and for validating that the subscriber has accepted the certificate.
type CertificateStatus struct {
	Serial string `db:"serial"`

	// subscriberApproved: true iff the subscriber has posted back to the server
	//   that they accept the certificate, otherwise 0.
	SubscriberApproved bool `db:"subscriberApproved"`

	// status: 'good' or 'revoked'. Note that good, expired certificates remain
	//   with status 'good' but don't necessarily get fresh OCSP responses.
	Status OCSPStatus `db:"status"`

	// ocspLastUpdated: The date and time of the last time we generated an OCSP
	//   response. If we have never generated one, this has the zero value of
	//   time.Time, i.e. Jan 1 1970.
	OCSPLastUpdated time.Time `db:"ocspLastUpdated"`

	// revokedDate: If status is 'revoked', this is the date and time it was
	//   revoked. Otherwise it has the zero value of time.Time, i.e. Jan 1 1970.
	RevokedDate time.Time `db:"revokedDate"`

	// revokedReason: If status is 'revoked', this is the reason code for the
	//   revocation. Otherwise it is zero (which happens to be the reason
	//   code for 'unspecified').
	RevokedReason int `db:"revokedReason"`

	LockCol int64 `json:"-"`
}

// A large table of OCSP responses. This contains all historical OCSP
// responses we've signed, is append-only, and is likely to get quite
// large. We'll probably want administratively truncate it at some point.
type OCSPResponse struct {
	ID int `db:"id"`

	// serial: Same as certificate serial.
	Serial string `db:"serial"`

	// createdAt: The date the response was signed.
	CreatedAt time.Time `db:"createdAt"`

	// response: The encoded and signed CRL.
	Response []byte `db:"response"`
}

// A large table of signed CRLs. This contains all historical CRLs
// we've signed, is append-only, and is likely to get quite large.
type CRL struct {
	// serial: Same as certificate serial.
	Serial string `db:"serial"`

	// createdAt: The date the CRL was signed.
	CreatedAt time.Time `db:"createdAt"`

	// crl: The encoded and signed CRL.
	CRL string `db:"crl"`
}

type DeniedCSR struct {
	ID int `db:"id"`

	Names string `db:"names"`
}

// OCSPSigningRequest is a transfer object representing an OCSP Signing Request
type OCSPSigningRequest struct {
	CertDER   []byte
	Status    string
	Reason    int
	RevokedAt time.Time
}
