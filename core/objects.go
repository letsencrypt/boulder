package core

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v1"

	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/revocation"
)

// AcmeStatus defines the state of a given authorization
type AcmeStatus string

// AcmeResource values identify different types of ACME resources
type AcmeResource string

// Buffer is a variable-length collection of bytes
type Buffer []byte

// IdentifierType defines the available identification mechanisms for domains
type IdentifierType string

// OCSPStatus defines the state of OCSP for a domain
type OCSPStatus string

// These statuses are the states of authorizations, challenges, and registrations
const (
	StatusUnknown     = AcmeStatus("unknown")     // Unknown status; the default
	StatusPending     = AcmeStatus("pending")     // In process; client has next action
	StatusProcessing  = AcmeStatus("processing")  // In process; server has next action
	StatusValid       = AcmeStatus("valid")       // Object is valid
	StatusInvalid     = AcmeStatus("invalid")     // Validation failed
	StatusRevoked     = AcmeStatus("revoked")     // Object no longer valid
	StatusDeactivated = AcmeStatus("deactivated") // Object has been deactivated
)

// These types are the available identification mechanisms
const (
	IdentifierDNS = IdentifierType("dns")
)

// The types of ACME resources
const (
	ResourceNewReg       = AcmeResource("new-reg")
	ResourceNewAuthz     = AcmeResource("new-authz")
	ResourceNewCert      = AcmeResource("new-cert")
	ResourceRevokeCert   = AcmeResource("revoke-cert")
	ResourceRegistration = AcmeResource("reg")
	ResourceChallenge    = AcmeResource("challenge")
	ResourceAuthz        = AcmeResource("authz")
	ResourceKeyChange    = AcmeResource("key-change")
)

// These status are the states of OCSP
const (
	OCSPStatusGood    = OCSPStatus("good")
	OCSPStatusRevoked = OCSPStatus("revoked")
)

// These types are the available challenges
const (
	ChallengeTypeHTTP01   = "http-01"
	ChallengeTypeTLSSNI01 = "tls-sni-01"
	ChallengeTypeTLSSNI02 = "tls-sni-02"
	ChallengeTypeDNS01    = "dns-01"
)

// ValidChallenge tests whether the provided string names a known challenge
func ValidChallenge(name string) bool {
	switch name {
	case ChallengeTypeHTTP01:
		fallthrough
	case ChallengeTypeTLSSNI01:
		fallthrough
	case ChallengeTypeDNS01:
		return true
	case ChallengeTypeTLSSNI02:
		return features.Enabled(features.AllowTLS02Challenges)

	default:
		return false
	}
}

// TLSSNISuffix is appended to pseudo-domain names in DVSNI challenges
const TLSSNISuffix = "acme.invalid"

// DNSPrefix is attached to DNS names in DNS challenges
const DNSPrefix = "_acme-challenge"

// An AcmeIdentifier encodes an identifier that can
// be validated by ACME.  The protocol allows for different
// types of identifier to be supported (DNS names, IP
// addresses, etc.), but currently we only support
// domain names.
type AcmeIdentifier struct {
	Type  IdentifierType `json:"type"`  // The type of identifier being encoded
	Value string         `json:"value"` // The identifier itself
}

// CertificateRequest is just a CSR
//
// This data is unmarshalled from JSON by way of RawCertificateRequest, which
// represents the actual structure received from the client.
type CertificateRequest struct {
	CSR   *x509.CertificateRequest // The CSR
	Bytes []byte                   // The original bytes of the CSR, for logging.
}

type RawCertificateRequest struct {
	CSR JSONBuffer `json:"csr"` // The encoded CSR
}

// UnmarshalJSON provides an implementation for decoding CertificateRequest objects.
func (cr *CertificateRequest) UnmarshalJSON(data []byte) error {
	var raw RawCertificateRequest
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	csr, err := x509.ParseCertificateRequest(raw.CSR)
	if err != nil {
		return err
	}

	cr.CSR = csr
	cr.Bytes = raw.CSR
	return nil
}

// MarshalJSON provides an implementation for encoding CertificateRequest objects.
func (cr CertificateRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(RawCertificateRequest{
		CSR: cr.CSR.Raw,
	})
}

// Registration objects represent non-public metadata attached
// to account keys.
type Registration struct {
	// Unique identifier
	ID int64 `json:"id" db:"id"`

	// Account key to which the details are attached
	Key *jose.JsonWebKey `json:"key"`

	// Contact URIs
	Contact *[]string `json:"contact,omitempty"`

	// Agreement with terms of service
	Agreement string `json:"agreement,omitempty"`

	// InitialIP is the IP address from which the registration was created
	InitialIP net.IP `json:"initialIp"`

	// CreatedAt is the time the registration was created.
	CreatedAt time.Time `json:"createdAt"`

	Status AcmeStatus
}

// ValidationRecord represents a validation attempt against a specific URL/hostname
// and the IP addresses that were resolved and used
type ValidationRecord struct {
	// DNS only
	Authorities []string `json:",omitempty"`

	// SimpleHTTP only
	URL string `json:"url,omitempty"`

	// Shared
	Hostname          string   `json:"hostname"`
	Port              string   `json:"port"`
	AddressesResolved []net.IP `json:"addressesResolved"`
	AddressUsed       net.IP   `json:"addressUsed"`
	// AddressesTried contains a list of addresses tried before the `AddressUsed`.
	// Presently this will only ever be one IP from `AddressesResolved` since the
	// only retry is in the case of a v6 failure with one v4 fallback. E.g. if
	// a record with `AddressesResolved: { 127.0.0.1, ::1 }` were processed for
	// a challenge validation with the IPv6 first flag on and the ::1 address
	// failed but the 127.0.0.1 retry succeeded then the record would end up
	// being:
	// {
	//   ...
	//   AddressesResolved: [ 127.0.0.1, ::1 ],
	//   AddressUsed: 127.0.0.1
	//   AddressesTried: [ ::1 ],
	//   ...
	// }
	AddressesTried []net.IP `json:"addressesTried"`
}

func looksLikeKeyAuthorization(str string) error {
	parts := strings.Split(str, ".")
	if len(parts) != 2 {
		return fmt.Errorf("Invalid key authorization: does not look like a key authorization")
	} else if !LooksLikeAToken(parts[0]) {
		return fmt.Errorf("Invalid key authorization: malformed token")
	} else if !LooksLikeAToken(parts[1]) {
		// Thumbprints have the same syntax as tokens in boulder
		// Both are base64-encoded and 32 octets
		return fmt.Errorf("Invalid key authorization: malformed key thumbprint")
	}
	return nil
}

// Challenge is an aggregate of all data needed for any challenges.
//
// Rather than define individual types for different types of
// challenge, we just throw all the elements into one bucket,
// together with the common metadata elements.
type Challenge struct {
	ID int64 `json:"id,omitempty"`

	// The type of challenge
	Type string `json:"type"`

	// The status of this challenge
	Status AcmeStatus `json:"status,omitempty"`

	// Contains the error that occurred during challenge validation, if any
	Error *probs.ProblemDetails `json:"error,omitempty"`

	// A URI to which a response can be POSTed
	URI string `json:"uri"`

	// Used by http-01, tls-sni-01, and dns-01 challenges
	Token string `json:"token,omitempty"` // Used by http-00, tls-sni-00, and dns-00 challenges

	// The KeyAuthorization provided by the client to start validation of
	// the challenge. Set during
	//
	//   POST /acme/authz/:authzid/:challid
	//
	// Used by http-01, tls-sni-01, and dns-01 challenges
	ProvidedKeyAuthorization string `json:"keyAuthorization,omitempty"`

	// Contains information about URLs used or redirected to and IPs resolved and
	// used
	ValidationRecord []ValidationRecord `json:"validationRecord,omitempty"`
}

// ExpectedKeyAuthorization computes the expected KeyAuthorization value for
// the challenge.
func (ch Challenge) ExpectedKeyAuthorization(key *jose.JsonWebKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("Cannot authorize a nil key")
	}

	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}

	return ch.Token + "." + base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

// RecordsSane checks the sanity of a ValidationRecord object before sending it
// back to the RA to be stored.
func (ch Challenge) RecordsSane() bool {
	if ch.ValidationRecord == nil || len(ch.ValidationRecord) == 0 {
		return false
	}

	switch ch.Type {
	case ChallengeTypeHTTP01:
		for _, rec := range ch.ValidationRecord {
			if rec.URL == "" || rec.Hostname == "" || rec.Port == "" || rec.AddressUsed == nil ||
				len(rec.AddressesResolved) == 0 {
				return false
			}
		}
	case ChallengeTypeTLSSNI01:
		fallthrough
	case ChallengeTypeTLSSNI02:
		if len(ch.ValidationRecord) > 1 {
			return false
		}
		if ch.ValidationRecord[0].URL != "" {
			return false
		}
		if ch.ValidationRecord[0].Hostname == "" || ch.ValidationRecord[0].Port == "" ||
			ch.ValidationRecord[0].AddressUsed == nil || len(ch.ValidationRecord[0].AddressesResolved) == 0 {
			return false
		}
	case ChallengeTypeDNS01:
		if len(ch.ValidationRecord) > 1 {
			return false
		}
		if ch.ValidationRecord[0].Hostname == "" {
			return false
		}
		return true
	default: // Unsupported challenge type
		return false
	}

	return true
}

// CheckConsistencyForClientOffer checks the fields of a challenge object before it is
// given to the client.
func (ch Challenge) CheckConsistencyForClientOffer() error {
	if err := ch.checkConsistency(); err != nil {
		return err
	}

	// Before completion, the key authorization field should be empty
	if ch.ProvidedKeyAuthorization != "" {
		return fmt.Errorf("A response to this challenge was already submitted.")
	}
	return nil
}

// CheckConsistencyForValidation checks the fields of a challenge object before it is
// given to the VA.
func (ch Challenge) CheckConsistencyForValidation() error {
	if err := ch.checkConsistency(); err != nil {
		return err
	}

	// If the challenge is completed, then there should be a key authorization
	return looksLikeKeyAuthorization(ch.ProvidedKeyAuthorization)
}

// checkConsistency checks the sanity of a challenge object before issued to the client.
func (ch Challenge) checkConsistency() error {
	if ch.Status != StatusPending {
		return fmt.Errorf("The challenge is not pending.")
	}

	// There always needs to be a token
	if !LooksLikeAToken(ch.Token) {
		return fmt.Errorf("The token is missing.")
	}
	return nil
}

// Authorization represents the authorization of an account key holder
// to act on behalf of a domain.  This struct is intended to be used both
// internally and for JSON marshaling on the wire.  Any fields that should be
// suppressed on the wire (e.g., ID, regID) must be made empty before marshaling.
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
	// longer be considered valid. Note: a certificate may be issued even on the
	// last day of an authorization's lifetime. The last day for which someone can
	// hold a valid certificate based on an authorization is authorization
	// lifetime + certificate lifetime.
	Expires *time.Time `json:"expires,omitempty" db:"expires"`

	// An array of challenges objects used to validate the
	// applicant's control of the identifier.  For authorizations
	// in process, these are challenges to be fulfilled; for
	// final authorizations, they describe the evidence that
	// the server used in support of granting the authorization.
	Challenges []Challenge `json:"challenges,omitempty" db:"-"`

	// The server may suggest combinations of challenges if it
	// requires more than one challenge to be completed.
	Combinations [][]int `json:"combinations,omitempty" db:"combinations"`
}

// FindChallenge will look for the given challenge inside this authorization. If
// found, it will return the index of that challenge within the Authorization's
// Challenges array. Otherwise it will return -1.
func (authz *Authorization) FindChallenge(challengeID int64) int {
	for i, c := range authz.Challenges {
		if c.ID == challengeID {
			return i
		}
	}
	return -1
}

// JSONBuffer fields get encoded and decoded JOSE-style, in base64url encoding
// with stripped padding.
type JSONBuffer []byte

// URL-safe base64 encode that strips padding
func base64URLEncode(data []byte) string {
	var result = base64.URLEncoding.EncodeToString(data)
	return strings.TrimRight(result, "=")
}

// URL-safe base64 decoder that adds padding
func base64URLDecode(data string) ([]byte, error) {
	var missing = (4 - len(data)%4) % 4
	data += strings.Repeat("=", missing)
	return base64.URLEncoding.DecodeString(data)
}

// MarshalJSON encodes a JSONBuffer for transmission.
func (jb JSONBuffer) MarshalJSON() (result []byte, err error) {
	return json.Marshal(base64URLEncode(jb))
}

// UnmarshalJSON decodes a JSONBuffer to an object.
func (jb *JSONBuffer) UnmarshalJSON(data []byte) (err error) {
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

	Serial  string    `db:"serial"`
	Digest  string    `db:"digest"`
	DER     []byte    `db:"der"`
	Issued  time.Time `db:"issued"`
	Expires time.Time `db:"expires"`
}

// IdentifierData holds information about what certificates are known for a
// given identifier. This is used to present Proof of Possession challenges in
// the case where a certificate already exists. The DB table holding
// IdentifierData rows contains information about certs issued by Boulder and
// also information about certs observed from third parties.
type IdentifierData struct {
	ReversedName string `db:"reversedName"` // The label-wise reverse of an identifier, e.g. com.example or com.example.*
	CertSHA1     string `db:"certSHA1"`     // The hex encoding of the SHA-1 hash of a cert containing the identifier
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
	RevokedReason revocation.Reason `db:"revokedReason"`

	LastExpirationNagSent time.Time `db:"lastExpirationNagSent"`

	// The encoded and signed OCSP response.
	OCSPResponse []byte `db:"ocspResponse"`

	// For performance reasons[0] we duplicate the `Expires` field of the
	// `Certificates` object/table in `CertificateStatus` to avoid a costly `JOIN`
	// later on just to retrieve this `Time` value. This helps both the OCSP
	// updater and the expiration-mailer stay performant.
	//
	// Similarly, we add an explicit `IsExpired` boolean to `CertificateStatus`
	// table that the OCSP updater so that the database can create a meaningful
	// index on `(isExpired, ocspLastUpdated)` without a `JOIN` on `certificates`.
	// For more detail see Boulder #1864[0].
	//
	// [0]: https://github.com/letsencrypt/boulder/issues/1864
	NotAfter  time.Time `db:"notAfter"`
	IsExpired bool      `db:"isExpired"`

	LockCol int64 `json:"-"`
}

// OCSPResponse is a (large) table of OCSP responses. This contains all
// historical OCSP responses we've signed, is append-only, and is likely to get
// quite large.
// It must be administratively truncated outside of Boulder.
type OCSPResponse struct {
	ID int `db:"id"`

	// serial: Same as certificate serial.
	Serial string `db:"serial"`

	// createdAt: The date the response was signed.
	CreatedAt time.Time `db:"createdAt"`

	// response: The encoded and signed CRL.
	Response []byte `db:"response"`
}

// CRL is a large table of signed CRLs. This contains all historical CRLs
// we've signed, is append-only, and is likely to get quite large.
// It must be administratively truncated outside of Boulder.
type CRL struct {
	// serial: Same as certificate serial.
	Serial string `db:"serial"`

	// createdAt: The date the CRL was signed.
	CreatedAt time.Time `db:"createdAt"`

	// crl: The encoded and signed CRL.
	CRL string `db:"crl"`
}

// OCSPSigningRequest is a transfer object representing an OCSP Signing Request
type OCSPSigningRequest struct {
	CertDER   []byte
	Status    string
	Reason    revocation.Reason
	RevokedAt time.Time
}

// SignedCertificateTimestamp is the internal representation of ct.SignedCertificateTimestamp
// that is used to maintain backwards compatibility with our old CT implementation.
type SignedCertificateTimestamp struct {
	ID int `db:"id"`
	// The version of the protocol to which the SCT conforms
	SCTVersion uint8 `db:"sctVersion"`
	// the SHA-256 hash of the log's public key, calculated over
	// the DER encoding of the key represented as SubjectPublicKeyInfo.
	LogID string `db:"logID"`
	// Timestamp (in ms since unix epoc) at which the SCT was issued
	Timestamp uint64 `db:"timestamp"`
	// For future extensions to the protocol
	Extensions []byte `db:"extensions"`
	// The Log's signature for this SCT
	Signature []byte `db:"signature"`

	// The serial of the certificate this SCT is for
	CertificateSerial string `db:"certificateSerial"`

	LockCol int64
}

// FQDNSet contains the SHA256 hash of the lowercased, comma joined dNSNames
// contained in a certificate.
type FQDNSet struct {
	ID      int64
	SetHash []byte
	Serial  string
	Issued  time.Time
	Expires time.Time
}
