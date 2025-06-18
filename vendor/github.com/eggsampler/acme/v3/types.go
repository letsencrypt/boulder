package acme

import (
	"crypto"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

var (
	// ErrUnsupportedKey is returned when an unsupported key type is encountered.
	ErrUnsupportedKey = errors.New("acme: unknown key type; only RSA and ECDSA are supported")

	// ErrRenewalInfoNotSupported is returned by Client.GetRenewalInfo if the
	// renewal info entry isn't present on the acme directory (ie, it's not
	// supported by the acme server)
	ErrRenewalInfoNotSupported = errors.New("renewal information endpoint not supported")
)

// Different possible challenge types provided by an ACME server.
// See https://tools.ietf.org/html/rfc8555#section-9.7.8
const (
	ChallengeTypeDNS01        = "dns-01"
	ChallengeTypeDNSAccount01 = "dns-account-01"
	ChallengeTypeHTTP01       = "http-01"
	ChallengeTypeTLSALPN01    = "tls-alpn-01"

	// ChallengeTypeTLSSNI01 is deprecated and should not be used.
	// See: https://community.letsencrypt.org/t/important-what-you-need-to-know-about-tls-sni-validation-issues/50811
	ChallengeTypeTLSSNI01 = "tls-sni-01"
)

// Constants used for certificate revocation, used for RevokeCertificate
// See https://tools.ietf.org/html/rfc5280#section-5.3.1
const (
	ReasonUnspecified          = iota // 0
	ReasonKeyCompromise               // 1
	ReasonCaCompromise                // 2
	ReasonAffiliationChanged          // 3
	ReasonSuperseded                  // 4
	ReasonCessationOfOperation        // 5
	ReasonCertificateHold             // 6
	_                                 // 7 - Unused
	ReasonRemoveFromCRL               // 8
	ReasonPrivilegeWithdrawn          // 9
	ReasonAaCompromise                // 10
)

// Directory object as returned from the client's directory url upon creation of client.
// See https://tools.ietf.org/html/rfc8555#section-7.1.1
type Directory struct {
	NewNonce   string `json:"newNonce"`   // url to new nonce endpoint
	NewAccount string `json:"newAccount"` // url to new account endpoint
	NewOrder   string `json:"newOrder"`   // url to new order endpoint
	NewAuthz   string `json:"newAuthz"`   // url to new authz endpoint
	RevokeCert string `json:"revokeCert"` // url to revoke cert endpoint
	KeyChange  string `json:"keyChange"`  // url to key change endpoint

	// https://datatracker.ietf.org/doc/html/draft-ietf-acme-ari-03
	RenewalInfo string `json:"renewalInfo"` // url to renewal info endpoint

	// meta object containing directory metadata
	Meta struct {
		TermsOfService          string            `json:"termsOfService"`
		Website                 string            `json:"website"`
		CaaIdentities           []string          `json:"caaIdentities"`
		ExternalAccountRequired bool              `json:"externalAccountRequired"`
		Profiles                map[string]string `json:"profiles"`
	} `json:"meta"`

	// Directory url provided when creating a new acme client.
	URL string `json:"-"`
}

// Client structure to interact with an ACME server.
// This is typically how most, if not all, of the communication between the client and server occurs.
type Client struct {
	httpClient      *http.Client
	nonces          *nonceStack
	dir             Directory
	userAgentSuffix string
	acceptLanguage  string
	retryCount      int

	// The amount of total time the Client will wait at most for a challenge to be updated or a certificate to be issued.
	// Default 30 seconds if duration is not set or if set to 0.
	PollTimeout time.Duration

	// The time between checking if a challenge has been updated or a certificate has been issued.
	// Default 0.5 seconds if duration is not set or if set to 0.
	PollInterval time.Duration

	// IgnorePolling does not use any simple polling in order finalisation
	IgnorePolling bool

	// IgnoreRetryAfter does not use the retry-after header in order finalisation
	IgnoreRetryAfter bool
}

// Account structure representing fields in an account object.
// See https://tools.ietf.org/html/rfc8555#section-7.1.2
// See also https://tools.ietf.org/html/rfc8555#section-9.7.1
type Account struct {
	Status  string   `json:"status"`
	Contact []string `json:"contact"`
	Orders  string   `json:"orders"`

	// Provided by the Location http header when creating a new account or fetching an existing account.
	URL string `json:"-"`

	// The private key used to create or fetch the account.
	// Not fetched from server.
	PrivateKey crypto.Signer `json:"-"`

	// Thumbprint is the SHA-256 digest JWK_Thumbprint of the account key.
	// See https://tools.ietf.org/html/rfc8555#section-8.1
	Thumbprint string `json:"-"`

	// ExternalAccountBinding is populated when using the NewAcctOptExternalAccountBinding option for NewAccountOption
	// and is otherwise empty. Not populated when account is fetched or created otherwise.
	ExternalAccountBinding ExternalAccountBinding `json:"-"`
}

// ExternalAccountBinding holds the key identifier and mac key provided for use in servers that support/require
// external account binding.
// The MacKey is a base64url-encoded string.
// Algorithm is a "MAC-based algorithm" as per RFC8555. Typically this is either,
//   - "HS256" for HashFunc: crypto.SHA256
//   - "HS384" for HashFunc: crypto.SHA384
//   - "HS512" for HashFunc: crypto.SHA512
//
// However this is dependent on the acme server in question and is provided here to give more options for future compatibility.
type ExternalAccountBinding struct {
	KeyIdentifier string      `json:"-"`
	MacKey        string      `json:"-"`
	Algorithm     string      `json:"-"`
	HashFunc      crypto.Hash `json:"-"`
}

// Identifier object used in order and authorization objects
// See https://tools.ietf.org/html/rfc8555#section-7.1.4
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Order object returned when fetching or creating a new order.
// See https://tools.ietf.org/html/rfc8555#section-7.1.3
type Order struct {
	Status         string       `json:"status"`
	Expires        time.Time    `json:"expires"`
	Identifiers    []Identifier `json:"identifiers"`
	Profile        string       `json:"Profile,omitempty"`
	NotBefore      time.Time    `json:"notBefore"`
	NotAfter       time.Time    `json:"notAfter"`
	Error          Problem      `json:"error"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate"`

	// URL for the order object.
	// Provided by the rel="Location" Link http header
	URL string `json:"-"`

	// RetryAfter is the http Retry-After header from the order response
	RetryAfter time.Time `json:"-"`

	// Replaces (optional, string): A string uniquely identifying a
	// previously-issued certificate which this order is intended to replace.
	// See https://datatracker.ietf.org/doc/html/draft-ietf-acme-ari-03#section-5
	Replaces string `json:"replaces,omitempty"`
}

// Authorization object returned when fetching an authorization in an order.
// See https://tools.ietf.org/html/rfc8555#section-7.1.4
type Authorization struct {
	Identifier Identifier  `json:"identifier"`
	Status     string      `json:"status"`
	Expires    time.Time   `json:"expires"`
	Challenges []Challenge `json:"challenges"`
	Wildcard   bool        `json:"wildcard"`

	// For convenience access to the provided challenges
	ChallengeMap   map[string]Challenge `json:"-"`
	ChallengeTypes []string             `json:"-"`

	URL string `json:"-"`
}

// Challenge object fetched in an authorization or directly from the challenge url.
// See https://tools.ietf.org/html/rfc8555#section-7.1.5
type Challenge struct {
	Type      string  `json:"type"`
	URL       string  `json:"url"`
	Status    string  `json:"status"`
	Validated string  `json:"validated"`
	Error     Problem `json:"error"`

	// Based on the challenge used
	Token            string `json:"token"`
	KeyAuthorization string `json:"keyAuthorization"`

	// Authorization url provided by the rel="up" Link http header
	AuthorizationURL string `json:"-"`
}

// OrderList of challenge objects.
type OrderList struct {
	Orders []string `json:"orders"`

	// Order list pagination, url to next orders.
	// Provided by the rel="next" Link http header
	Next string `json:"-"`
}

// NewAccountRequest object used for submitting a request for a new account.
// Primarily used with NewAccountOptionFunc
type NewAccountRequest struct {
	OnlyReturnExisting     bool            `json:"onlyReturnExisting"`
	TermsOfServiceAgreed   bool            `json:"termsOfServiceAgreed"`
	Contact                []string        `json:"contact,omitempty"`
	ExternalAccountBinding json.RawMessage `json:"externalAccountBinding"`
}

// RenewalInfo stores the server-provided suggestions on when to renew
// certificates.
type RenewalInfo struct {
	SuggestedWindow struct {
		Start time.Time `json:"start"`
		End   time.Time `json:"end"`
	} `json:"suggestedWindow"`
	ExplanationURL string `json:"explanationURL,omitempty"`

	RetryAfter time.Time `json:"-"`
}
