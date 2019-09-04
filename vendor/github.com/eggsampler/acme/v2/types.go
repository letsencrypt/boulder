package acme

import (
	"crypto"
	"errors"
	"net/http"
	"time"
)

// Different possible challenge types provided by an ACME server.
const (
	ChallengeTypeDNS01     = "dns-01"
	ChallengeTypeHTTP01    = "http-01"
	ChallengeTypeTLSALPN01 = "tls-alpn-01"
	ChallengeTypeTLSSNI01  = "tls-sni-01"
)

// Constants used for certificate revocation, used for RevokeCertificate
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

var (
	ErrUnsupported = errors.New("acme: unsupported")
)

// Directory object as returned from the client's directory url upon creation of client.
type Directory struct {
	NewNonce   string `json:"newNonce"`   // url to new nonce endpoint
	NewAccount string `json:"newAccount"` // url to new account endpoint
	NewOrder   string `json:"newOrder"`   // url to new order endpoint
	NewAuthz   string `json:"newAuthz"`   // url to new authz endpoint
	RevokeCert string `json:"revokeCert"` // url to revoke cert endpoint
	KeyChange  string `json:"keyChange"`  // url to key change endpoint

	// meta object containing directory metadata
	Meta struct {
		TermsOfService          string   `json:"termsOfService"`
		Website                 string   `json:"website"`
		CaaIdentities           []string `json:"caaIdentities"`
		ExternalAccountRequired bool     `json:"externalAccountRequired"`
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
}

// Account structure representing fields in an account object.
type Account struct {
	Status               string   `json:"status"`
	Contact              []string `json:"contact"`
	TermsOfServiceAgreed bool     `json:"onlyReturnExisting"`
	Orders               string   `json:"orders"`

	// Provided by the Location http header when creating a new account or fetching an existing account.
	URL string `json:"-"`

	// The private key used to create or fetch the account.
	// Not fetched from server.
	PrivateKey crypto.Signer `json:"-"`

	// SHA-256 digest JWK_Thumbprint of the account key.
	// Used in updating challenges, see: https://tools.ietf.org/html/draft-ietf-acme-acme-10#section-8.1
	Thumbprint string `json:"-"`
}

// Identifier object used in order and authorization objects
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Order object returned when fetching or creating a new order.
type Order struct {
	Status         string       `json:"status"`
	Expires        time.Time    `json:"expires"`
	Identifiers    []Identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	Error          Problem      `json:"error"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate"`

	// URL for the order object.
	// Provided by the rel="Location" Link http header
	URL string `json:"-"`
}

// Authorization object returned when fetching an authorization in an order.
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
