package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	cfsslConfig "github.com/cloudflare/cfssl/config"
	"github.com/letsencrypt/pkcs11key"

	"github.com/letsencrypt/boulder/core"
)

// PasswordConfig either contains a password or the path to a file
// containing a password
type PasswordConfig struct {
	Password     string
	PasswordFile string
}

// Pass returns a password, either directly from the configuration
// struct or by reading from a specified file
func (pc *PasswordConfig) Pass() (string, error) {
	if pc.PasswordFile != "" {
		contents, err := ioutil.ReadFile(pc.PasswordFile)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(contents), "\n"), nil
	}
	return pc.Password, nil
}

// ServiceConfig contains config items that are common to all our services, to
// be embedded in other config structs.
type ServiceConfig struct {
	// DebugAddr is the address to run the /debug handlers on.
	DebugAddr string
	GRPC      *GRPCServerConfig
	TLS       TLSConfig
}

// DBConfig defines how to connect to a database. The connect string may be
// stored in a file separate from the config, because it can contain a password,
// which we want to keep out of configs.
type DBConfig struct {
	DBConnect string
	// A file containing a connect URL for the DB.
	DBConnectFile string
	MaxDBConns    int
}

// URL returns the DBConnect URL represented by this DBConfig object, either
// loading it from disk or returning a default value. Leading and trailing
// whitespace is stripped.
func (d *DBConfig) URL() (string, error) {
	if d.DBConnectFile != "" {
		url, err := ioutil.ReadFile(d.DBConnectFile)
		return strings.TrimSpace(string(url)), err
	}
	return d.DBConnect, nil
}

type SMTPConfig struct {
	PasswordConfig
	Server   string
	Port     string
	Username string
}

// CAConfig structs have configuration information for the certificate
// authority, including database parameters as well as controls for
// issued certificates.
type CAConfig struct {
	ServiceConfig
	DBConfig
	HostnamePolicyConfig

	GRPCCA            *GRPCServerConfig
	GRPCOCSPGenerator *GRPCServerConfig

	RSAProfile   string
	ECDSAProfile string
	TestMode     bool
	SerialPrefix int
	// TODO(jsha): Remove Key field once we've migrated to Issuers
	Key *IssuerConfig
	// Issuers contains configuration information for each issuer cert and key
	// this CA knows about. The first in the list is used as the default.
	Issuers []IssuerConfig
	// LifespanOCSP is how long OCSP responses are valid for; It should be longer
	// than the minTimeToExpiry field for the OCSP Updater.
	LifespanOCSP ConfigDuration
	// How long issued certificates are valid for, should match expiry field
	// in cfssl config.
	Expiry string
	// The maximum number of subjectAltNames in a single certificate
	MaxNames int
	CFSSL    cfsslConfig.Config

	// DoNotForceCN is a temporary config setting. It controls whether
	// to add a certificate's serial to its Subject, and whether to
	// not pull a SAN entry to be the CN if no CN was given in a CSR.
	DoNotForceCN bool

	// EnableMustStaple governs whether the Must Staple extension in CSRs
	// triggers issuance of certificates with Must Staple.
	EnableMustStaple bool

	// WeakKeyFile is the path to a JSON file containing truncated RSA modulus
	// hashes of known easily enumerable keys.
	WeakKeyFile string

	SAService *GRPCClientConfig

	Features map[string]bool
}

// PAConfig specifies how a policy authority should connect to its
// database, what policies it should enforce, and what challenges
// it should offer.
type PAConfig struct {
	DBConfig
	EnforcePolicyWhitelist bool
	Challenges             map[string]bool
}

// HostnamePolicyConfig specifies a file from which to load a policy regarding
// what hostnames to issue for.
type HostnamePolicyConfig struct {
	HostnamePolicyFile string
}

// CheckChallenges checks whether the list of challenges in the PA config
// actually contains valid challenge names
func (pc PAConfig) CheckChallenges() error {
	if len(pc.Challenges) == 0 {
		return errors.New("empty challenges map in the Policy Authority config is not allowed")
	}
	for name := range pc.Challenges {
		if !core.ValidChallenge(name) {
			return fmt.Errorf("Invalid challenge in PA config: %s", name)
		}
	}
	return nil
}

// IssuerConfig contains info about an issuer: private key and issuer cert.
// It should contain either a File path to a PEM-format private key,
// or a PKCS11Config defining how to load a module for an HSM.
type IssuerConfig struct {
	// A file from which a pkcs11key.Config will be read and parsed, if present
	ConfigFile string
	File       string
	PKCS11     *pkcs11key.Config
	CertFile   string
	// Number of sessions to open with the HSM. For maximum performance,
	// this should be equal to the number of cores in the HSM. Defaults to 1.
	NumSessions int
}

// TLSConfig represents certificates and a key for authenticated TLS.
type TLSConfig struct {
	CertFile   *string
	KeyFile    *string
	CACertFile *string
}

// Load reads and parses the certificates and key listed in the TLSConfig, and
// returns a *tls.Config suitable for either client or server use.
func (t TLSConfig) Load() (*tls.Config, error) {
	if t.CertFile == nil {
		return nil, fmt.Errorf("nil CertFile in TLSConfig")
	}
	if t.KeyFile == nil {
		return nil, fmt.Errorf("nil KeyFile in TLSConfig")
	}
	if t.CACertFile == nil {
		return nil, fmt.Errorf("nil CACertFile in TLSConfig")
	}
	caCertBytes, err := ioutil.ReadFile(*t.CACertFile)
	if err != nil {
		return nil, fmt.Errorf("reading CA cert from %q: %s", *t.CACertFile, err)
	}
	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM(caCertBytes); !ok {
		return nil, fmt.Errorf("parsing CA certs from %s failed", *t.CACertFile)
	}
	cert, err := tls.LoadX509KeyPair(*t.CertFile, *t.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading key pair from %q and %q: %s",
			*t.CertFile, *t.KeyFile, err)
	}
	return &tls.Config{
		RootCAs:      rootCAs,
		ClientCAs:    rootCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{cert},
	}, nil
}

// RPCServerConfig contains configuration particular to a specific RPC server
// type (e.g. RA, SA, etc)
type RPCServerConfig struct {
	Server     string // Queue name where the server receives requests
	RPCTimeout ConfigDuration
}

// OCSPUpdaterConfig provides the various window tick times and batch sizes needed
// for the OCSP (and SCT) updater
type OCSPUpdaterConfig struct {
	ServiceConfig
	DBConfig

	NewCertificateWindow     ConfigDuration
	OldOCSPWindow            ConfigDuration
	MissingSCTWindow         ConfigDuration
	RevokedCertificateWindow ConfigDuration

	NewCertificateBatchSize     int
	OldOCSPBatchSize            int
	MissingSCTBatchSize         int
	RevokedCertificateBatchSize int

	OCSPMinTimeToExpiry          ConfigDuration
	OCSPStaleMaxAge              ConfigDuration
	OldestIssuedSCT              ConfigDuration
	ParallelGenerateOCSPRequests int

	AkamaiBaseURL           string
	AkamaiClientToken       string
	AkamaiClientSecret      string
	AkamaiAccessToken       string
	AkamaiPurgeRetries      int
	AkamaiPurgeRetryBackoff ConfigDuration

	SignFailureBackoffFactor float64
	SignFailureBackoffMax    ConfigDuration

	Publisher            *GRPCClientConfig
	SAService            *GRPCClientConfig
	OCSPGeneratorService *GRPCClientConfig

	Features map[string]bool
}

// GoogleSafeBrowsingConfig is the JSON config struct for the VA's use of the
// Google Safe Browsing API.
type GoogleSafeBrowsingConfig struct {
	APIKey    string
	DataDir   string
	ServerURL string
}

// SyslogConfig defines the config for syslogging.
type SyslogConfig struct {
	StdoutLevel int
	SyslogLevel int
}

// StatsdConfig defines the config for Statsd.
type StatsdConfig struct {
	Server string
	Prefix string
}

// ConfigDuration is just an alias for time.Duration that allows
// serialization to YAML as well as JSON.
type ConfigDuration struct {
	time.Duration
}

// ErrDurationMustBeString is returned when a non-string value is
// presented to be deserialized as a ConfigDuration
var ErrDurationMustBeString = errors.New("cannot JSON unmarshal something other than a string into a ConfigDuration")

// UnmarshalJSON parses a string into a ConfigDuration using
// time.ParseDuration.  If the input does not unmarshal as a
// string, then UnmarshalJSON returns ErrDurationMustBeString.
func (d *ConfigDuration) UnmarshalJSON(b []byte) error {
	s := ""
	err := json.Unmarshal(b, &s)
	if err != nil {
		if _, ok := err.(*json.UnmarshalTypeError); ok {
			return ErrDurationMustBeString
		}
		return err
	}
	dd, err := time.ParseDuration(s)
	d.Duration = dd
	return err
}

// MarshalJSON returns the string form of the duration, as a byte array.
func (d ConfigDuration) MarshalJSON() ([]byte, error) {
	return []byte(d.Duration.String()), nil
}

// UnmarshalYAML uses the same frmat as JSON, but is called by the YAML
// parser (vs. the JSON parser).
func (d *ConfigDuration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}

	d.Duration = dur
	return nil
}

// LogDescription contains the information needed to submit certificates
// to a CT log and verify returned receipts
type LogDescription struct {
	URI string
	Key string
}

// GRPCClientConfig contains the information needed to talk to the gRPC service
type GRPCClientConfig struct {
	ServerAddresses []string
	Timeout         ConfigDuration
}

// GRPCServerConfig contains the information needed to run a gRPC service
type GRPCServerConfig struct {
	Address string `json:"address"`
	// ClientNames is a list of allowed client certificate subject alternate names
	// (SANs). The server will reject clients that do not present a certificate
	// with a SAN present on the `ClientNames` list.
	ClientNames []string `json:"clientNames"`
}

// PortConfig specifies what ports the VA should call to on the remote
// host when performing its checks.
type PortConfig struct {
	HTTPPort  int
	HTTPSPort int
	TLSPort   int
}

// CAADistributedResolverConfig specifies the HTTP client setup and interfaces
// needed to resolve CAA addresses over multiple paths
type CAADistributedResolverConfig struct {
	Timeout     ConfigDuration
	MaxFailures int
	Proxies     []string
}
