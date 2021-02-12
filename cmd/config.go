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

	// MaxOpenConns sets the maximum number of open connections to the
	// database. If MaxIdleConns is greater than 0 and MaxOpenConns is
	// less than MaxIdleConns, then MaxIdleConns will be reduced to
	// match the new MaxOpenConns limit. If n < 0, then there is no
	// limit on the number of open connections.
	MaxOpenConns int

	// MaxIdleConns sets the maximum number of connections in the idle
	// connection pool. If MaxOpenConns is greater than 0 but less than
	// MaxIdleConns, then MaxIdleConns will be reduced to match the
	// MaxOpenConns limit. If n < 0, no idle connections are retained.
	MaxIdleConns int

	// ConnMaxLifetime sets the maximum amount of time a connection may
	// be reused. Expired connections may be closed lazily before reuse.
	// If d < 0, connections are not closed due to a connection's age.
	ConnMaxLifetime ConfigDuration

	// ConnMaxIdleTime sets the maximum amount of time a connection may
	// be idle. Expired connections may be closed lazily before reuse.
	// If d < 0, connections are not closed due to a connection's idle
	// time.
	ConnMaxIdleTime ConfigDuration
}

// DeprecatedDBConfig is a temporary type that acts as a receiver for
// fields unmarshalled from the root of a component's JSON config
// (deprecated).
// TODO(#5275): Remove once all configs in dev, staging and prod
// have been updated to contain the `dbconfig` field
type DeprecatedDBConfig DBConfig

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

// DefaultDBConfig is a temporary helper function that copies DBConfig
// fields unmarshalled from the root of a component's JSON config
// (deprecated) to the named `DBConfig` substruct of the service config.
// TODO(#5275): Remove once all configs in dev, staging and prod
// have been updated to contain the `dbconfig` field
func DefaultDBConfig(dbConfig *DBConfig, databaseConfig *DeprecatedDBConfig) {
	if dbConfig.DBConnectFile != "" {
		// dbConfig was specified properly in the JSON return early
		return
	}
	dbConfig.DBConnect = databaseConfig.DBConnect
	dbConfig.DBConnectFile = databaseConfig.DBConnectFile
	dbConfig.MaxOpenConns = databaseConfig.MaxOpenConns
	dbConfig.MaxIdleConns = databaseConfig.MaxIdleConns
	dbConfig.ConnMaxIdleTime = databaseConfig.ConnMaxIdleTime
	dbConfig.ConnMaxLifetime = databaseConfig.ConnMaxLifetime
}

type SMTPConfig struct {
	PasswordConfig
	Server   string
	Port     string
	Username string
}

// PAConfig specifies how a policy authority should connect to its
// database, what policies it should enforce, and what challenges
// it should offer.
type PAConfig struct {
	DBConfig
	Challenges map[core.AcmeChallenge]bool
}

// CheckChallenges checks whether the list of challenges in the PA config
// actually contains valid challenge names
func (pc PAConfig) CheckChallenges() error {
	if len(pc.Challenges) == 0 {
		return errors.New("empty challenges map in the Policy Authority config is not allowed")
	}
	for c := range pc.Challenges {
		if !c.IsValid() {
			return fmt.Errorf("Invalid challenge in PA config: %s", c)
		}
	}
	return nil
}

// HostnamePolicyConfig specifies a file from which to load a policy regarding
// what hostnames to issue for.
type HostnamePolicyConfig struct {
	HostnamePolicyFile string
}

// TLSConfig represents certificates and a key for authenticated TLS.
type TLSConfig struct {
	CertFile   *string
	KeyFile    *string
	CACertFile *string
}

// Load reads and parses the certificates and key listed in the TLSConfig, and
// returns a *tls.Config suitable for either client or server use.
func (t *TLSConfig) Load() (*tls.Config, error) {
	if t == nil {
		return nil, fmt.Errorf("nil TLS section in config")
	}
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
		// Set the only acceptable TLS version to 1.2 and the only acceptable cipher suite
		// to ECDHE-RSA-CHACHA20-POLY1305.
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305},
	}, nil
}

// RPCServerConfig contains configuration particular to a specific RPC server
// type (e.g. RA, SA, etc)
type RPCServerConfig struct {
	Server     string // Queue name where the server receives requests
	RPCTimeout ConfigDuration
}

// SyslogConfig defines the config for syslogging.
type SyslogConfig struct {
	StdoutLevel int
	SyslogLevel int
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
		var jsonUnmarshalTypeErr *json.UnmarshalTypeError
		if errors.As(err, &jsonUnmarshalTypeErr) {
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

// UnmarshalYAML uses the same format as JSON, but is called by the YAML
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

// GRPCClientConfig contains the information needed to talk to the gRPC service
type GRPCClientConfig struct {
	ServerAddress string
	Timeout       ConfigDuration
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
