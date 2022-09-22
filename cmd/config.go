package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/letsencrypt/boulder/core"
)

// PasswordConfig contains a path to a file containing a password.
type PasswordConfig struct {
	PasswordFile string
}

// Pass returns a password, extracted from the PasswordConfig's PasswordFile
func (pc *PasswordConfig) Pass() (string, error) {
	// Make PasswordConfigs optional, for backwards compatibility.
	if pc.PasswordFile == "" {
		return "", nil
	}
	contents, err := os.ReadFile(pc.PasswordFile)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(contents), "\n"), nil
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

// URL returns the DBConnect URL represented by this DBConfig object, either
// loading it from disk or returning a default value. Leading and trailing
// whitespace is stripped.
func (d *DBConfig) URL() (string, error) {
	if d.DBConnectFile != "" {
		url, err := os.ReadFile(d.DBConnectFile)
		return strings.TrimSpace(string(url)), err
	}
	return d.DBConnect, nil
}

// DSNAddressAndUser returns the Address and User of the DBConnect DSN from
// this object.
func (d *DBConfig) DSNAddressAndUser() (string, string, error) {
	dsnStr, err := d.URL()
	if err != nil {
		return "", "", fmt.Errorf("failed to load DBConnect URL: %s", err)
	}
	config, err := mysql.ParseDSN(dsnStr)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse DSN from the DBConnect URL: %s", err)
	}
	return config.Addr, config.User, nil
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
			return fmt.Errorf("invalid challenge in PA config: %s", c)
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
	caCertBytes, err := os.ReadFile(*t.CACertFile)
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

// SyslogConfig defines the config for syslogging.
// 3 means "error", 4 means "warning", 6 is "info" and 7 is "debug".
// Configuring a given level causes all messages at that level and below to
// be logged.
type SyslogConfig struct {
	// When absent or zero, this causes no logs to be emitted on stdout/stderr.
	// Errors and warnings will be emitted on stderr if the configured level
	// allows.
	StdoutLevel int
	// When absent or zero, this defaults to logging all messages of level 6
	// or below. To disable syslog logging entirely, set this to -1.
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
	err := unmarshal(&s)
	if err != nil {
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
	// ServerAddress is a single host:port combination that the gRPC client
	// will, if necessary, resolve via DNS and then connect to. This field
	// cannot be used in combination with `ServerIPAddresses` field.
	ServerAddress string
	// ServerIPAddresses is a list of IPv4/6 addresses, in the format IPv4:port,
	// [IPv6]:port or :port, that the gRPC client will connect to. Note that the
	// server's certificate will be validated against these IP addresses, so
	// they must be present in the SANs of the server certificate. This field
	// cannot be used in combination with `ServerAddress`.
	ServerIPAddresses []string
	Timeout           ConfigDuration
}

// GRPCServerConfig contains the information needed to run a gRPC service
type GRPCServerConfig struct {
	Address string `json:"address"`
	// ClientNames is a list of allowed client certificate subject alternate names
	// (SANs). The server will reject clients that do not present a certificate
	// with a SAN present on the `ClientNames` list.
	ClientNames []string `json:"clientNames"`
	// MaxConnectionAge specifies how long a connection may live before the server sends a GoAway to the
	// client. Because gRPC connections re-resolve DNS after a connection close,
	// this controls how long it takes before a client learns about changes to its
	// backends.
	// https://pkg.go.dev/google.golang.org/grpc/keepalive#ServerParameters
	MaxConnectionAge ConfigDuration
}

// PortConfig specifies what ports the VA should call to on the remote
// host when performing its checks.
type PortConfig struct {
	HTTPPort  int
	HTTPSPort int
	TLSPort   int
}

// OpenTelemetryConfig provides config options for the OpenTelemetry library
// The configuration parameters are documented here:
// https://github.com/open-telemetry/opentelemetry-go/tree/main/exporters/otlp/otlptrace#configuration
type OpenTelemetryConfig struct {
	// Endpoint to connect to with the OTLP protocol
	OTLPEndpoint string

	// SampleRatio is the ratio of traces to sample.
	// Set to something between 0 and 1, where 1 is sampling all traces.
	// See otel trace.TraceIDRatioBased for details.
	SampleRatio float64

	// StdoutExporter prints traces to stdout if this is true.
	// Useful in test or dev environments without an OTLP endpoint available
	StdoutExporter bool

	// We will probably want more configuration parameters
	// Note that the oltptrace exporter also supports using environment
	// variables for configuration, but are overridden by the values that are
	// present here.
}

// BeelineConfig is deprecated and will be removed in a future release.
// Beeline has been replaced with OpenTelemetry tracing.
type BeelineConfig struct {
	// WriteKey deprecated.
	WriteKey PasswordConfig
	// Dataset deprecated.
	Dataset string
	// ServiceName deprecated.
	ServiceName string
	// SampleRate deprecated.
	SampleRate uint32
	// Mute deprecated.
	Mute bool
}
