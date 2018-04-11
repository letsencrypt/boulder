package ca_config

import (
	cfsslConfig "github.com/cloudflare/cfssl/config"
	"github.com/letsencrypt/pkcs11key"

	"github.com/letsencrypt/boulder/cmd"
)

// CAConfig structs have configuration information for the certificate
// authority, including database parameters as well as controls for
// issued certificates.
type CAConfig struct {
	cmd.ServiceConfig
	cmd.DBConfig
	cmd.HostnamePolicyConfig

	GRPCCA            *cmd.GRPCServerConfig
	GRPCOCSPGenerator *cmd.GRPCServerConfig

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
	LifespanOCSP cmd.ConfigDuration
	// How long issued certificates are valid for, should match expiry field
	// in cfssl config.
	Expiry string
	// How far back certificates should be backdated, should match backdate
	// field in cfssl config.
	Backdate cmd.ConfigDuration
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

	// EnablePrecertificateFlow governs whether precertificate-based issuance
	// is enabled.
	EnablePrecertificateFlow bool

	// WeakKeyFile is the path to a JSON file containing truncated RSA modulus
	// hashes of known easily enumerable keys.
	WeakKeyFile string

	SAService *cmd.GRPCClientConfig

	// Path to directory holding orphan queue files, if not provided a orphan queue
	// is not used.
	OrphanQueueDir string

	Features map[string]bool
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
