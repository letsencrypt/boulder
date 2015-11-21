// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package config

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	cfsslConfig "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/config"

	// NOTE: This package should not depend on any other Boulder packages, in
	// order to avoid circular dependencies.
)

// Config stores configuration parameters that applications
// will need.  For simplicity, we just lump them all into
// one struct, and use encoding/json to read it from a file.
//
// Note: NO DEFAULTS are provided.
type Config struct {
	ActivityMonitor struct {
		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	// General
	AMQP struct {
		Server            string
		Insecure          bool
		RA                Queue
		VA                Queue
		SA                Queue
		CA                Queue
		OCSP              Queue
		Publisher         Queue
		TLS               *TLSConfig
		ReconnectTimeouts struct {
			Base ConfigDuration
			Max  ConfigDuration
		}
	}

	WFE struct {
		BaseURL       string
		ListenAddress string

		AllowOrigins []string

		CertCacheDuration           string
		CertNoCacheExpirationWindow string
		IndexCacheDuration          string
		IssuerCacheDuration         string

		ShutdownStopTimeout string
		ShutdownKillTimeout string

		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	CA CAConfig

	Monolith struct {
		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	RA struct {
		RateLimitPoliciesFilename string

		MaxConcurrentRPCServerRequests int64

		MaxContactsPerRegistration int

		// UseIsSafeDomain determines whether to call VA.IsSafeDomain
		UseIsSafeDomain bool // TODO(jmhodges): remove after va IsSafeDomain deploy

		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	SA struct {
		DBConnect string

		MaxConcurrentRPCServerRequests int64

		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	VA struct {
		UserAgent string

		PortConfig PortConfig

		MaxConcurrentRPCServerRequests int64

		GoogleSafeBrowsing *GoogleSafeBrowsingConfig

		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	SQL struct {
		SQLDebug bool
	}

	Statsd StatsdConfig

	Syslog SyslogConfig

	Revoker struct {
		DBConnect string
	}

	Mailer struct {
		Server   string
		Port     string
		Username string
		Password string

		DBConnect string

		CertLimit int
		NagTimes  []string
		// How much earlier (than configured nag intervals) to
		// send reminders, to account for the expected delay
		// before the next expiration-mailer invocation.
		NagCheckInterval string
		// Path to a text/template email template
		EmailTemplate string

		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	OCSPResponder struct {
		// Source indicates the source of pre-signed OCSP responses to be used. It
		// can be a DBConnect string or a file URL. The file URL style is used
		// when responding from a static file for intermediates and roots.
		Source string

		Path          string
		ListenAddress string
		// MaxAge is the max-age to set in the Cache-Controler response
		// header. It is a time.Duration formatted string.
		MaxAge ConfigDuration

		ShutdownStopTimeout string
		ShutdownKillTimeout string

		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	OCSPUpdater OCSPUpdaterConfig

	Publisher struct {
		MaxConcurrentRPCServerRequests int64

		// DebugAddr is the address to run the /debug handlers on.
		DebugAddr string
	}

	ExternalCertImporter struct {
		CertsToImportCSVFilename   string
		DomainsToImportCSVFilename string
		CertsToRemoveCSVFilename   string
		StatsdRate                 float32
	}

	PA PAConfig

	Common struct {
		BaseURL string
		// Path to a PEM-encoded copy of the issuer certificate.
		IssuerCert string

		DNSResolver               string
		DNSTimeout                string
		DNSAllowLoopbackAddresses bool

		CT CTConfig
	}

	CertChecker struct {
		Workers             int
		ReportDirectoryPath string
		DBConnect           string
	}

	SubscriberAgreementURL string
}

// CAConfig structs have configuration information for the certificate
// authority, including database parameters as well as controls for
// issued certificates.
type CAConfig struct {
	Profile      string
	TestMode     bool
	DBConnect    string
	SerialPrefix int
	Key          KeyConfig
	// LifespanOCSP is how long OCSP responses are valid for; It should be longer
	// than the minTimeToExpiry field for the OCSP Updater.
	LifespanOCSP string
	// How long issued certificates are valid for, should match expiry field
	// in cfssl config.
	Expiry string
	// The maximum number of subjectAltNames in a single certificate
	MaxNames int
	CFSSL    cfsslConfig.Config

	MaxConcurrentRPCServerRequests int64

	HSMFaultTimeout ConfigDuration

	// DebugAddr is the address to run the /debug handlers on.
	DebugAddr string
}

// PAConfig specifies how a policy authority should connect to its
// database, what policies it should enforce, and what challenges
// it should offer.
type PAConfig struct {
	DBConnect              string
	EnforcePolicyWhitelist bool
	Challenges             map[string]bool
}

// KeyConfig should contain either a File path to a PEM-format private key,
// or a PKCS11Config defining how to load a module for an HSM.
type KeyConfig struct {
	File   string
	PKCS11 PKCS11Config
}

// PKCS11Config defines how to load a module for an HSM.
type PKCS11Config struct {
	Module          string
	TokenLabel      string
	PIN             string
	PrivateKeyLabel string
}

// TLSConfig reprents certificates and a key for authenticated TLS.
type TLSConfig struct {
	CertFile   *string
	KeyFile    *string
	CACertFile *string
}

// Queue describes a queue name
type Queue struct {
	Server string
}

// OCSPUpdaterConfig provides the various window tick times and batch sizes needed
// for the OCSP (and SCT) updater
type OCSPUpdaterConfig struct {
	DBConnect string

	NewCertificateWindow     ConfigDuration
	OldOCSPWindow            ConfigDuration
	MissingSCTWindow         ConfigDuration
	RevokedCertificateWindow ConfigDuration

	NewCertificateBatchSize     int
	OldOCSPBatchSize            int
	MissingSCTBatchSize         int
	RevokedCertificateBatchSize int

	OCSPMinTimeToExpiry ConfigDuration
	OldestIssuedSCT     ConfigDuration

	AkamaiBaseURL           string
	AkamaiClientToken       string
	AkamaiClientSecret      string
	AkamaiAccessToken       string
	AkamaiPurgeRetries      int
	AkamaiPurgeRetryBackoff ConfigDuration

	SignFailureBackoffFactor float64
	SignFailureBackoffMax    ConfigDuration

	// DebugAddr is the address to run the /debug handlers on.
	DebugAddr string
}

// GoogleSafeBrowsingConfig is the JSON config struct for the VA's use of the
// Google Safe Browsing API.
type GoogleSafeBrowsingConfig struct {
	APIKey  string
	DataDir string
}

// SyslogConfig defines the config for syslogging.
type SyslogConfig struct {
	Network     string
	Server      string
	StdoutLevel *int
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

// PortConfig specifies what ports the VA should call to on the remote
// host when performing its checks.
type PortConfig struct {
	HTTPPort  int
	HTTPSPort int
	TLSPort   int
}

// CTConfig defines where the publisher publishes logs to.
type CTConfig struct {
	Logs                       []LogDescription `json:"logs"`
	SubmissionRetries          int              `json:"submissionRetries"`
	SubmissionBackoffString    string           `json:"submissionBackoff"`
	IntermediateBundleFilename string           `json:"intermediateBundleFilename"`
}

// LogDescription tells you how to connect to a CT log and verify its statements.
type LogDescription struct {
	ID        string
	URI       string
	PublicKey *ecdsa.PublicKey
}

type rawLogDescription struct {
	URI       string `json:"uri"`
	PublicKey string `json:"key"`
}

// UnmarshalJSON parses a simple JSON format for log descriptions.  Both the
// URI and the public key are expected to be strings.  The public key is a
// base64-encoded PKIX public key structure.
func (logDesc *LogDescription) UnmarshalJSON(data []byte) error {
	var rawLogDesc rawLogDescription
	if err := json.Unmarshal(data, &rawLogDesc); err != nil {
		return fmt.Errorf("Failed to unmarshal log description, %s", err)
	}
	logDesc.URI = rawLogDesc.URI
	// Load Key
	pkBytes, err := base64.StdEncoding.DecodeString(rawLogDesc.PublicKey)
	if err != nil {
		return fmt.Errorf("Failed to decode base64 log public key")
	}
	pk, err := x509.ParsePKIXPublicKey(pkBytes)
	if err != nil {
		return fmt.Errorf("Failed to parse log public key")
	}
	ecdsaKey, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("Failed to unmarshal log description for %s, unsupported public key type", logDesc.URI)
	}
	logDesc.PublicKey = ecdsaKey

	// Generate key hash for log ID
	pkHash := sha256.Sum256(pkBytes)
	logDesc.ID = base64.StdEncoding.EncodeToString(pkHash[:])
	if len(logDesc.ID) != 44 {
		return fmt.Errorf("Invalid log ID length [%d]", len(logDesc.ID))
	}

	return nil
}
