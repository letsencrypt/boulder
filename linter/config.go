package linter

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/pelletier/go-toml"
	"github.com/zmap/zlint/v3/lint"

	"github.com/letsencrypt/boulder/linter/lints/cpcps"
)

// Config is a validated, in-memory zlint lint configuration. The zero value
// is an empty configuration.
type Config struct {
	// The zlint package only accepts configuration as TOML (and re-parses it on
	// every lint pass anyway), so we store the config in zlint's format.
	toml string
}

// LoadConfigFile reads and validates a zlint TOML config file. An empty path
// yields an empty Config. It is an error for the file to set the shared
// configuration keys read by the CP/CPS profile lints: those are derived from
// certificates via WithIssuer and WithExisting instead.
func LoadConfigFile(path string) (Config, error) {
	if path == "" {
		return Config{}, nil
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("failed to read zlint config file: %w", err)
	}
	tree, err := toml.LoadBytes(contents)
	if err != nil {
		return Config{}, fmt.Errorf("failed to parse zlint config file %q: %w", path, err)
	}
	for _, key := range []string{cpcps.IssuerCertificateConfigKey, cpcps.ExistingCertificateConfigKey} {
		if tree.HasPath([]string{cpcps.GlobalConfigNamespace, key}) {
			return Config{}, fmt.Errorf("zlint config file %q must not set %s.%s: it is derived from the issuer certificate", path, cpcps.GlobalConfigNamespace, key)
		}
	}
	return Config{toml: string(contents)}, nil
}

// WithIssuer returns a copy of the Config with a stanza holding the PEM of the
// issuer's certificate. This is necessary for the CP/CPS profile lints, which
// check that certain fields of the certificate being linted match the issuer. A
// nil issuer, or one with no raw DER bytes (i.e. a to-be-signed template rather
// than a real certificate, as in a self-signed root ceremony), returns the
// Config unchanged.
func (c Config) WithIssuer(issuer *x509.Certificate) (Config, error) {
	if issuer == nil || len(issuer.Raw) == 0 {
		return c, nil
	}
	issuerPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Raw}))
	return c.set(cpcps.IssuerCertificateConfigKey, issuerPEM)
}

// WithExisting returns a copy of the Config with a stanza holding the PEM of
// the pre-existing certificate which is being cross-signed. This is necessary
// for the CP/CPS Cross-Certified Subordinate CA Certificate lint. It is only
// used by the ceremony tool. A nil existing certificate, or one with no raw DER
// bytes, returns the Config unchanged.
func (c Config) WithExisting(existing *x509.Certificate) (Config, error) {
	if existing == nil || len(existing.Raw) == 0 {
		return c, nil
	}
	existingPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: existing.Raw}))
	return c.set(cpcps.ExistingCertificateConfigKey, existingPEM)
}

// set returns a copy of the Config with the given key (inside the Global
// namespace) set to the given value.
func (c Config) set(key string, value string) (Config, error) {
	tree, err := toml.Load(c.toml)
	if err != nil {
		return Config{}, fmt.Errorf("failed to parse zlint config: %w", err)
	}
	tree.SetPath([]string{cpcps.GlobalConfigNamespace, key}, value)
	tomlString, err := tree.ToTomlString()
	if err != nil {
		return Config{}, fmt.Errorf("failed to serialize zlint config: %w", err)
	}
	return Config{toml: tomlString}, nil
}

// build converts the Config into the lint.Configuration that zlint consumes.
func (c Config) build() (lint.Configuration, error) {
	return lint.NewConfigFromString(c.toml)
}

// configuredRegistry implements the zlint.Registry interface by embedding a
// normal Registry but replacing the GetConfiguration method with one that
// returns our own config. This allows us to easily supply different config
// objects for each lint pass without having to modify the underlying registry.
type configuredRegistry struct {
	lint.Registry
	config lint.Configuration
}

// GetConfiguration returns the config associated with this registry. It
// satisfies the zlint.Registry interface.
func (r configuredRegistry) GetConfiguration() lint.Configuration {
	return r.config
}

// NewRegistryWithConfig is like NewRegistry, but the returned registry also
// carries the contents of the given Config.
func NewRegistryWithConfig(skipLints []string, config Config) (lint.Registry, error) {
	reg, err := NewRegistry(skipLints)
	if err != nil {
		return nil, err
	}
	lintConfig, err := config.build()
	if err != nil {
		return nil, err
	}
	return configuredRegistry{reg, lintConfig}, nil
}
