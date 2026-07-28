package cpcps

import (
	"github.com/zmap/zlint/v3/lint"
)

// Keys within the shared configuration stanza. These must match the toml
// tags on SharedConfig's fields, and are exported so that the linter
// package can emit configuration using these keys.
const (
	// GlobalConfigNamespace is the name of the TOML stanza from which
	// IssuingCAConfig is deserialized. It must match the namespace of zlint's
	// lint.Global higher-scoped configuration, which IssuingCAConfig embeds.
	GlobalConfigNamespace = "Global"
	// IssuerCertificateConfigKey configures the Issuing CA's certificate.
	IssuerCertificateConfigKey = "issuer_certificate"
	// ExistingCertificateConfigKey configures the pre-existing certificate of
	// a CA being cross-signed.
	ExistingCertificateConfigKey = "existing_certificate"
)

// globalNamespace aliases zlint's lint.Global so that IssuingCAConfig can
// embed it under an unexported field name. The promoted (unexported)
// namespace method is what routes deserialization of IssuingCAConfig to the
// shared [Global] stanza, via zlint's "higher-scoped configuration"
// mechanism; the unexported field name makes zlint's reflection-based config
// resolver skip the embedded field itself, which it could not deserialize.
type globalNamespace = lint.Global //nolint:unused // Used in SharedConfig.

// SharedConfig is the lint configuration shared by every CP/CPS profile
// lint. Rather than each lint carrying an identical stanza of its own, all of
// them declare a pointer to this struct, which zlint fills from the single
// shared [Global] stanza of the lint configuration.
type SharedConfig struct {
	globalNamespace //nolint:unused // Used by zlint, not by us.
	// IssuerCertificatePEM must hold the PEM encoding of the Issuing CA's
	// certificate, so that the profile rows requiring byte-for-byte
	// correspondence with the Issuing CA can be enforced. If it is not
	// configured, the CP/CPS profile lints fail.
	IssuerCertificatePEM string `toml:"issuer_certificate" comment:"The PEM encoding of the Issuing CA's certificate."`
	// ExistingCertificatePEM must hold the PEM encoding of the existing CA
	// Certificate upon which a cross-certificate confers a second issuance
	// path. It is read only by the cross-certified subordinate CA profile
	// lint, and only the ceremony tool ever configures it, because only the
	// ceremony tool issues cross-certificates.
	ExistingCertificatePEM string `toml:"existing_certificate" comment:"The PEM encoding of the existing CA Certificate being cross-signed."`
}

// issuerPEM returns the configured Issuing CA certificate PEM, or the empty
// string if the receiver was never configured.
func (c *SharedConfig) issuerPEM() string { //nolint:unused // Will be used in a followup PR.
	if c == nil {
		return ""
	}
	return c.IssuerCertificatePEM
}

// existingPEM returns the configured existing CA certificate PEM, or the
// empty string if the receiver was never configured.
func (c *SharedConfig) existingPEM() string { //nolint:unused // Will be used in a followup PR.
	if c == nil {
		return ""
	}
	return c.ExistingCertificatePEM
}
