package cmd

import (
	"io/ioutil"
	"time"

	"gopkg.in/yaml.v2"
)

// RateLimitConfig contains all application layer rate limiting policies
type RateLimitConfig struct {
	// Total number of certificates that can be extant at any given time.
	// The 2160h window, 90 days, is chosen to match certificate lifetime, since the
	// main capacity factor is how many OCSP requests we can sign with available
	// hardware.
	TotalCertificates RateLimitPolicy `yaml:"totalCertificates"`
	// Number of certificates that can be extant containing any given name.
	// These are counted by "base domain" aka eTLD+1, so any entries in the
	// overrides section must be an eTLD+1 according to the publicsuffix package.
	CertificatesPerName RateLimitPolicy `yaml:"certificatesPerName"`
	// Number of registrations that can be created per IP.
	// Note: Since this is checked before a registration is created, setting a
	// RegistrationOverride on it has no effect.
	RegistrationsPerIP RateLimitPolicy `yaml:"registrationsPerIP"`
	// Number of pending authorizations that can exist per account. Overrides by
	// key are not applied, but overrides by registration are.
	PendingAuthorizationsPerAccount RateLimitPolicy `yaml:"pendingAuthorizationsPerAccount"`
	// Number of certificates that can be extant containing a specific set
	// of DNS names.
	CertificatesPerFQDNSet RateLimitPolicy `yaml:"certificatesPerFQDNSet"`
}

// RateLimitPolicy describes a general limiting policy
type RateLimitPolicy struct {
	// How long to count items for
	Window ConfigDuration `yaml:"window"`
	// The max number of items that can be present before triggering the rate
	// limit. Zero means "no limit."
	Threshold int `yaml:"threshold"`
	// A per-key override setting different limits than the default (higher or lower).
	// The key is defined on a per-limit basis and should match the key it counts on.
	// For instance, a rate limit on the number of certificates per name uses name as
	// a key, while a rate limit on the number of registrations per IP subnet would
	// use subnet as a key.
	// Note that a zero entry in the overrides map does not mean "not limit," it
	// means a limit of zero.
	Overrides map[string]int `yaml:"overrides"`
	// A per-registration override setting. This can be used, e.g. if there are
	// hosting providers that we would like to grant a higher rate of issuance
	// than the default. If both key-based and registration-based overrides are
	// available, the registration-based on takes priority.
	RegistrationOverrides map[int64]int `yaml:"registrationOverrides"`
}

// Enabled returns true iff the RateLimitPolicy is enabled.
func (rlp *RateLimitPolicy) Enabled() bool {
	return rlp.Threshold != 0
}

// GetThreshold returns the threshold for this rate limit, taking into account
// any overrides for `key`.
func (rlp *RateLimitPolicy) GetThreshold(key string, regID int64) int {
	if override, ok := rlp.RegistrationOverrides[regID]; ok {
		return override
	}
	if override, ok := rlp.Overrides[key]; ok {
		return override
	}
	return rlp.Threshold
}

// WindowBegin returns the time that a RateLimitPolicy's window begins, given a
// particular end time (typically the current time).
func (rlp *RateLimitPolicy) WindowBegin(windowEnd time.Time) time.Time {
	return windowEnd.Add(-1 * rlp.Window.Duration)
}

// LoadRateLimitPolicies loads various rate limiting policies from a YAML
// configuration file
func LoadRateLimitPolicies(filename string) (RateLimitConfig, error) {
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		return RateLimitConfig{}, err
	}
	var rlc RateLimitConfig
	err = yaml.Unmarshal(contents, &rlc)
	if err != nil {
		return RateLimitConfig{}, err
	}
	return rlc, nil
}
