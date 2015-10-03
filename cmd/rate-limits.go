package cmd

import (
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/yaml.v2"
	"io/ioutil"
	"time"
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
}

// RateLimitPolicy describes a general limiting policy
type RateLimitPolicy struct {
	// How long to count items for
	Window ConfigDuration `yaml:"window"`
	// The max number of items that can be present before triggering the rate
	// limit. Zero means "no limit."
	Threshold int64 `yaml:"threshold"`
	// A per-key override granting higher limits. The key is defined on a
	// per-limit basis and should match the key it counts on. For instance, a rate
	// limit on the number of certificates per name uses name as a key, whilte a
	// rate limit on the number of registrations per IP subnet would use subnet as
	// a key.
	// Note that a zero entry in the overrides map does not mean "not limit," it
	// means a limit of zero.
	Overrides map[string]int64 `yaml:"overrides"`
}

// Enabled returns true iff the RateLimitPolicy is enabled.
func (rlp *RateLimitPolicy) Enabled() bool {
	return rlp.Threshold != 0
}

// GetThreshold returns the threshold for this rate limit, taking into account
// any overrides for `key`.
func (rlp *RateLimitPolicy) GetThreshold(key string) int64 {
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
