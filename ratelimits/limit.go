package ratelimits

import (
	"fmt"
	"os"
	"strings"

	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/strictyaml"
)

type limit struct {
	// Burst specifies maximum concurrent allowed requests at any given time. It
	// must be greater than zero.
	Burst int64

	// Count is the number of requests allowed per period. It must be greater
	// than zero.
	Count int64

	// Period is the duration of time in which the count (of requests) is
	// allowed. It must be greater than zero.
	Period config.Duration

	// emissionInterval is the interval, in nanoseconds, at which tokens are
	// added to a bucket (period / count). This is also the steady-state rate at
	// which requests can be made without being denied even once the burst has
	// been exhausted. This is precomputed to avoid doing the same calculation
	// on every request.
	emissionInterval int64

	// burstOffset is the duration of time, in nanoseconds, it takes for a
	// bucket to go from empty to full (burst * (period / count)). This is
	// precomputed to avoid doing the same calculation on every request.
	burstOffset int64

	// isOverride is true if this limit is an override limit, false if it is a
	// default limit.
	isOverride bool
}

func precomputeLimit(l limit) limit {
	l.emissionInterval = l.Period.Nanoseconds() / l.Count
	l.burstOffset = l.emissionInterval * l.Burst
	return l
}

func validateLimit(l limit) error {
	if l.Burst <= 0 {
		return fmt.Errorf("invalid burst '%d', must be > 0", l.Burst)
	}
	if l.Count <= 0 {
		return fmt.Errorf("invalid count '%d', must be > 0", l.Count)
	}
	if l.Period.Duration <= 0 {
		return fmt.Errorf("invalid period '%s', must be > 0", l.Period)
	}
	return nil
}

type limits map[string]limit

// loadLimits marshals the YAML file at path into a map of limis.
func loadLimits(path string) (limits, error) {
	lm := make(limits)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	err = strictyaml.Unmarshal(data, &lm)
	if err != nil {
		return nil, err
	}
	return lm, nil
}

// parseOverrideNameId is broken out for ease of testing.
func parseOverrideNameId(key string) (Name, string, error) {
	if !strings.Contains(key, ":") {
		// Avoids a potential panic in strings.SplitN below.
		return Unknown, "", fmt.Errorf("invalid override %q, must be formatted 'name:id'", key)
	}
	nameAndId := strings.SplitN(key, ":", 2)
	nameStr := nameAndId[0]
	if nameStr == "" {
		return Unknown, "", fmt.Errorf("empty name in override %q, must be formatted 'name:id'", key)
	}

	name, ok := stringToName[nameStr]
	if !ok {
		return Unknown, "", fmt.Errorf("unrecognized name %q in override limit %q, must be one of %v", nameStr, key, limitNames)
	}
	id := nameAndId[1]
	if id == "" {
		return Unknown, "", fmt.Errorf("empty id in override %q, must be formatted 'name:id'", key)
	}
	return name, id, nil
}

// loadAndParseOverrideLimits loads override limits from YAML, validates them,
// and parses them into a map of limits keyed by 'Name:id'.
func loadAndParseOverrideLimits(path string) (limits, error) {
	fromFile, err := loadLimits(path)
	if err != nil {
		return nil, err
	}
	parsed := make(limits, len(fromFile))

	for k, v := range fromFile {
		err = validateLimit(v)
		if err != nil {
			return nil, fmt.Errorf("validating override limit %q: %w", k, err)
		}
		name, id, err := parseOverrideNameId(k)
		if err != nil {
			return nil, fmt.Errorf("parsing override limit %q: %w", k, err)
		}
		err = validateIdForName(name, id)
		if err != nil {
			return nil, fmt.Errorf(
				"validating name %s and id %q for override limit %q: %w", name, id, k, err)
		}
		if name == CertificatesPerFQDNSetPerAccount {
			// FQDNSet hashes are not a nice thing to ask for in a config file,
			// so we allow the user to specify a comma-separated list of FQDNs
			// and compute the hash here.
			regIdDomains := strings.SplitN(id, ":", 2)
			if len(regIdDomains) != 2 {
				// Should never happen, the Id format was validated above.
				return nil, fmt.Errorf("invalid override limit %q, must be formatted 'name:id'", k)
			}
			regId := regIdDomains[0]
			domains := strings.Split(regIdDomains[1], ",")
			fqdnSet := core.HashNames(domains)
			id = fmt.Sprintf("%s:%s", regId, fqdnSet)
		}
		v.isOverride = true
		parsed[bucketKey(name, id)] = precomputeLimit(v)
	}
	return parsed, nil
}

// loadAndParseDefaultLimits loads default limits from YAML, validates them, and
// parses them into a map of limits keyed by 'Name'.
func loadAndParseDefaultLimits(path string) (limits, error) {
	fromFile, err := loadLimits(path)
	if err != nil {
		return nil, err
	}
	parsed := make(limits, len(fromFile))

	for k, v := range fromFile {
		err := validateLimit(v)
		if err != nil {
			return nil, fmt.Errorf("parsing default limit %q: %w", k, err)
		}
		name, ok := stringToName[k]
		if !ok {
			return nil, fmt.Errorf("unrecognized name %q in default limit, must be one of %v", k, limitNames)
		}
		parsed[nameToEnumString(name)] = precomputeLimit(v)
	}
	return parsed, nil
}
