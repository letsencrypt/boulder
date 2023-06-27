package ratelimits

import (
	"fmt"
	"os"
	"strings"

	"github.com/letsencrypt/boulder/config"
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
func parseOverrideNameId(key string) (*Name, string, error) {
	if !strings.Contains(key, ":") {
		// Avoids a potential panic in strings.SplitN below.
		return nil, "", fmt.Errorf("invalid override %q, must be formatted 'name:id'", key)
	}
	nameAndId := strings.SplitN(key, ":", 2)
	nameStr := nameAndId[0]
	if nameStr == "" {
		return nil, "", fmt.Errorf("empty name in override %q, must be formatted 'name:id'", key)
	}

	name, ok := stringToName[nameStr]
	if !ok {
		return nil, "", fmt.Errorf("unrecognized name %q in override limit %q, must be one of %v", nameStr, key, limitNames)
	}
	id := nameAndId[1]
	if id == "" {
		return nil, "", fmt.Errorf("empty id in override %q, must be formatted 'name:id'", key)
	}
	return &name, id, nil
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
		err = validateIdForName(*name, id)
		if err != nil {
			return nil, fmt.Errorf(
				"validating name %s and id %q for override limit %q: %w", nameToString[*name], id, k, err)
		}
		parsed[bucketKey(*name, id)] = v
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
		parsed[nameToEnumString(name)] = v
	}
	return parsed, nil
}
