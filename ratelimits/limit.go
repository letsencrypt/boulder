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

type limits map[string]limit

func parseDefaultName(k string) (string, error) {
	name, ok := stringToName[k]
	if !ok {
		return "", fmt.Errorf(
			"unrecognized limit %q, must be one of %v", k, limitNames)
	}
	return nameToEnumString(name), nil
}

func parseOverrideNameId(k string) (string, string, error) {
	nameAndId := strings.SplitN(k, ":", 2)
	nameStr := nameAndId[0]
	if nameStr == "" {
		return "", "", fmt.Errorf("empty name in override %q, must be formatted 'name:id'", k)
	}
	id := nameAndId[1]
	if id == "" {
		return "", "", fmt.Errorf("empty id in override %q, must be formatted 'name:id'", k)
	}

	name, ok := stringToName[nameStr]
	if !ok {
		return "", "", fmt.Errorf(
			"unrecognized limit %q, must be one of %v", nameStr, limitNames)
	}
	err := validateIdForName(name, id)
	if err != nil {
		return "", "", fmt.Errorf("parsing limit %q: %w", k, err)
	}
	return nameToEnumString(name), id, nil
}

// parseLimits parses the limits loaded from YAML, validates them, and returns a
// map of limits with the limit names interned to their enum values.
func parseLimits(fromFile limits) (limits, error) {
	parsed := make(map[string]limit, len(fromFile))
	for k, v := range fromFile {
		if v.Burst <= 0 {
			return nil, fmt.Errorf("invalid burst %q, in limit %q, must be <= 0", v.Burst, k)
		}
		if v.Count <= 0 {
			return nil, fmt.Errorf("invalid count %q, in limit %q, must be <= 0", v.Count, k)
		}
		if v.Period.Duration <= 0 {
			return nil, fmt.Errorf("invalid count %q, in limit %q, must be <= 0", v.Period, k)
		}
		if strings.Contains(k, ":") {
			// Override limit
			name, id, err := parseOverrideNameId(k)
			if err != nil {
				return nil, err
			}
			parsed[name+":"+id] = v
		} else {
			// Default limit
			name, err := parseDefaultName(k)
			if err != nil {
				return nil, err
			}
			parsed[name] = v
		}
	}
	return parsed, nil
}

// loadLimits loads both default and override limits from YAML.
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
	return parseLimits(lm)
}
