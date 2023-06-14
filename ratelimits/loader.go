package ratelimits

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

func validateLimits(limits map[string]RateLimit) error {
	for k, v := range limits {
		if v.Burst <= 0 {
			return fmt.Errorf("burst must be greater than zero: %q", k)
		}
		if v.Count <= 0 {
			return fmt.Errorf("count must be greater than zero: %q", k)
		}
		if v.Period <= 0 {
			return fmt.Errorf("period must be greater than zero: %q", k)
		}
		if strings.Contains(k, ":") {
			// These limits are overrides.
			p := strings.Split(k, ":")[0]
			if p == "" {
				return fmt.Errorf("invalid prefix: %q", k)
			}
			// Ensure prefix is a valid limit type.
			if !isPrefix(p) {
				return fmt.Errorf("prefix %q of override %q is not a recognized limit type", p, k)
			}
		}
	}
	return nil
}

// loadLimits is a helper that loads the YAML limits file at the given path and
// returns a map of limits. It can be called for default or override limits.
func loadLimits(path string) (map[string]RateLimit, error) {
	limits := make(map[string]RateLimit)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(data, &limits)
	if err != nil {
		return nil, err
	}
	err = validateLimits(limits)
	if err != nil {
		return nil, err
	}
	return limits, nil
}
