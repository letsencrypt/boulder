package ratelimits

import (
	"fmt"
	"os"
	"strings"

	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/strictyaml"
)

type rateLimit struct {
	// Burst specifies maximum concurrent (allowed) requests at any given time.
	// It MUST be greater than zero.
	Burst int64

	// Count is the number of requests allowed per period. It MUST be greater
	// than zero.
	Count int64

	// Period is the duration of time in which the count (of requests) is
	// allowed. It MUST be greater than zero.
	Period config.Duration
}

type limits map[string]rateLimit

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (l *limits) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var lm map[string]rateLimit
	err := unmarshal(&lm)
	if err != nil {
		return err
	}
	for k, v := range lm {
		if v.Burst <= 0 {
			return fmt.Errorf("invalid burst %q !<= 0", k)
		}
		if v.Count <= 0 {
			return fmt.Errorf("invalid count %q !<= 0", k)
		}
		if v.Period.Duration <= 0 {
			return fmt.Errorf("invalid period %q !<= 0", k)
		}
		if !strings.Contains(k, ":") {
			// Default limit
			nameInt, ok := stringToName[k]
			if !ok {
				return fmt.Errorf(
					"unrecognized limit %q, valid names=%q", k, limitNames)
			}
			delete(lm, k)
			lm[nameToIntString(Name(nameInt))] = v
		} else {
			// Override limit
			nameAndId := strings.Split(k, ":")
			name := nameAndId[0]
			if name == "" {
				return fmt.Errorf("empty limit name %q, must be 'name:id'", k)
			}
			id := nameAndId[1]
			if id == "" {
				return fmt.Errorf("empty id %q, must be 'name:id'", k)
			}

			nameInt, ok := stringToName[name]
			if !ok {
				return fmt.Errorf(
					"unrecognized limit %q, valid names=%q", k, limitNames)
			}
			delete(lm, k)
			lm[nameToIntString(Name(nameInt))+":"+id] = v
		}
	}
	*l = limits(lm)
	return nil
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
	return lm, nil
}
