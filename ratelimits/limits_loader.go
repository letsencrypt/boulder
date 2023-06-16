package ratelimits

import (
	"fmt"
	"os"
	"strings"

	"github.com/letsencrypt/boulder/strictyaml"
)

type limits map[string]RateLimit

func (l *limits) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var lm map[string]RateLimit
	err := unmarshal(&lm)
	if err != nil {
		return err
	}
	for k, v := range lm {
		if v.Burst <= 0 {
			return fmt.Errorf("invalid burst %q !>= 0", k)
		}
		if v.Count <= 0 {
			return fmt.Errorf("invalid count %q !>= 0", k)
		}
		if v.Period.Duration <= 0 {
			return fmt.Errorf("invalid period %q !>= 0", k)
		}
		if strings.Contains(k, ":") {
			// Override limit
			prefixId := strings.Split(k, ":")
			prefix := prefixId[0]
			if prefix == "" {
				return fmt.Errorf("empty prefix %q must be prefix:id", k)
			}
			id := prefixId[1]
			if id == "" {
				return fmt.Errorf("empty id %q must be prefix:id", k)
			}

			prefixInt, ok := stringToPrefix[prefix]
			if !ok {
				return fmt.Errorf("prefix %q not of type Prefix", k)
			}
			delete(lm, k)
			lm[prefixToIntString(Prefix(prefixInt))+":"+id] = v
		} else {
			// Default limit
			prefixInt, ok := stringToPrefix[k]
			if !ok {
				return fmt.Errorf("prefix %q not of type Prefix", k)
			}
			delete(lm, k)
			lm[prefixToIntString(Prefix(prefixInt))] = v
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
