package ratelimits

import (
	"fmt"
	"net"
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
			"unrecognized limit %q, must be one in %q", k, limitNames)
	}
	return nameToIntString(name), nil
}

func parseOverrideNameId(k string) (string, string, error) {
	nameAndId := strings.SplitN(k, ":", 2)
	nameStr := nameAndId[0]
	if nameStr == "" {
		return "", "", fmt.Errorf("empty name in override %q, must be 'name:id'", k)
	}
	id := nameAndId[1]
	if id == "" {
		return "", "", fmt.Errorf("empty id in override %q, must be 'name:id'", k)
	}

	name, ok := stringToName[nameStr]
	if !ok {
		return "", "", fmt.Errorf(
			"unrecognized limit %q, must be one in %q", nameStr, limitNames)
	}

	if ipv4AddrNameId(name) {
		ip := net.ParseIP(id)
		if ip == nil || ip.To4() == nil {
			return "", "", fmt.Errorf(
				"invalid addr %q, in override %q, must be IPv4", id, k)
		}
	}

	if ipv6RangeNameId(name) {
		_, net, err := net.ParseCIDR(id)
		if err != nil {
			return "", "", fmt.Errorf(
				"invalid id %q, in override %q, must be IPv6 CIDR range", id, k)
		}
		if net.IP.To4() != nil {
			return "", "", fmt.Errorf(
				"invalid CIDR %q, in override %q, must be IPv6 CIDR range", id, k)
		}
		ones, _ := net.Mask.Size()
		if ones != 48 {
			return "", "", fmt.Errorf(
				"invalid range %q, in override %q, must be /48,", id, k)
		}
	}
	return nameToIntString(name), id, nil
}

// UnmarshalYAML implements go-yaml's yaml.Unmarshaler interface. This method
// will be called by strictyaml.Unmarshal() when unmarshaling the limits map. It
// validates the limits map and interns the limit names to their integer
// representation and returns an error if any of the limits are invalid.
func (l *limits) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var file map[string]limit

	err := unmarshal(&file)
	if err != nil {
		return err
	}
	final := make(map[string]limit, len(file))

	for k, v := range file {
		if v.Burst <= 0 {
			return fmt.Errorf("invalid burst %q, in limit %q, must be <= 0", v.Burst, k)
		}
		if v.Count <= 0 {
			return fmt.Errorf("invalid count %q, in limit %q, must be <= 0", v.Count, k)
		}
		if v.Period.Duration <= 0 {
			return fmt.Errorf("invalid count %q, in limit %q, must be <= 0", v.Period, k)
		}
		if strings.Contains(k, ":") {
			// Override limit
			name, id, err := parseOverrideNameId(k)
			if err != nil {
				return err
			}
			final[name+":"+id] = v
		} else {
			// Default limit
			name, err := parseDefaultName(k)
			if err != nil {
				return err
			}
			final[name] = v
		}
	}
	*l = limits(final)
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
