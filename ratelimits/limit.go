package ratelimits

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/strictyaml"
	"gopkg.in/yaml.v3"
)

// errLimitDisabled indicates that the limit name specified is valid but is not
// currently configured.
var errLimitDisabled = errors.New("limit disabled")

// LimitConfig defines the exportable configuration for a rate limit or a rate
// limit override, without a `limit`'s internal fields.
//
// The zero value of this struct is invalid, because some of the fields must be
// greater than zero.
type LimitConfig struct {
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

type LimitConfigs map[string]*LimitConfig

// Limit defines the configuration for a rate Limit or a rate Limit override.
//
// The zero value of this struct is invalid, because some of the fields must be
// greater than zero. It and several of its fields are exported to support admin
// tooling used during the migration from overrides.yaml to the overrides
// database table.
type Limit struct {
	// Burst specifies maximum concurrent allowed requests at any given time. It
	// must be greater than zero.
	Burst int64

	// Count is the number of requests allowed per period. It must be greater
	// than zero.
	Count int64

	// Period is the duration of time in which the count (of requests) is
	// allowed. It must be greater than zero.
	Period config.Duration

	// Name is the Name of the limit. It must be one of the Name enums defined
	// in this package.
	Name Name

	// Comment is an optional field that can be used to provide additional
	// context for an override. It is not used for default limits.
	Comment string

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

	// isOverride is true if the limit is an override.
	isOverride bool
}

// precompute calculates the emissionInterval and burstOffset for the limit.
func (l *Limit) precompute() {
	l.emissionInterval = l.Period.Nanoseconds() / l.Count
	l.burstOffset = l.emissionInterval * l.Burst
}

func ValidateLimit(l *Limit) error {
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

type limits map[string]*Limit

// loadDefaults marshals the defaults YAML file at path into a map of limits.
func loadDefaults(path string) (LimitConfigs, error) {
	lm := make(LimitConfigs)
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

type overrideID struct {
	Id string `yaml:"id"`
	// Comment is an optional field that can be used to provide additional
	// context for the override.
	Comment string `yaml:"comment,omitempty"`
}

type overrideYAML struct {
	LimitConfig `yaml:",inline"`
	// Ids is a list of ids that this override applies to.
	Ids []overrideID `yaml:"ids"`
}

type overridesYAML []map[string]overrideYAML

// loadOverrides marshals the YAML file at path into a map of overrides.
func loadOverrides(path string) (overridesYAML, error) {
	ov := overridesYAML{}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	err = strictyaml.Unmarshal(data, &ov)
	if err != nil {
		return nil, err
	}
	return ov, nil
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

// parseOverrideNameEnumId is like parseOverrideNameId, but it expects the
// key to be formatted as 'name:id', where 'name' is a Name enum string and 'id'
// is a string identifier. It returns an error if either part is missing or invalid.
func parseOverrideNameEnumId(key string) (Name, string, error) {
	if !strings.Contains(key, ":") {
		// Avoids a potential panic in strings.SplitN below.
		return Unknown, "", fmt.Errorf("invalid override %q, must be formatted 'name:id'", key)
	}
	nameStrAndId := strings.SplitN(key, ":", 2)
	if len(nameStrAndId) != 2 {
		return Unknown, "", fmt.Errorf("invalid override %q, must be formatted 'name:id'", key)
	}

	nameInt, err := strconv.Atoi(nameStrAndId[0])
	if err != nil {
		return Unknown, "", fmt.Errorf("invalid name %q in override limit %q, must be an integer", nameStrAndId[0], key)
	}
	name := Name(nameInt)
	if !name.isValid() {
		return Unknown, "", fmt.Errorf("invalid name %q in override limit %q, must be one of %v", nameStrAndId[0], key, limitNames)

	}
	return name, nameStrAndId[1], nil
}

// parseOverrideLimits validates a YAML list of override limits. It must be
// formatted as a list of maps, where each map has a single key representing the
// limit name and a value that is a map containing the limit fields and an
// additional 'ids' field that is a list of ids that this override applies to.
func parseOverrideLimits(newOverridesYAML overridesYAML) (limits, error) {
	parsed := make(limits)

	for _, ov := range newOverridesYAML {
		for k, v := range ov {
			name, ok := stringToName[k]
			if !ok {
				return nil, fmt.Errorf("unrecognized name %q in override limit, must be one of %v", k, limitNames)
			}

			for _, entry := range v.Ids {
				id := entry.Id
				err := validateIdForName(name, id)
				if err != nil {
					return nil, fmt.Errorf(
						"validating name %s and id %q for override limit %q: %w", name, id, k, err)
				}
				if name == CertificatesPerFQDNSet {
					// FQDNSet hashes are not a nice thing to ask for in a
					// config file, so we allow the user to specify a
					// comma-separated list of FQDNs and compute the hash here.
					id = fmt.Sprintf("%x", hashNames(strings.Split(id, ",")))

				}

				lim := &Limit{
					Burst:      v.Burst,
					Count:      v.Count,
					Period:     v.Period,
					Name:       name,
					Comment:    entry.Comment,
					isOverride: true,
				}
				lim.precompute()

				err = ValidateLimit(lim)
				if err != nil {
					return nil, fmt.Errorf("validating override limit %q: %w", k, err)
				}
				parsed[joinWithColon(name.EnumString(), id)] = lim
			}
		}
	}
	return parsed, nil
}

// parseDefaultLimits validates a map of default limits and rekeys it by 'Name'.
func parseDefaultLimits(newDefaultLimits LimitConfigs) (limits, error) {
	parsed := make(limits)

	for k, v := range newDefaultLimits {
		name, ok := stringToName[k]
		if !ok {
			return nil, fmt.Errorf("unrecognized name %q in default limit, must be one of %v", k, limitNames)
		}

		lim := &Limit{
			Burst:  v.Burst,
			Count:  v.Count,
			Period: v.Period,
			Name:   name,
		}

		err := ValidateLimit(lim)
		if err != nil {
			return nil, fmt.Errorf("parsing default limit %q: %w", k, err)
		}

		lim.precompute()
		parsed[name.EnumString()] = lim
	}
	return parsed, nil
}

type limitRegistry struct {
	// defaults stores default limits by 'name'.
	defaults limits

	// overrides stores override limits by 'name:id'.
	overrides limits
}

func newLimitRegistryFromFiles(defaults, overrides string) (*limitRegistry, error) {
	defaultsData, err := loadDefaults(defaults)
	if err != nil {
		return nil, err
	}

	if overrides == "" {
		return newLimitRegistry(defaultsData, nil)
	}

	overridesData, err := loadOverrides(overrides)
	if err != nil {
		return nil, err
	}

	return newLimitRegistry(defaultsData, overridesData)
}

func newLimitRegistry(defaults LimitConfigs, overrides overridesYAML) (*limitRegistry, error) {
	regDefaults, err := parseDefaultLimits(defaults)
	if err != nil {
		return nil, err
	}

	regOverrides, err := parseOverrideLimits(overrides)
	if err != nil {
		return nil, err
	}

	return &limitRegistry{
		defaults:  regDefaults,
		overrides: regOverrides,
	}, nil
}

// getLimit returns the limit for the specified by name and bucketKey, name is
// required, bucketKey is optional. If bucketkey is empty, the default for the
// limit specified by name is returned. If no default limit exists for the
// specified name, errLimitDisabled is returned.
func (l *limitRegistry) getLimit(name Name, bucketKey string) (*Limit, error) {
	if !name.isValid() {
		// This should never happen. Callers should only be specifying the limit
		// Name enums defined in this package.
		return nil, fmt.Errorf("specified name enum %q, is invalid", name)
	}
	if bucketKey != "" {
		// Check for override.
		ol, ok := l.overrides[bucketKey]
		if ok {
			return ol, nil
		}
	}
	dl, ok := l.defaults[name.EnumString()]
	if ok {
		return dl, nil
	}
	return nil, errLimitDisabled
}

// LoadOverridesByBucketKey loads the overrides YAML at the supplied path,
// parses it with the existing helpers, and returns the resulting limits map
// keyed by "<name>:<id>". This function is exported to support admin tooling
// used during the migration from overrides.yaml to the overrides database
// table.
func LoadOverridesByBucketKey(path string) (map[string]*Limit, error) {
	ovs, err := loadOverrides(path)
	if err != nil {
		return nil, err
	}
	return parseOverrideLimits(ovs)
}

// DumpOverrides dumps the provided overrides to YAML at the supplied path.
// Overrides are grouped by Name, then by Count, Burst, and Period. Groups are
// written in the following order:
//   - Name  (ascending)
//   - Count (descending)
//   - Burst (descending)
//   - Period (ascending)
//
// This function supports admin tooling that routinely exports the overrides
// table for investigation or auditing.
func DumpOverrides(path string, overrides map[string]*Limit) error {
	type entry struct {
		nameStr string
		LimitConfig
	}

	grouped := make(map[entry][]overrideID)

	for bucketKey, limit := range overrides {
		name, id, err := parseOverrideNameEnumId(bucketKey)
		if err != nil {
			return err
		}

		key := entry{
			nameStr: name.String(),
			LimitConfig: LimitConfig{
				Burst:  limit.Burst,
				Count:  limit.Count,
				Period: limit.Period,
			},
		}

		grouped[key] = append(grouped[key], overrideID{
			Id:      id,
			Comment: limit.Comment,
		})
	}

	var keys []entry
	for k := range maps.Keys(grouped) {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		// Sort by limit name in ascending order.
		if keys[i].nameStr != keys[j].nameStr {
			return keys[i].nameStr < keys[j].nameStr
		}
		// Sort by count in descending order (higher counts first).
		if keys[i].Count != keys[j].Count {
			return keys[i].Count > keys[j].Count
		}
		// Sort by burst in descending order (higher bursts first).
		if keys[i].Burst != keys[j].Burst {
			return keys[i].Burst > keys[j].Burst
		}
		// Sort by period in ascending order (lower durations first).
		return keys[i].Period.Duration < keys[j].Period.Duration
	})

	var out overridesYAML
	for _, k := range keys {
		ids := grouped[k]
		sort.Slice(ids, func(i, j int) bool {
			if ids[i].Comment != ids[j].Comment {
				// Sort by comment in ascending order.
				return ids[i].Comment < ids[j].Comment
			}
			// Sort by id in ascending order.
			return ids[i].Id < ids[j].Id
		})

		out = append(out, map[string]overrideYAML{
			k.nameStr: {
				LimitConfig: k.LimitConfig,
				Ids:         ids,
			},
		})
	}

	data, err := yaml.Marshal(out)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
