package ratelimits

import (
	"os"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/test"
)

func Test_parseOverrideNameId(t *testing.T) {
	usageRequestsPerIPv4AddressStr := nameToString[UsageRequestsPerIPv4Address]
	usageRequestsPerIPv6RangeStr := nameToString[UsageRequestsPerIPv6Range]

	// 'enum:ipv4'
	// Valid IPv4 address.
	name, id, err := parseOverrideNameId(usageRequestsPerIPv4AddressStr + ":10.0.0.1")
	test.AssertNotError(t, err, "should not error")
	test.AssertEquals(t, *name, UsageRequestsPerIPv4Address)
	test.AssertEquals(t, id, "10.0.0.1")

	// 'enum:ipv6range'
	// Valid IPv6 address range.
	name, id, err = parseOverrideNameId(usageRequestsPerIPv6RangeStr + ":2001:0db8:0000::/48")
	test.AssertNotError(t, err, "should not error")
	test.AssertEquals(t, *name, UsageRequestsPerIPv6Range)
	test.AssertEquals(t, id, "2001:0db8:0000::/48")

	// Missing colon (this should never happen but we should avoid panicking).
	_, _, err = parseOverrideNameId(usageRequestsPerIPv4AddressStr + "10.0.0.1")
	test.AssertError(t, err, "missing colon")

	// Empty string.
	_, _, err = parseOverrideNameId("")
	test.AssertError(t, err, "empty string")

	// Only a colon.
	_, _, err = parseOverrideNameId(usageRequestsPerIPv4AddressStr + ":")
	test.AssertError(t, err, "only a colon")

	// Invalid enum.
	_, _, err = parseOverrideNameId("lol:noexist")
	test.AssertError(t, err, "invalid enum")
}

func Test_validateLimit(t *testing.T) {
	err := validateLimit(limit{Burst: 1, Count: 1, Period: config.Duration{Duration: time.Second}})
	test.AssertNotError(t, err, "valid limit")

	// All of the following are invalid.
	for _, l := range []limit{
		{Burst: 0, Count: 1, Period: config.Duration{Duration: time.Second}},
		{Burst: 1, Count: 0, Period: config.Duration{Duration: time.Second}},
		{Burst: 1, Count: 1, Period: config.Duration{Duration: 0}},
	} {
		err = validateLimit(l)
		test.AssertError(t, err, "limit should be invalid")
	}
}

func Test_validateIdForName(t *testing.T) {
	// 'enum:ipv4'
	// Valid IPv4 address.
	err := validateIdForName(UsageRequestsPerIPv4Address, "10.0.0.1")
	test.AssertNotError(t, err, "valid ipv4 address")

	// 'enum:ipv6rangeCIDR'
	// Valid IPv6 address range.
	err = validateIdForName(UsageRequestsPerIPv6Range, "2001:0db8:0000::/48")
	test.AssertNotError(t, err, "should not error")

	// Empty string.
	err = validateIdForName(UsageRequestsPerIPv4Address, "")
	test.AssertError(t, err, "Id is an empty string")

	// One space.
	err = validateIdForName(UsageRequestsPerIPv4Address, " ")
	test.AssertError(t, err, "Id is a single space")

	// Invalid IPv4 address.
	err = validateIdForName(UsageRequestsPerIPv4Address, "10.0.0.9000")
	test.AssertError(t, err, "invalid IPv4 address")

	// Invalid IPv6 CIDR range.
	err = validateIdForName(UsageRequestsPerIPv6Range, "2001:0db8:0000::/128")
	test.AssertError(t, err, "invalid IPv6 CIDR range")

	// Invalid IPv6 CIDR.
	err = validateIdForName(UsageRequestsPerIPv6Range, "2001:0db8:0000::/48/48")
	test.AssertError(t, err, "invalid IPv6 CIDR")

	// IPv6 address when we expect IPv4 address.
	err = validateIdForName(UsageRequestsPerIPv4Address, "2001:0db8:85a3:0000:0000:8a2e:0370:7334")
	test.AssertError(t, err, "ipv6 address when we expect ipv4 address")

	// IPv4 CIDR when we expect IPv6 CIDR range.
	err = validateIdForName(UsageRequestsPerIPv6Range, "10.0.0.0/16")
	test.AssertError(t, err, "ipv4 cidr when we expect ipv6 cidr range")

	// 'enum:regId'
	// Valid regId.
	err = validateIdForName(NewOrdersPerAccount, "1234567890")
	test.AssertNotError(t, err, "valid regId")

	// Invalid regId.
	err = validateIdForName(NewOrdersPerAccount, "lol")
	test.AssertError(t, err, "invalid regId")

	// No overrides allowed.
	err = validateIdForName(NewRegistrationsPerIPv4Address, ":10.1.1.1")
	test.AssertError(t, err, "overrides not allowed")
	err = validateIdForName(NewRegistrationsPerIPv6Range, ":2001:0db8:0000::/48")
	test.AssertError(t, err, "overrides not allowed")
	err = validateIdForName(FailedAuthorizationsPerAccount, ":1234567890")
	test.AssertError(t, err, "overrides not allowed")
	err = validateIdForName(CertificatesPerDomainPerAccount, ":example.com")
	test.AssertError(t, err, "overrides not allowed")
	err = validateIdForName(CertificatesPerFQDNSetPerAccount, ":example.com")
	test.AssertError(t, err, "overrides not allowed")
}

func Test_loadAndParseOverrideLimits(t *testing.T) {
	usageRequestsPerIPv4AddressEnumStr := nameToEnumString(UsageRequestsPerIPv4Address)
	UsageRequestsPerIPv6RangeEnumStr := nameToEnumString(UsageRequestsPerIPv6Range)

	// Load a single valid override limit.
	l, err := loadAndParseOverrideLimits("testdata/working_override.yml")
	test.AssertNotError(t, err, "valid single override limit")
	expectKey := usageRequestsPerIPv4AddressEnumStr + ":" + "10.0.0.2"
	test.AssertEquals(t, l[expectKey].Burst, int64(40))
	test.AssertEquals(t, l[expectKey].Count, int64(40))
	test.AssertEquals(t, l[expectKey].Period.Duration, time.Second)

	// Load multiple valid override limits.
	l, err = loadAndParseOverrideLimits("testdata/working_overrides.yml")
	test.AssertNotError(t, err, "multiple valid override limits")
	test.AssertEquals(t, l[expectKey].Burst, int64(40))
	test.AssertEquals(t, l[expectKey].Count, int64(40))
	test.AssertEquals(t, l[expectKey].Period.Duration, time.Second)
	expectKey2 := UsageRequestsPerIPv6RangeEnumStr + ":" + "2001:0db8:0000::/48"
	test.AssertEquals(t, l[expectKey2].Burst, int64(50))
	test.AssertEquals(t, l[expectKey2].Count, int64(50))
	test.AssertEquals(t, l[expectKey2].Period.Duration, time.Second*2)

	// Path is empty string.
	_, err = loadAndParseOverrideLimits("")
	test.AssertError(t, err, "path is empty string")
	test.Assert(t, os.IsNotExist(err), "path is empty string")

	// Path to file which does not exist.
	_, err = loadAndParseOverrideLimits("testdata/file_does_not_exist.yml")
	test.AssertError(t, err, "a file that does not exist ")
	test.Assert(t, os.IsNotExist(err), "test file should not exist")

	// Burst cannot be 0.
	_, err = loadAndParseOverrideLimits("testdata/busted_override_burst_0.yml")
	test.AssertError(t, err, "single override limit with burst=0")
	test.Assert(t, !os.IsNotExist(err), "test file should exist")

	// Id cannot be empty.
	_, err = loadAndParseOverrideLimits("testdata/busted_override_empty_id.yml")
	test.AssertError(t, err, "single override limit with empty id")
	test.Assert(t, !os.IsNotExist(err), "test file should exist")

	// Name cannot be empty.
	_, err = loadAndParseOverrideLimits("testdata/busted_override_empty_name.yml")
	test.AssertError(t, err, "single override limit with empty name")
	test.Assert(t, !os.IsNotExist(err), "test file should exist")

	// Name must be a string representation of a valid Name enumeration.
	_, err = loadAndParseOverrideLimits("testdata/busted_override_invalid_name.yml")
	test.AssertError(t, err, "single override limit with invalid name")
	test.Assert(t, !os.IsNotExist(err), "test file should exist")

	// Multiple entries, second entry has a bad name.
	_, err = loadAndParseOverrideLimits("testdata/busted_overrides_second_entry_bad_name.yml")
	test.AssertError(t, err, "multiple override limits, second entry is bad")
	test.Assert(t, !os.IsNotExist(err), "test file should exist")

	// Multiple entries, third entry has id of "lol", instead of an IPv4 address.
	_, err = loadAndParseOverrideLimits("testdata/busted_overrides_third_entry_bad_id.yml")
	test.AssertError(t, err, "multiple override limits, third entry has bad Id value")
	test.Assert(t, !os.IsNotExist(err), "test file should exist")
}

func Test_loadAndParseDefaultLimits(t *testing.T) {
	usageRequestsPerIPv4AddressEnumStr := nameToEnumString(UsageRequestsPerIPv4Address)
	UsageRequestsPerIPv6RangeEnumStr := nameToEnumString(UsageRequestsPerIPv6Range)

	// Load a single valid default limit.
	l, err := loadAndParseDefaultLimits("testdata/working_default.yml")
	test.AssertNotError(t, err, "valid single default limit")
	test.AssertEquals(t, l[usageRequestsPerIPv4AddressEnumStr].Burst, int64(20))
	test.AssertEquals(t, l[usageRequestsPerIPv4AddressEnumStr].Count, int64(20))
	test.AssertEquals(t, l[usageRequestsPerIPv4AddressEnumStr].Period.Duration, time.Second)

	// Load multiple valid default limits.
	l, err = loadAndParseDefaultLimits("testdata/working_defaults.yml")
	test.AssertNotError(t, err, "multiple valid default limits")
	test.AssertEquals(t, l[usageRequestsPerIPv4AddressEnumStr].Burst, int64(20))
	test.AssertEquals(t, l[usageRequestsPerIPv4AddressEnumStr].Count, int64(20))
	test.AssertEquals(t, l[usageRequestsPerIPv4AddressEnumStr].Period.Duration, time.Second)
	test.AssertEquals(t, l[UsageRequestsPerIPv6RangeEnumStr].Burst, int64(30))
	test.AssertEquals(t, l[UsageRequestsPerIPv6RangeEnumStr].Count, int64(30))
	test.AssertEquals(t, l[UsageRequestsPerIPv6RangeEnumStr].Period.Duration, time.Second*2)

	// Path is empty string.
	_, err = loadAndParseDefaultLimits("")
	test.AssertError(t, err, "path is empty string")
	test.Assert(t, os.IsNotExist(err), "path is empty string")

	// Path to file which does not exist.
	_, err = loadAndParseDefaultLimits("testdata/file_does_not_exist.yml")
	test.AssertError(t, err, "a file that does not exist")
	test.Assert(t, os.IsNotExist(err), "test file should not exist")

	// Burst cannot be 0.
	_, err = loadAndParseDefaultLimits("testdata/busted_default_burst_0.yml")
	test.AssertError(t, err, "single default limit with burst=0")
	test.Assert(t, !os.IsNotExist(err), "test file should exist")

	// Name cannot be empty.
	_, err = loadAndParseDefaultLimits("testdata/busted_default_empty_name.yml")
	test.AssertError(t, err, "single default limit with empty name")
	test.Assert(t, !os.IsNotExist(err), "test file should exist")

	// Name must be a string representation of a valid Name enumeration.
	_, err = loadAndParseDefaultLimits("testdata/busted_default_invalid_name.yml")
	test.AssertError(t, err, "single default limit with invalid name")
	test.Assert(t, !os.IsNotExist(err), "test file should exist")

	// Multiple entries, second entry has a bad name.
	_, err = loadAndParseDefaultLimits("testdata/busted_defaults_second_entry_bad_name.yml")
	test.AssertError(t, err, "multiple default limits, one is bad")
	test.Assert(t, !os.IsNotExist(err), "test file should exist")
}
