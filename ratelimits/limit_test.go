package ratelimits

import (
	"os"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/test"
)

func Test_parseOverrideNameId(t *testing.T) {
	// 'enum:ipv4'
	// Valid IPv4 address.
	name, id, err := parseOverrideNameId(NewRegistrationsPerIPAddress.String() + ":10.0.0.1")
	test.AssertNotError(t, err, "should not error")
	test.AssertEquals(t, name, NewRegistrationsPerIPAddress)
	test.AssertEquals(t, id, "10.0.0.1")

	// 'enum:ipv6range'
	// Valid IPv6 address range.
	name, id, err = parseOverrideNameId(NewRegistrationsPerIPv6Range.String() + ":2001:0db8:0000::/48")
	test.AssertNotError(t, err, "should not error")
	test.AssertEquals(t, name, NewRegistrationsPerIPv6Range)
	test.AssertEquals(t, id, "2001:0db8:0000::/48")

	// Missing colon (this should never happen but we should avoid panicking).
	_, _, err = parseOverrideNameId(NewRegistrationsPerIPAddress.String() + "10.0.0.1")
	test.AssertError(t, err, "missing colon")

	// Empty string.
	_, _, err = parseOverrideNameId("")
	test.AssertError(t, err, "empty string")

	// Only a colon.
	_, _, err = parseOverrideNameId(NewRegistrationsPerIPAddress.String() + ":")
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
	// 'enum:ipAddress'
	// Valid IPv4 address.
	err := validateIdForName(NewRegistrationsPerIPAddress, "10.0.0.1")
	test.AssertNotError(t, err, "valid ipv4 address")

	// 'enum:ipAddress'
	// Valid IPv6 address.
	err = validateIdForName(NewRegistrationsPerIPAddress, "2001:0db8:85a3:0000:0000:8a2e:0370:7334")
	test.AssertNotError(t, err, "valid ipv6 address")

	// 'enum:ipv6rangeCIDR'
	// Valid IPv6 address range.
	err = validateIdForName(NewRegistrationsPerIPv6Range, "2001:0db8:0000::/48")
	test.AssertNotError(t, err, "should not error")

	// 'enum:regId'
	// Valid regId.
	err = validateIdForName(NewOrdersPerAccount, "1234567890")
	test.AssertNotError(t, err, "valid regId")

	// 'enum:regId:domain'
	// Valid regId and domain.
	err = validateIdForName(CertificatesPerDomainPerAccount, "1234567890:example.com")
	test.AssertNotError(t, err, "valid regId and domain")

	// 'enum:regId:fqdnSet'
	// Valid regId and FQDN set containing a single domain.
	err = validateIdForName(CertificatesPerFQDNSetPerAccount, "1234567890:example.com")
	test.AssertNotError(t, err, "valid regId and FQDN set containing a single domain")

	// 'enum:regId:fqdnSet'
	// Valid regId and FQDN set containing multiple domains.
	err = validateIdForName(CertificatesPerFQDNSetPerAccount, "1234567890:example.com,example.org")
	test.AssertNotError(t, err, "valid regId and FQDN set containing multiple domains")

	// Empty string.
	err = validateIdForName(NewRegistrationsPerIPAddress, "")
	test.AssertError(t, err, "Id is an empty string")

	// One space.
	err = validateIdForName(NewRegistrationsPerIPAddress, " ")
	test.AssertError(t, err, "Id is a single space")

	// Invalid IPv4 address.
	err = validateIdForName(NewRegistrationsPerIPAddress, "10.0.0.9000")
	test.AssertError(t, err, "invalid IPv4 address")

	// Invalid IPv6 address.
	err = validateIdForName(NewRegistrationsPerIPAddress, "2001:0db8:85a3:0000:0000:8a2e:0370:7334:9000")
	test.AssertError(t, err, "invalid IPv6 address")

	// Invalid IPv6 CIDR range.
	err = validateIdForName(NewRegistrationsPerIPv6Range, "2001:0db8:0000::/128")
	test.AssertError(t, err, "invalid IPv6 CIDR range")

	// Invalid IPv6 CIDR.
	err = validateIdForName(NewRegistrationsPerIPv6Range, "2001:0db8:0000::/48/48")
	test.AssertError(t, err, "invalid IPv6 CIDR")

	// IPv4 CIDR when we expect IPv6 CIDR range.
	err = validateIdForName(NewRegistrationsPerIPv6Range, "10.0.0.0/16")
	test.AssertError(t, err, "ipv4 cidr when we expect ipv6 cidr range")

	// Invalid regId.
	err = validateIdForName(NewOrdersPerAccount, "lol")
	test.AssertError(t, err, "invalid regId")

	// Invalid regId with good domain.
	err = validateIdForName(CertificatesPerDomainPerAccount, "lol:example.com")
	test.AssertError(t, err, "invalid regId with good domain")

	// Valid regId with bad domain.
	err = validateIdForName(CertificatesPerDomainPerAccount, "1234567890:lol")
	test.AssertError(t, err, "valid regId with bad domain")

	// Empty regId with good domain.
	err = validateIdForName(CertificatesPerDomainPerAccount, ":lol")
	test.AssertError(t, err, "valid regId with bad domain")

	// Valid regId with empty domain.
	err = validateIdForName(CertificatesPerDomainPerAccount, "1234567890:")
	test.AssertError(t, err, "valid regId with empty domain")

	// Empty regId with empty domain, no separator.
	err = validateIdForName(CertificatesPerDomainPerAccount, "")
	test.AssertError(t, err, "empty regId with empty domain, no separator")

	// Instead of anything we would expect, we get lol.
	err = validateIdForName(CertificatesPerDomainPerAccount, "lol")
	test.AssertError(t, err, "instead of anything we would expect, just lol")

	// Valid regId with good domain and a secret third separator.
	err = validateIdForName(CertificatesPerDomainPerAccount, "1234567890:example.com:lol")
	test.AssertError(t, err, "valid regId with good domain and a secret third separator")

	// Valid regId with bad FQDN set.
	err = validateIdForName(CertificatesPerFQDNSetPerAccount, "1234567890:lol..99")
	test.AssertError(t, err, "valid regId with bad FQDN set")

	// Bad regId with good FQDN set.
	err = validateIdForName(CertificatesPerFQDNSetPerAccount, "lol:example.com,example.org")
	test.AssertError(t, err, "bad regId with good FQDN set")

	// Empty regId with good FQDN set.
	err = validateIdForName(CertificatesPerFQDNSetPerAccount, ":example.com,example.org")
	test.AssertError(t, err, "empty regId with good FQDN set")

	// Good regId with empty FQDN set.
	err = validateIdForName(CertificatesPerFQDNSetPerAccount, "1234567890:")
	test.AssertError(t, err, "good regId with empty FQDN set")

	// Empty regId with empty FQDN set, no separator.
	err = validateIdForName(CertificatesPerFQDNSetPerAccount, "")
	test.AssertError(t, err, "empty regId with empty FQDN set, no separator")

	// Instead of anything we would expect, just lol.
	err = validateIdForName(CertificatesPerFQDNSetPerAccount, "lol")
	test.AssertError(t, err, "instead of anything we would expect, just lol")

	// Valid regId with good FQDN set and a secret third separator.
	err = validateIdForName(CertificatesPerFQDNSetPerAccount, "1234567890:example.com,example.org:lol")
	test.AssertError(t, err, "valid regId with good FQDN set and a secret third separator")
}

func Test_loadAndParseOverrideLimits(t *testing.T) {
	newRegistrationsPerIPAddressEnumStr := nameToEnumString(NewRegistrationsPerIPAddress)
	newRegistrationsPerIPv6RangeEnumStr := nameToEnumString(NewRegistrationsPerIPv6Range)

	// Load a single valid override limit with Id formatted as 'enum:RegId'.
	l, err := loadAndParseOverrideLimits("testdata/working_override.yml")
	test.AssertNotError(t, err, "valid single override limit")
	expectKey := newRegistrationsPerIPAddressEnumStr + ":" + "10.0.0.2"
	test.AssertEquals(t, l[expectKey].Burst, int64(40))
	test.AssertEquals(t, l[expectKey].Count, int64(40))
	test.AssertEquals(t, l[expectKey].Period.Duration, time.Second)

	// Load single valid override limit with Id formatted as 'regId:domain'.
	l, err = loadAndParseOverrideLimits("testdata/working_override_regid_domain.yml")
	test.AssertNotError(t, err, "valid single override limit with Id of regId:domain")
	expectKey = nameToEnumString(CertificatesPerDomainPerAccount) + ":" + "12345678:example.com"
	test.AssertEquals(t, l[expectKey].Burst, int64(40))
	test.AssertEquals(t, l[expectKey].Count, int64(40))
	test.AssertEquals(t, l[expectKey].Period.Duration, time.Second)

	// Load multiple valid override limits with 'enum:RegId' Ids.
	l, err = loadAndParseOverrideLimits("testdata/working_overrides.yml")
	expectKey1 := newRegistrationsPerIPAddressEnumStr + ":" + "10.0.0.2"
	test.AssertNotError(t, err, "multiple valid override limits")
	test.AssertEquals(t, l[expectKey1].Burst, int64(40))
	test.AssertEquals(t, l[expectKey1].Count, int64(40))
	test.AssertEquals(t, l[expectKey1].Period.Duration, time.Second)
	expectKey2 := newRegistrationsPerIPv6RangeEnumStr + ":" + "2001:0db8:0000::/48"
	test.AssertEquals(t, l[expectKey2].Burst, int64(50))
	test.AssertEquals(t, l[expectKey2].Count, int64(50))
	test.AssertEquals(t, l[expectKey2].Period.Duration, time.Second*2)

	// Load multiple valid override limits with 'regID:fqdnSet' Ids as follows:
	//   - CertificatesPerFQDNSetPerAccount:12345678:example.com
	//   - CertificatesPerFQDNSetPerAccount:12345678:example.com,example.net
	//   - CertificatesPerFQDNSetPerAccount:12345678:example.com,example.net,example.org
	firstEntryFQDNSetHash := string(core.HashNames([]string{"example.com"}))
	secondEntryFQDNSetHash := string(core.HashNames([]string{"example.com", "example.net"}))
	thirdEntryFQDNSetHash := string(core.HashNames([]string{"example.com", "example.net", "example.org"}))
	firstEntryKey := nameToEnumString(CertificatesPerFQDNSetPerAccount) + ":" + "12345678:" + firstEntryFQDNSetHash
	secondEntryKey := nameToEnumString(CertificatesPerFQDNSetPerAccount) + ":" + "12345678:" + secondEntryFQDNSetHash
	thirdEntryKey := nameToEnumString(CertificatesPerFQDNSetPerAccount) + ":" + "12345678:" + thirdEntryFQDNSetHash
	l, err = loadAndParseOverrideLimits("testdata/working_overrides_regid_fqdnset.yml")
	test.AssertNotError(t, err, "multiple valid override limits with Id of regId:fqdnSets")
	test.AssertEquals(t, l[firstEntryKey].Burst, int64(40))
	test.AssertEquals(t, l[firstEntryKey].Count, int64(40))
	test.AssertEquals(t, l[firstEntryKey].Period.Duration, time.Second)
	test.AssertEquals(t, l[secondEntryKey].Burst, int64(50))
	test.AssertEquals(t, l[secondEntryKey].Count, int64(50))
	test.AssertEquals(t, l[secondEntryKey].Period.Duration, time.Second*2)
	test.AssertEquals(t, l[thirdEntryKey].Burst, int64(60))
	test.AssertEquals(t, l[thirdEntryKey].Count, int64(60))
	test.AssertEquals(t, l[thirdEntryKey].Period.Duration, time.Second*3)

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
	newRestistrationsPerIPv4AddressEnumStr := nameToEnumString(NewRegistrationsPerIPAddress)
	newRegistrationsPerIPv6RangeEnumStr := nameToEnumString(NewRegistrationsPerIPv6Range)

	// Load a single valid default limit.
	l, err := loadAndParseDefaultLimits("testdata/working_default.yml")
	test.AssertNotError(t, err, "valid single default limit")
	test.AssertEquals(t, l[newRestistrationsPerIPv4AddressEnumStr].Burst, int64(20))
	test.AssertEquals(t, l[newRestistrationsPerIPv4AddressEnumStr].Count, int64(20))
	test.AssertEquals(t, l[newRestistrationsPerIPv4AddressEnumStr].Period.Duration, time.Second)

	// Load multiple valid default limits.
	l, err = loadAndParseDefaultLimits("testdata/working_defaults.yml")
	test.AssertNotError(t, err, "multiple valid default limits")
	test.AssertEquals(t, l[newRestistrationsPerIPv4AddressEnumStr].Burst, int64(20))
	test.AssertEquals(t, l[newRestistrationsPerIPv4AddressEnumStr].Count, int64(20))
	test.AssertEquals(t, l[newRestistrationsPerIPv4AddressEnumStr].Period.Duration, time.Second)
	test.AssertEquals(t, l[newRegistrationsPerIPv6RangeEnumStr].Burst, int64(30))
	test.AssertEquals(t, l[newRegistrationsPerIPv6RangeEnumStr].Count, int64(30))
	test.AssertEquals(t, l[newRegistrationsPerIPv6RangeEnumStr].Period.Duration, time.Second*2)

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
