package ratelimits

import (
	"testing"
	"time"

	"github.com/letsencrypt/boulder/test"
)

func Test_parseOverrideNameId(t *testing.T) {
	usageRequestsPerIPv4AddressEnumStr := nameToEnumString(UsageRequestsPerIPv4Address)
	usageRequestsPerIPv4AddressStr := nameToString[UsageRequestsPerIPv4Address]

	usageRequestsPerIPv6RangeEnumStr := nameToEnumString(UsageRequestsPerIPv6Range)
	usageRequestsPerIPv6RangeStr := nameToString[UsageRequestsPerIPv6Range]

	newOrdersPerAccountEnumStr := nameToEnumString(NewOrdersPerAccount)
	newOrdersPerAccountStr := nameToString[NewOrdersPerAccount]

	// 'enum:ipv4'
	// Valid IPv4 address.
	name, id, err := parseOverrideNameId(usageRequestsPerIPv4AddressStr + ":10.0.0.1")
	test.AssertNotError(t, err, "should not error")
	test.AssertEquals(t, name, usageRequestsPerIPv4AddressEnumStr)
	test.AssertEquals(t, id, "10.0.0.1")

	// 'enum:ipv6range'
	// Valid IPv6 address range.
	name, id, err = parseOverrideNameId(usageRequestsPerIPv6RangeStr + ":2001:0db8:0000::/48")
	test.AssertNotError(t, err, "should not error")
	test.AssertEquals(t, name, usageRequestsPerIPv6RangeEnumStr)
	test.AssertEquals(t, id, "2001:0db8:0000::/48")

	// Invalid IPv4 address.
	_, _, err = parseOverrideNameId(usageRequestsPerIPv4AddressStr + ":10.0.0.9000")
	test.AssertError(t, err, "should error")

	// Invalid IPv6 CIDR range.
	_, _, err = parseOverrideNameId(usageRequestsPerIPv6RangeStr + ":2001:0db8:0000::/128")
	test.AssertError(t, err, "should error")

	// Invalid IPv6 CIDR.
	_, _, err = parseOverrideNameId(usageRequestsPerIPv6RangeStr + ":2001:0db8:0000::/48/48")
	test.AssertError(t, err, "should error")

	// IPv6 address when we expect IPv4 address.
	_, _, err = parseOverrideNameId(usageRequestsPerIPv4AddressStr + ":2001:0db8:85a3:0000:0000:8a2e:0370:7334")
	test.AssertError(t, err, "should error")

	// IPv4 CIDR when we expect IPv6 CIDR range.
	_, _, err = parseOverrideNameId(usageRequestsPerIPv4AddressStr + ":10.0.0.0/16")
	test.AssertError(t, err, "should error")

	// 'enum:regId'
	// Valid regId.
	regId := "1234567890"
	name, id, err = parseOverrideNameId(newOrdersPerAccountStr + ":" + regId)
	test.AssertNotError(t, err, "should not error")
	test.AssertEquals(t, name, newOrdersPerAccountEnumStr)
	test.AssertEquals(t, id, regId)

	// Invalid regId.
	_, _, err = parseOverrideNameId(newOrdersPerAccountStr + ":" + "lol")
	test.AssertError(t, err, "should error")

	// No overrides allowed.
	_, _, err = parseOverrideNameId(nameToString[NewRegistrationsPerIPv4Address] + ":10.1.1.1")
	test.AssertError(t, err, "should error")
	_, _, err = parseOverrideNameId(nameToString[NewRegistrationsPerIPv6Range] + ":2001:0db8:0000::/48")
	test.AssertError(t, err, "should error")
	_, _, err = parseOverrideNameId(nameToString[FailedAuthorizationsPerAccount] + ":1234567890")
	test.AssertError(t, err, "should error")
	_, _, err = parseOverrideNameId(nameToString[CertificatesPerDomainPerAccount] + ":example.com")
	test.AssertError(t, err, "should error")
	_, _, err = parseOverrideNameId(nameToString[CertificatesPerFQDNSetPerAccount] + ":example.com")
	test.AssertError(t, err, "should error")

	// Invalid enum.
	_, _, err = parseOverrideNameId("lol:noexist")
	test.AssertError(t, err, "should error")
}

func Test_loadLimits(t *testing.T) {
	usageRequestsPerIPv4AddressEnumStr := nameToEnumString(UsageRequestsPerIPv4Address)
	usageRequestsPerIPv6RangeEnumStr := nameToEnumString(UsageRequestsPerIPv6Range)

	l, err := loadLimits("testdata/defaults.yml")
	test.AssertNotError(t, err, "should not error")
	expectKey := usageRequestsPerIPv4AddressEnumStr
	test.AssertEquals(t, l[expectKey].Burst, int64(20))
	test.AssertEquals(t, l[expectKey].Count, int64(20))
	test.AssertEquals(t, l[expectKey].Period.Duration, time.Second)

	l, err = loadLimits("testdata/overrides.yml")
	test.AssertNotError(t, err, "should not error")
	expectKey = usageRequestsPerIPv4AddressEnumStr + ":" + "10.0.0.2"
	test.AssertEquals(t, l[expectKey].Burst, int64(40))
	test.AssertEquals(t, l[expectKey].Count, int64(40))
	test.AssertEquals(t, l[expectKey].Period.Duration, time.Second)

	l, err = loadLimits("testdata/working_override_ipv6.yml")
	test.AssertNotError(t, err, "should not error")
	expectKey = usageRequestsPerIPv6RangeEnumStr + ":" + "2001:0db8:0000::/48"
	test.AssertEquals(t, l[expectKey].Burst, int64(40))
	test.AssertEquals(t, l[expectKey].Count, int64(40))
	test.AssertEquals(t, l[expectKey].Period.Duration, time.Second)

	_, err = loadLimits("")
	test.AssertError(t, err, "should error")

	_, err = loadLimits("testdata/does_not_exist.yml")
	test.AssertError(t, err, "should error")

	_, err = loadLimits("testdata/busted_burst.yml")
	test.AssertError(t, err, "should error")

	_, err = loadLimits("testdata/busted_count.yml")
	test.AssertError(t, err, "should error")

	_, err = loadLimits("testdata/busted_period.yml")
	test.AssertError(t, err, "should error")

	_, err = loadLimits("testdata/busted_override_name.yml")
	test.AssertError(t, err, "should error")

	_, err = loadLimits("testdata/busted_override_limit.yml")
	test.AssertError(t, err, "should error")

	_, err = loadLimits("testdata/busted_override_empty_name.yml")
	test.AssertError(t, err, "should error")

	_, err = loadLimits("testdata/busted_override_empty_id.yml")
	test.AssertError(t, err, "should error")

	_, err = loadLimits("testdata/busted_name.yml")
	test.AssertError(t, err, "should error")
}
