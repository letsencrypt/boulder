package ratelimits

import (
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test"
)

func Test_parseOverrideNameId(t *testing.T) {
	usageRequestsPerIPv4AddressEnumStr := nameToIntString(0)
	usageRequestsPerIPv4AddressStr := nameToString[0]

	newRegistrationsPerIPv6RangeEnumStr := nameToIntString(3)
	newRegistrationsPerIPv6RangeStr := nameToString[3]

	newOrdersPerAccountEnumStr := nameToIntString(4)
	newOrdersPerAccountStr := nameToString[4]

	certificatesPerDomainPerAccountEnumStr := nameToIntString(6)
	certificatesPerDomainPerAccountStr := nameToString[6]

	certificatesPerFQDNSetPerAccountEnumStr := nameToIntString(7)
	certificatesPerFQDNSetPerAccountStr := nameToString[7]

	// 'enum:ipv4'
	// Valid IPv4 address.
	name, id, err := parseOverrideNameId(usageRequestsPerIPv4AddressStr + ":10.0.0.1")
	test.AssertNotError(t, err, "should not error")
	test.AssertEquals(t, name, usageRequestsPerIPv4AddressEnumStr)
	test.AssertEquals(t, id, "10.0.0.1")

	// 'enum:ipv6range'
	// Valid IPv6 address range.
	name, id, err = parseOverrideNameId(newRegistrationsPerIPv6RangeStr + ":2001:0db8:0000::/48")
	test.AssertNotError(t, err, "should not error")
	test.AssertEquals(t, name, newRegistrationsPerIPv6RangeEnumStr)
	test.AssertEquals(t, id, "2001:0db8:0000::/48")

	// Invalid IPv4 address.
	_, _, err = parseOverrideNameId(usageRequestsPerIPv4AddressStr + ":10.0.0.9000")
	test.AssertError(t, err, "should error")

	// Invalid IPv6 CIDR range.
	_, _, err = parseOverrideNameId(newRegistrationsPerIPv6RangeStr + ":2001:0db8:0000::/128")
	test.AssertError(t, err, "should error")

	// Invalid IPv6 CIDR.
	_, _, err = parseOverrideNameId(newRegistrationsPerIPv6RangeStr + ":2001:0db8:0000::/48/48")
	test.AssertError(t, err, "should error")

	// IPv6 address when we expect IPv4 address.
	_, _, err = parseOverrideNameId(usageRequestsPerIPv4AddressStr + ":2001:0db8:85a3:0000:0000:8a2e:0370:7334")
	test.AssertError(t, err, "should error")

	// IPv4 CIDR when we expect IPv6 CIDR range.
	_, _, err = parseOverrideNameId(usageRequestsPerIPv4AddressStr + ":192.168.0.0/16")
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

	// 'enum:regId:domain'
	// Valid regId and domain.
	regId = "1234567890"
	domain := "example.com"
	name, id, err = parseOverrideNameId(certificatesPerDomainPerAccountStr + ":" + regId + ":" + domain)
	test.AssertNotError(t, err, "should not error")
	test.AssertEquals(t, name, certificatesPerDomainPerAccountEnumStr)
	test.AssertEquals(t, id, regId+":"+domain)

	// Invalid regId, good domain.
	_, _, err = parseOverrideNameId(certificatesPerDomainPerAccountStr + ":" + "lol" + ":" + domain)
	test.AssertError(t, err, "should error")

	// Good regId, invalid domain.
	_, _, err = parseOverrideNameId(certificatesPerDomainPerAccountStr + ":" + regId + ":" + "22#%")
	test.AssertError(t, err, "should error")

	// 'enum:regId:fqdnSet'
	// Valid regId and fqdnSet.
	regId = "1234567890"
	fqdns := []string{"example.com", "example.org"}
	fqdnSet := strings.Join(fqdns, ",")
	fqdnSetHashStr := string(sa.HashNames(fqdns))
	name, id, err = parseOverrideNameId(certificatesPerFQDNSetPerAccountStr + ":" + regId + ":" + fqdnSet)
	test.AssertNotError(t, err, "should not error")
	test.AssertEquals(t, name, certificatesPerFQDNSetPerAccountEnumStr)
	test.AssertEquals(t, id, regId+":"+fqdnSetHashStr)
}

func Test_loadLimits(t *testing.T) {
	UsageRequestsPerIPv4AddressString := nameToIntString(0)
	NewRegistrationsPerIPv6RangeString := nameToIntString(3)

	l, err := loadLimits("testdata/defaults.yml")
	test.AssertNotError(t, err, "should not error")
	expectKey := UsageRequestsPerIPv4AddressString
	test.AssertEquals(t, l[expectKey].Burst, int64(20))
	test.AssertEquals(t, l[expectKey].Count, int64(20))
	test.AssertEquals(t, l[expectKey].Period.Duration, time.Second)

	l, err = loadLimits("testdata/overrides.yml")
	test.AssertNotError(t, err, "should not error")
	expectKey = UsageRequestsPerIPv4AddressString + ":" + "10.0.0.2"
	test.AssertEquals(t, l[expectKey].Burst, int64(40))
	test.AssertEquals(t, l[expectKey].Count, int64(40))
	test.AssertEquals(t, l[expectKey].Period.Duration, time.Second)

	l, err = loadLimits("testdata/working_override_ipv6.yml")
	test.AssertNotError(t, err, "should not error")
	expectKey = NewRegistrationsPerIPv6RangeString + ":" + "2001:0db8:0000::/48"
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
