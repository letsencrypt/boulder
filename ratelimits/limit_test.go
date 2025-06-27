package ratelimits

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/test"
)

// loadAndParseDefaultLimits is a helper that calls both loadDefaults and
// parseDefaultLimits to handle a YAML file.
//
// TODO(#7901): Update the tests to test these functions individually.
func loadAndParseDefaultLimits(path string) (Limits, error) {
	fromFile, err := loadDefaults(path)
	if err != nil {
		return nil, err
	}

	return parseDefaultLimits(fromFile)
}

// loadAndParseOverrideLimits is a helper that calls both loadOverrides and
// parseOverrideLimits to handle a YAML file.
//
// TODO(#7901): Update the tests to test these functions individually.
func loadAndParseOverrideLimits(path string) (Limits, error) {
	fromFile, err := loadOverrides(path)
	if err != nil {
		return nil, err
	}

	return parseOverrideLimits(fromFile)
}

func TestParseOverrideNameId(t *testing.T) {
	// 'enum:ipv4'
	// Valid IPv4 address.
	name, id, err := parseOverrideNameId(NewRegistrationsPerIPAddress.String() + ":10.0.0.1")
	test.AssertNotError(t, err, "should not error")
	test.AssertEquals(t, name, NewRegistrationsPerIPAddress)
	test.AssertEquals(t, id, "10.0.0.1")

	// 'enum:ipv6range'
	// Valid IPv6 address range.
	name, id, err = parseOverrideNameId(NewRegistrationsPerIPv6Range.String() + ":2602:80a:6000::/48")
	test.AssertNotError(t, err, "should not error")
	test.AssertEquals(t, name, NewRegistrationsPerIPv6Range)
	test.AssertEquals(t, id, "2602:80a:6000::/48")

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

func TestParseOverrideNameEnumId(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input       string
		wantName    Name
		wantId      string
		expectError bool
		desc        string
	}{
		{
			input:       NewRegistrationsPerIPAddress.EnumString() + ":10.0.0.1",
			wantName:    NewRegistrationsPerIPAddress,
			wantId:      "10.0.0.1",
			expectError: false,
			desc:        "valid IPv4 address",
		},
		{
			input:       NewRegistrationsPerIPv6Range.EnumString() + ":2001:0db8:0000::/48",
			wantName:    NewRegistrationsPerIPv6Range,
			wantId:      "2001:0db8:0000::/48",
			expectError: false,
			desc:        "valid IPv6 address range",
		},
		{
			input:       NewRegistrationsPerIPAddress.EnumString() + "10.0.0.1",
			expectError: true,
			desc:        "missing colon",
		},
		{
			input:       "",
			expectError: true,
			desc:        "empty string",
		},
		{
			input:       NewRegistrationsPerIPAddress.EnumString() + ":",
			expectError: true,
			desc:        "only a colon",
		},
		{
			input:       "lol:noexist",
			expectError: true,
			desc:        "invalid enum",
		},
	}

	for _, tc := range tests {
		name, id, err := parseOverrideNameEnumId(tc.input)
		if tc.expectError {
			test.AssertError(t, err, tc.desc)
		} else {
			test.AssertNotError(t, err, tc.desc)
			test.AssertEquals(t, name, tc.wantName)
			test.AssertEquals(t, id, tc.wantId)
		}
	}
}

func TestValidateLimit(t *testing.T) {
	err := ValidateLimit(&Limit{Burst: 1, Count: 1, Period: config.Duration{Duration: time.Second}})
	test.AssertNotError(t, err, "valid limit")

	// All of the following are invalid.
	for _, l := range []*Limit{
		{Burst: 0, Count: 1, Period: config.Duration{Duration: time.Second}},
		{Burst: 1, Count: 0, Period: config.Duration{Duration: time.Second}},
		{Burst: 1, Count: 1, Period: config.Duration{Duration: 0}},
	} {
		err = ValidateLimit(l)
		test.AssertError(t, err, "limit should be invalid")
	}
}

func TestLoadAndParseOverrideLimits(t *testing.T) {
	// Load a single valid override limit with Id formatted as 'enum:RegId'.
	l, err := loadAndParseOverrideLimits("testdata/working_override.yml")
	test.AssertNotError(t, err, "valid single override limit")
	expectKey := joinWithColon(NewRegistrationsPerIPAddress.EnumString(), "64.112.117.1")
	test.AssertEquals(t, l[expectKey].Burst, int64(40))
	test.AssertEquals(t, l[expectKey].Count, int64(40))
	test.AssertEquals(t, l[expectKey].Period.Duration, time.Second)

	// Load single valid override limit with a 'domainOrCIDR' Id.
	l, err = loadAndParseOverrideLimits("testdata/working_override_regid_domainorcidr.yml")
	test.AssertNotError(t, err, "valid single override limit with Id of regId:domainOrCIDR")
	expectKey = joinWithColon(CertificatesPerDomain.EnumString(), "example.com")
	test.AssertEquals(t, l[expectKey].Burst, int64(40))
	test.AssertEquals(t, l[expectKey].Count, int64(40))
	test.AssertEquals(t, l[expectKey].Period.Duration, time.Second)

	// Load multiple valid override limits with 'regId' Ids.
	l, err = loadAndParseOverrideLimits("testdata/working_overrides.yml")
	test.AssertNotError(t, err, "multiple valid override limits")
	expectKey1 := joinWithColon(NewRegistrationsPerIPAddress.EnumString(), "64.112.117.1")
	test.AssertEquals(t, l[expectKey1].Burst, int64(40))
	test.AssertEquals(t, l[expectKey1].Count, int64(40))
	test.AssertEquals(t, l[expectKey1].Period.Duration, time.Second)
	expectKey2 := joinWithColon(NewRegistrationsPerIPv6Range.EnumString(), "2602:80a:6000::/48")
	test.AssertEquals(t, l[expectKey2].Burst, int64(50))
	test.AssertEquals(t, l[expectKey2].Count, int64(50))
	test.AssertEquals(t, l[expectKey2].Period.Duration, time.Second*2)

	// Load multiple valid override limits with 'fqdnSet' Ids, as follows:
	//   - CertificatesPerFQDNSet:example.com
	//   - CertificatesPerFQDNSet:example.com,example.net
	//   - CertificatesPerFQDNSet:example.com,example.net,example.org
	entryKey1 := newFQDNSetBucketKey(CertificatesPerFQDNSet, identifier.NewDNSSlice([]string{"example.com"}))
	entryKey2 := newFQDNSetBucketKey(CertificatesPerFQDNSet, identifier.NewDNSSlice([]string{"example.com", "example.net"}))
	entryKey3 := newFQDNSetBucketKey(CertificatesPerFQDNSet, identifier.NewDNSSlice([]string{"example.com", "example.net", "example.org"}))
	entryKey4 := newFQDNSetBucketKey(CertificatesPerFQDNSet, identifier.ACMEIdentifiers{
		identifier.NewIP(netip.MustParseAddr("2602:80a:6000::1")),
		identifier.NewIP(netip.MustParseAddr("9.9.9.9")),
		identifier.NewDNS("example.com"),
	})

	l, err = loadAndParseOverrideLimits("testdata/working_overrides_regid_fqdnset.yml")
	test.AssertNotError(t, err, "multiple valid override limits with 'fqdnSet' Ids")
	test.AssertEquals(t, l[entryKey1].Burst, int64(40))
	test.AssertEquals(t, l[entryKey1].Count, int64(40))
	test.AssertEquals(t, l[entryKey1].Period.Duration, time.Second)
	test.AssertEquals(t, l[entryKey2].Burst, int64(50))
	test.AssertEquals(t, l[entryKey2].Count, int64(50))
	test.AssertEquals(t, l[entryKey2].Period.Duration, time.Second*2)
	test.AssertEquals(t, l[entryKey3].Burst, int64(60))
	test.AssertEquals(t, l[entryKey3].Count, int64(60))
	test.AssertEquals(t, l[entryKey3].Period.Duration, time.Second*3)
	test.AssertEquals(t, l[entryKey4].Burst, int64(60))
	test.AssertEquals(t, l[entryKey4].Count, int64(60))
	test.AssertEquals(t, l[entryKey4].Period.Duration, time.Second*4)

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
	test.AssertContains(t, err.Error(), "invalid burst")

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

func TestLoadAndParseDefaultLimits(t *testing.T) {
	// Load a single valid default limit.
	l, err := loadAndParseDefaultLimits("testdata/working_default.yml")
	test.AssertNotError(t, err, "valid single default limit")
	test.AssertEquals(t, l[NewRegistrationsPerIPAddress.EnumString()].Burst, int64(20))
	test.AssertEquals(t, l[NewRegistrationsPerIPAddress.EnumString()].Count, int64(20))
	test.AssertEquals(t, l[NewRegistrationsPerIPAddress.EnumString()].Period.Duration, time.Second)

	// Load multiple valid default limits.
	l, err = loadAndParseDefaultLimits("testdata/working_defaults.yml")
	test.AssertNotError(t, err, "multiple valid default limits")
	test.AssertEquals(t, l[NewRegistrationsPerIPAddress.EnumString()].Burst, int64(20))
	test.AssertEquals(t, l[NewRegistrationsPerIPAddress.EnumString()].Count, int64(20))
	test.AssertEquals(t, l[NewRegistrationsPerIPAddress.EnumString()].Period.Duration, time.Second)
	test.AssertEquals(t, l[NewRegistrationsPerIPv6Range.EnumString()].Burst, int64(30))
	test.AssertEquals(t, l[NewRegistrationsPerIPv6Range.EnumString()].Count, int64(30))
	test.AssertEquals(t, l[NewRegistrationsPerIPv6Range.EnumString()].Period.Duration, time.Second*2)

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
	test.AssertContains(t, err.Error(), "invalid burst")

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

func TestLoadAndDumpOverrides(t *testing.T) {
	t.Parallel()

	input := `
- CertificatesPerDomain:
    burst: 5000
    count: 5000
    period: 168h0m0s
    ids:
        - id: example.com
          comment: IN-10057
        - id: example.net
          comment: IN-10057
- CertificatesPerDomain:
    burst: 300
    count: 300
    period: 168h0m0s
    ids:
        - id: example.org
          comment: IN-10057
- CertificatesPerDomainPerAccount:
    burst: 12000
    count: 12000
    period: 168h0m0s
    ids:
        - id: "123456789"
          comment: Affluent (IN-8322)
- CertificatesPerDomainPerAccount:
    burst: 6000
    count: 6000
    period: 168h0m0s
    ids:
        - id: "543219876"
          comment: Affluent (IN-8322)
        - id: "987654321"
          comment: Affluent (IN-8322)
- CertificatesPerFQDNSet:
    burst: 50
    count: 50
    period: 168h0m0s
    ids:
        - id: example.co.uk,example.cn
          comment: IN-6843
- CertificatesPerFQDNSet:
    burst: 24
    count: 24
    period: 168h0m0s
    ids:
        - id: example.org,example.com,example.net
          comment: IN-6006
- FailedAuthorizationsPerDomainPerAccount:
    burst: 250
    count: 250
    period: 1h0m0s
    ids:
        - id: "123456789"
          comment: Digital Lake (IN-6736)
- FailedAuthorizationsPerDomainPerAccount:
    burst: 50
    count: 50
    period: 1h0m0s
    ids:
        - id: "987654321"
          comment: Digital Lake (IN-6856)
- FailedAuthorizationsPerDomainPerAccount:
    burst: 10
    count: 10
    period: 1h0m0s
    ids:
        - id: "543219876"
          comment: Big Mart (IN-6949)
- NewOrdersPerAccount:
    burst: 3000
    count: 3000
    period: 3h0m0s
    ids:
        - id: "123456789"
          comment: Galaxy Hoster (IN-8180)
- NewOrdersPerAccount:
    burst: 1000
    count: 1000
    period: 3h0m0s
    ids:
        - id: "543219876"
          comment: Big Mart (IN-8180)
        - id: "987654321"
          comment: Buy More (IN-10057)
- NewRegistrationsPerIPAddress:
    burst: 100000
    count: 100000
    period: 3h0m0s
    ids:
        - id: 2600:1f1c:5e0:e702:ca06:d2a3:c7ce:a02e
          comment: example.org IN-2395
        - id: 55.66.77.88
          comment: example.org IN-2395
- NewRegistrationsPerIPAddress:
    burst: 200
    count: 200
    period: 3h0m0s
    ids:
        - id: 11.22.33.44
          comment: example.net (IN-1583)`

	expectCSV := `
name,id,count,burst,period,comment
CertificatesPerDomain,example.com,5000,5000,168h0m0s,IN-10057
CertificatesPerDomain,example.net,5000,5000,168h0m0s,IN-10057
CertificatesPerDomain,example.org,300,300,168h0m0s,IN-10057
CertificatesPerDomainPerAccount,123456789,12000,12000,168h0m0s,Affluent (IN-8322)
CertificatesPerDomainPerAccount,543219876,6000,6000,168h0m0s,Affluent (IN-8322)
CertificatesPerDomainPerAccount,987654321,6000,6000,168h0m0s,Affluent (IN-8322)
CertificatesPerFQDNSet,7c956936126b492845ddb48f4d220034509e7c0ad54ed2c1ba2650406846d9c3,50,50,168h0m0s,IN-6843
CertificatesPerFQDNSet,394e82811f52e2da38b970afdb21c9bc9af81060939c690183c00fce37408738,24,24,168h0m0s,IN-6006
FailedAuthorizationsPerDomainPerAccount,123456789,250,250,1h0m0s,Digital Lake (IN-6736)
FailedAuthorizationsPerDomainPerAccount,987654321,50,50,1h0m0s,Digital Lake (IN-6856)
FailedAuthorizationsPerDomainPerAccount,543219876,10,10,1h0m0s,Big Mart (IN-6949)
NewOrdersPerAccount,123456789,3000,3000,3h0m0s,Galaxy Hoster (IN-8180)
NewOrdersPerAccount,543219876,1000,1000,3h0m0s,Big Mart (IN-8180)
NewOrdersPerAccount,987654321,1000,1000,3h0m0s,Buy More (IN-10057)
NewRegistrationsPerIPAddress,2600:1f1c:5e0:e702:ca06:d2a3:c7ce:a02e,100000,100000,3h0m0s,example.org IN-2395
NewRegistrationsPerIPAddress,55.66.77.88,100000,100000,3h0m0s,example.org IN-2395
NewRegistrationsPerIPAddress,11.22.33.44,200,200,3h0m0s,example.net (IN-1583)
`

	tempFile := filepath.Join(t.TempDir(), "overrides.yaml")

	err := os.WriteFile(tempFile, []byte(input), 0644)
	test.AssertNotError(t, err, "writing temp overrides.yaml")

	original, err := LoadOverridesByBucketKey(tempFile)
	test.AssertNotError(t, err, "loading overrides")
	test.Assert(t, len(original) > 0, "expected at least one override loaded")

	dumpFile := filepath.Join(t.TempDir(), "dumped.yaml")
	err = DumpOverrides(dumpFile, original)
	test.AssertNotError(t, err, "dumping overrides")

	dumped, err := os.ReadFile(dumpFile)
	test.AssertNotError(t, err, "reading dumped overrides file")
	test.AssertEquals(t, strings.TrimLeft(string(dumped), "\n"), strings.TrimLeft(expectCSV, "\n"))
}
