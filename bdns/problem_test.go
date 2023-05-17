package bdns

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestError(t *testing.T) {
	testCases := []struct {
		err      error
		expected string
	}{
		{
			&Error{dns.TypeA, "hostname", makeTimeoutError(), -1, nil},
			"DNS problem: query timed out looking up A for hostname",
		}, {
			&Error{dns.TypeMX, "hostname", &net.OpError{Err: errors.New("some net error")}, -1, nil},
			"DNS problem: networking error looking up MX for hostname",
		}, {
			&Error{dns.TypeTXT, "hostname", nil, dns.RcodeNameError, nil},
			"DNS problem: NXDOMAIN looking up TXT for hostname - check that a DNS record exists for this domain",
		}, {
			&Error{dns.TypeTXT, "hostname", context.DeadlineExceeded, -1, nil},
			"DNS problem: query timed out looking up TXT for hostname",
		}, {
			&Error{dns.TypeTXT, "hostname", context.Canceled, -1, nil},
			"DNS problem: query timed out (and was canceled) looking up TXT for hostname",
		}, {
			&Error{dns.TypeCAA, "hostname", nil, dns.RcodeServerFailure, nil},
			"DNS problem: SERVFAIL looking up CAA for hostname - the domain's nameservers may be malfunctioning",
		}, {
			&Error{dns.TypeA, "hostname", nil, dns.RcodeServerFailure, &dns.EDNS0_EDE{InfoCode: 1, ExtraText: "oh no"}},
			"DNS problem: looking up A for hostname: DNSSEC: Unsupported DNSKEY Algorithm: oh no",
		}, {
			&Error{dns.TypeA, "hostname", nil, dns.RcodeServerFailure, &dns.EDNS0_EDE{InfoCode: 6, ExtraText: ""}},
			"DNS problem: looking up A for hostname: DNSSEC: Bogus",
		}, {
			&Error{dns.TypeA, "hostname", nil, dns.RcodeServerFailure, &dns.EDNS0_EDE{InfoCode: 1337, ExtraText: "mysterious"}},
			"DNS problem: looking up A for hostname: Unknown Extended DNS Error code 1337: mysterious",
		}, {
			&Error{dns.TypeCAA, "hostname", nil, dns.RcodeServerFailure, nil},
			"DNS problem: SERVFAIL looking up CAA for hostname - the domain's nameservers may be malfunctioning",
		}, {
			&Error{dns.TypeCAA, "hostname", nil, dns.RcodeServerFailure, nil},
			"DNS problem: SERVFAIL looking up CAA for hostname - the domain's nameservers may be malfunctioning",
		}, {
			&Error{dns.TypeA, "hostname", nil, dns.RcodeFormatError, nil},
			"DNS problem: FORMERR looking up A for hostname",
		},
	}
	for _, tc := range testCases {
		if tc.err.Error() != tc.expected {
			t.Errorf("got %q, expected %q", tc.err.Error(), tc.expected)
		}
	}
}
