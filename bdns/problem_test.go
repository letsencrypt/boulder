package bdns

import (
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"

	"github.com/letsencrypt/boulder/test"
)

func TestError(t *testing.T) {
	testCases := []struct {
		err      error
		expected string
	}{
		{
			&Error{dns.TypeMX, "hostname", &net.OpError{Err: errors.New("some net error")}, -1, nil, false},
			"DNS problem: server failure at resolver looking up MX for hostname",
		}, {
			&Error{dns.TypeTXT, "hostname", nil, dns.RcodeNameError, nil, false},
			"DNS problem: NXDOMAIN looking up TXT for hostname - check that a DNS record exists for this domain",
		}, {
			&Error{dns.TypeTXT, "hostname", errDohQueryTimeout, -1, nil, false},
			"DNS problem: query timed out looking up TXT for hostname",
		}, {
			&Error{dns.TypeTXT, "hostname", errDohQueryCanceled, -1, nil, false},
			"DNS problem: query timed out (and was canceled) looking up TXT for hostname",
		}, {
			&Error{dns.TypeCAA, "hostname", nil, dns.RcodeServerFailure, nil, false},
			"DNS problem: SERVFAIL looking up CAA for hostname - the domain's nameservers may be malfunctioning",
		}, {
			&Error{dns.TypeA, "hostname", nil, dns.RcodeServerFailure, &dns.EDNS0_EDE{InfoCode: 1, ExtraText: "oh no"}, false},
			"DNS problem: looking up A for hostname: DNSSEC: Unsupported DNSKEY Algorithm: oh no",
		}, {
			&Error{dns.TypeA, "hostname", nil, dns.RcodeServerFailure, &dns.EDNS0_EDE{InfoCode: 6, ExtraText: ""}, false},
			"DNS problem: looking up A for hostname: DNSSEC: Bogus",
		}, {
			&Error{dns.TypeA, "hostname", nil, dns.RcodeServerFailure, &dns.EDNS0_EDE{InfoCode: 1337, ExtraText: "mysterious"}, false},
			"DNS problem: looking up A for hostname: Unknown Extended DNS Error code 1337: mysterious",
		}, {
			&Error{dns.TypeCAA, "hostname", nil, dns.RcodeServerFailure, nil, false},
			"DNS problem: SERVFAIL looking up CAA for hostname - the domain's nameservers may be malfunctioning",
		}, {
			&Error{dns.TypeCAA, "hostname", nil, dns.RcodeServerFailure, nil, false},
			"DNS problem: SERVFAIL looking up CAA for hostname - the domain's nameservers may be malfunctioning",
		}, {
			&Error{dns.TypeA, "hostname", nil, dns.RcodeFormatError, nil, false},
			"DNS problem: FORMERR looking up A for hostname",
		}, {
			&Error{dns.TypeCAA, "hostname", nil, dns.RcodeSuccess, nil, true},
			"DNS problem: response was truncated looking up CAA for hostname",
		},
	}
	for _, tc := range testCases {
		if tc.err.Error() != tc.expected {
			t.Errorf("got %q, expected %q", tc.err.Error(), tc.expected)
		}
	}
}

func TestWrapErr(t *testing.T) {
	err := wrapErr(dns.TypeA, "hostname", &dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
	}, nil)
	test.AssertNotError(t, err, "expected success")

	err = wrapErr(dns.TypeA, "hostname", &dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: dns.RcodeRefused},
	}, nil)
	test.AssertError(t, err, "expected error")

	err = wrapErr(dns.TypeA, "hostname", &dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
	}, errors.New("oh no"))
	test.AssertError(t, err, "expected error")

	// A truncated response should be treated as an error, even though its
	// Rcode is RcodeSuccess: a truncated CAA response could be silently
	// missing the issue/issuewild records that would otherwise forbid
	// issuance.
	err = wrapErr(dns.TypeCAA, "hostname", &dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess, Truncated: true},
	}, nil)
	test.AssertError(t, err, "expected error for truncated response")
	test.AssertContains(t, err.Error(), "response was truncated")
}
