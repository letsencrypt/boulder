package bdns

import (
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

func TestDNSError(t *testing.T) {
	testCases := []struct {
		err      error
		expected string
	}{
		{
			&DNSError{dns.TypeA, "hostname", MockTimeoutError(), -1},
			"DNS problem: query timed out looking up A for hostname",
		}, {
			&DNSError{dns.TypeMX, "hostname", &net.OpError{Err: errors.New("some net error")}, -1},
			"DNS problem: networking error looking up MX for hostname",
		}, {
			&DNSError{dns.TypeTXT, "hostname", nil, dns.RcodeNameError},
			"DNS problem: NXDOMAIN looking up TXT for hostname",
		}, {
			&DNSError{dns.TypeTXT, "hostname", context.DeadlineExceeded, -1},
			"DNS problem: query timed out looking up TXT for hostname",
		}, {
			&DNSError{dns.TypeTXT, "hostname", context.Canceled, -1},
			"DNS problem: query timed out looking up TXT for hostname",
		},
	}
	for _, tc := range testCases {
		if tc.err.Error() != tc.expected {
			t.Errorf("got %q, expected %q", tc.err.Error(), tc.expected)
		}
	}
}
