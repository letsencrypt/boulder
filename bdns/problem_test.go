package bdns

import (
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
	"golang.org/x/net/context"

	"github.com/letsencrypt/boulder/probs"
)

func TestProblemDetailsFromDNSError(t *testing.T) {
	testCases := []struct {
		err      error
		expected string
	}{
		{
			&DNSError{dns.TypeA, "hostname", MockTimeoutError(), -1},
			"DNS problem: query timed out looking up A for hostname",
		}, {
			errors.New("other failure"),
			detailServerFailure,
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
		err := ProblemDetailsFromDNSError(tc.err)
		if err.Type != probs.ConnectionProblem {
			t.Errorf("ProblemDetailsFromDNSError(%q).Type = %q, expected %q", tc.err, err.Type, probs.ConnectionProblem)
		}
		if err.Detail != tc.expected {
			t.Errorf("ProblemDetailsFromDNSError(%q).Detail = %q, expected %q", tc.err, err.Detail, tc.expected)
		}
	}
}
