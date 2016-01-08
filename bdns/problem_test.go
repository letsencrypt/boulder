// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bdns

import (
	"errors"
	"net"
	"testing"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/golang.org/x/net/context"

	"github.com/letsencrypt/boulder/probs"
)

func TestProblemDetailsFromDNSError(t *testing.T) {
	testCases := []struct {
		err      error
		expected string
	}{
		{
			&dnsError{dns.TypeA, "hostname", MockTimeoutError(), -1},
			"DNS problem: query timed out looking up A for hostname",
		}, {
			errors.New("other failure"),
			detailServerFailure,
		}, {
			&dnsError{dns.TypeMX, "hostname", &net.OpError{Err: errors.New("some net error")}, -1},
			"DNS problem: networking error looking up MX for hostname",
		}, {
			&dnsError{dns.TypeTXT, "hostname", nil, dns.RcodeNameError},
			"DNS problem: NXDOMAIN looking up TXT for hostname",
		}, {
			&dnsError{dns.TypeTXT, "hostname", context.DeadlineExceeded, -1},
			"DNS problem: query timed out looking up TXT for hostname",
		}, {
			&dnsError{dns.TypeTXT, "hostname", context.Canceled, -1},
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
