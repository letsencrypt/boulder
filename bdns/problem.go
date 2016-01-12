// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bdns

import (
	"fmt"
	"net"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/golang.org/x/net/context"
	"github.com/letsencrypt/boulder/probs"
)

type dnsError struct {
	recordType uint16
	hostname   string
	// Exactly one of rCode or underlying should be set.
	underlying error
	rCode      int
}

func (d dnsError) Error() string {
	var detail string
	if d.underlying != nil {
		if netErr, ok := d.underlying.(*net.OpError); ok {
			if netErr.Timeout() {
				detail = detailDNSTimeout
			} else {
				detail = detailDNSNetFailure
			}
		} else if d.underlying == context.Canceled || d.underlying == context.DeadlineExceeded {
			detail = detailDNSTimeout
		} else {
			detail = detailServerFailure
		}
	} else if d.rCode != dns.RcodeSuccess {
		detail = dns.RcodeToString[d.rCode]
	} else {
		detail = detailServerFailure
	}
	return fmt.Sprintf("DNS problem: %s looking up %s for %s", detail,
		dns.TypeToString[d.recordType], d.hostname)
}

const detailDNSTimeout = "query timed out"
const detailDNSNetFailure = "networking error"
const detailServerFailure = "server failure at resolver"

// ProblemDetailsFromDNSError checks the error returned from Lookup...  methods
// and tests if the error was an underlying net.OpError or an error caused by
// resolver returning SERVFAIL or other invalid Rcodes and returns the relevant
// core.ProblemDetails. The detail string will contain a mention of the DNS
// record type and domain given.
func ProblemDetailsFromDNSError(err error) *probs.ProblemDetails {
	if dnsErr, ok := err.(*dnsError); ok {
		return &probs.ProblemDetails{
			Type:   probs.ConnectionProblem,
			Detail: dnsErr.Error(),
		}
	}
	return &probs.ProblemDetails{
		Type:   probs.ConnectionProblem,
		Detail: detailServerFailure,
	}
}
