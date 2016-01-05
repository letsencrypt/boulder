// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bdns

import (
	"fmt"
	"net"

	"github.com/letsencrypt/boulder/probs"
)

const detailDNSTimeout = "DNS query timed out"
const detailDNSNetFailure = "DNS networking error"
const detailServerFailure = "Server failure at resolver"

// ProblemDetailsFromDNSError checks the error returned from Lookup...  methods
// and tests if the error was an underlying net.OpError or an error caused by
// resolver returning SERVFAIL or other invalid Rcodes and returns the relevant
// core.ProblemDetails. The detail string will contain a mention of the DNS
// record type and domain given.
func ProblemDetailsFromDNSError(recordType, domain string, err error) *probs.ProblemDetails {
	detail := detailServerFailure
	if netErr, ok := err.(*net.OpError); ok {
		if netErr.Timeout() {
			detail = detailDNSTimeout
		} else {
			detail = detailDNSNetFailure
		}
	}
	detail = fmt.Sprintf("%s during %s-record lookup of %s", detail, recordType, domain)
	return &probs.ProblemDetails{
		Type:   probs.ConnectionProblem,
		Detail: detail,
	}
}
