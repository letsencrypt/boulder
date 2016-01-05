// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bdns

import (
	"errors"
	"net"
	"testing"

	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/probs"
)

func TestProblemDetailsFromDNSError(t *testing.T) {
	testCases := []struct {
		err      error
		expected string
	}{
		{
			mocks.TimeoutError(),
			detailDNSTimeout,
		}, {
			errors.New("other failure"),
			detailServerFailure,
		}, {
			&net.OpError{Err: errors.New("some net error")},
			detailDNSNetFailure,
		},
	}
	for _, tc := range testCases {
		err := ProblemDetailsFromDNSError("TXT", "example.com", tc.err)
		if err.Type != probs.ConnectionProblem {
			t.Errorf("ProblemDetailsFromDNSError(%q).Type = %q, expected %q", tc.err, err.Type, probs.ConnectionProblem)
		}
		exp := tc.expected + " during TXT-record lookup of example.com"
		if err.Detail != exp {
			t.Errorf("ProblemDetailsFromDNSError(%q).Detail = %q, expected %q", tc.err, err.Detail, tc.expected)
		}
	}
}
