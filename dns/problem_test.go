package dns

import (
	"errors"
	"net"
	"testing"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/mocks"
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
		err := ProblemDetailsFromDNSError(tc.err)
		if err.Type != core.ConnectionProblem {
			t.Errorf("ProblemDetailsFromDNSError(%q).Type = %q, expected %q", tc.err, err.Type, core.ConnectionProblem)
		}
		if err.Detail != tc.expected {
			t.Errorf("ProblemDetailsFromDNSError(%q).Detail = %q, expected %q", tc.err, err.Detail, tc.expected)
		}
	}
}
