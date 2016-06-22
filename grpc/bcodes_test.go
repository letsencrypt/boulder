package grpc

import (
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"
)

func TestErrorToProb(t *testing.T) {
	prob := ErrorToProb(CodedError(codes.Aborted, "it's an error!"))
	test.AssertEquals(t, prob.Detail, "it's an error!")
	test.AssertEquals(t, prob.Type, probs.ServerInternalProblem)
	prob = ErrorToProb(CodedError(DNSQueryTimeout, ""))
	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)
	prob = ErrorToProb(CodedError(DNSError, ""))
	test.AssertEquals(t, prob.Type, probs.ConnectionProblem)
}
