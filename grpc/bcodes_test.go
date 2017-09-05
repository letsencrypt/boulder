package grpc

import (
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"
)

func TestErrors(t *testing.T) {
	testcases := []struct {
		err          error
		expectedCode codes.Code
	}{
		{&probs.ProblemDetails{Type: probs.ConnectionProblem, Detail: "testing..."}, ProblemDetails},
	}

	for _, tc := range testcases {
		wrappedErr := wrapError(nil, tc.err)
		test.AssertEquals(t, grpc.Code(wrappedErr), tc.expectedCode)
		test.AssertDeepEquals(t, tc.err, unwrapError(wrappedErr, nil))
	}

	test.AssertEquals(t, wrapError(nil, nil), nil)
	test.AssertEquals(t, unwrapError(nil, nil), nil)
}
