package grpc

import (
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"
)

func TestErrors(t *testing.T) {
	testcases := []struct {
		err          error
		expectedCode codes.Code
	}{
		{core.MalformedRequestError("test 1"), MalformedRequestError},
		{core.NotSupportedError("test 2"), NotSupportedError},
		{core.UnauthorizedError("test 3"), UnauthorizedError},
		{core.NotFoundError("test 4"), NotFoundError},
		{core.LengthRequiredError("test 5"), LengthRequiredError},
		{core.SignatureValidationError("test 6"), SignatureValidationError},
		{core.RateLimitedError("test 7"), RateLimitedError},
		{core.BadNonceError("test 8"), BadNonceError},
		{core.NoSuchRegistrationError("test 9"), NoSuchRegistrationError},
		{core.InternalServerError("test 10"), InternalServerError},
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
