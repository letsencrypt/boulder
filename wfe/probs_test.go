package wfe

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"
)

func TestProblemDetailsFromError(t *testing.T) {
	// errMsg is used as the msg argument for `problemDetailsForError` and is
	// always returned in the problem detail.
	const errMsg = "testError"
	// detailMsg is used as the msg argument for the individual error types and is
	// sometimes not present in the produced problem's detail.
	const detailMsg = "testDetail"
	// fullDetail is what we expect the problem detail to look like when it
	// contains both the error message and the detail message
	fullDetail := fmt.Sprintf("%s :: %s", errMsg, detailMsg)
	testCases := []struct {
		err        error
		statusCode int
		problem    probs.ProblemType
		detail     string
	}{
		// boulder/core error types:
		//   Internal server errors expect just the `errMsg` in detail.
		{core.InternalServerError(detailMsg), 500, probs.ServerInternalProblem, errMsg},
		//   Other errors expect the full detail message
		{core.NotSupportedError(detailMsg), 501, probs.ServerInternalProblem, fullDetail},
		{core.MalformedRequestError(detailMsg), 400, probs.MalformedProblem, fullDetail},
		{core.UnauthorizedError(detailMsg), 403, probs.UnauthorizedProblem, fullDetail},
		{core.NotFoundError(detailMsg), 404, probs.MalformedProblem, fullDetail},
		{core.SignatureValidationError(detailMsg), 400, probs.MalformedProblem, fullDetail},
		{core.RateLimitedError(detailMsg), 429, probs.RateLimitedProblem, fullDetail},
		{core.BadNonceError(detailMsg), 400, probs.BadNonceProblem, fullDetail},
		//    The content length error has its own specific detail message
		{core.LengthRequiredError(detailMsg), 411, probs.MalformedProblem, "missing Content-Length header"},
		// boulder/errors error types
		//   Internal server errors expect just the `errMsg` in detail.
		{berrors.InternalServerError(detailMsg), 500, probs.ServerInternalProblem, errMsg},
		//   Other errors expect the full detail message
		{berrors.NotSupportedError(detailMsg), 501, probs.ServerInternalProblem, fullDetail},
		{berrors.MalformedError(detailMsg), 400, probs.MalformedProblem, fullDetail},
		{berrors.UnauthorizedError(detailMsg), 403, probs.UnauthorizedProblem, fullDetail},
		{berrors.NotFoundError(detailMsg), 404, probs.MalformedProblem, fullDetail},
		{berrors.SignatureValidationError(detailMsg), 400, probs.MalformedProblem, fullDetail},
		{berrors.RateLimitError(detailMsg), 429, probs.RateLimitedProblem, fullDetail},
		{berrors.InvalidEmailError(detailMsg), 400, probs.InvalidEmailProblem, fullDetail},
		{berrors.RejectedIdentifierError(detailMsg), 400, probs.RejectedIdentifierProblem, fullDetail},
	}
	for _, c := range testCases {
		p := problemDetailsForError(c.err, errMsg)
		if p.HTTPStatus != c.statusCode {
			t.Errorf("Incorrect status code for %s. Expected %d, got %d", reflect.TypeOf(c.err).Name(), c.statusCode, p.HTTPStatus)
		}
		if probs.ProblemType(p.Type) != c.problem {
			t.Errorf("Expected problem urn %#v, got %#v", c.problem, p.Type)
		}
		if p.Detail != c.detail {
			t.Errorf("Expected detailed message %q, got %q", c.detail, p.Detail)
		}
	}

	expected := &probs.ProblemDetails{
		Type:       probs.MalformedProblem,
		HTTPStatus: 200,
		Detail:     "gotcha",
	}
	p := problemDetailsForError(expected, "k")
	test.AssertDeepEquals(t, expected, p)
}
