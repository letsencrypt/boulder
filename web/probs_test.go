package web

import (
	"fmt"
	"reflect"
	"testing"

	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"
)

func TestProblemDetailsFromError(t *testing.T) {
	// errMsg is used as the msg argument for `ProblemDetailsForError` and is
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
		// boulder/errors error types
		//   Internal server errors expect just the `errMsg` in detail.
		{berrors.InternalServerError(detailMsg), 500, probs.ServerInternalProblem, errMsg},
		//   Other errors expect the full detail message
		{berrors.MalformedError(detailMsg), 400, probs.MalformedProblem, fullDetail},
		{berrors.UnauthorizedError(detailMsg), 403, probs.UnauthorizedProblem, fullDetail},
		{berrors.NotFoundError(detailMsg), 404, probs.MalformedProblem, fullDetail},
		{berrors.RateLimitError(detailMsg), 429, probs.RateLimitedProblem, fullDetail},
		{berrors.InvalidEmailError(detailMsg), 400, probs.InvalidEmailProblem, fullDetail},
		{berrors.RejectedIdentifierError(detailMsg), 400, probs.RejectedIdentifierProblem, fullDetail},
	}
	for _, c := range testCases {
		p := ProblemDetailsForError(c.err, errMsg)
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
	p := ProblemDetailsForError(expected, "k")
	test.AssertDeepEquals(t, expected, p)
}
