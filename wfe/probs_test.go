package wfe

import (
	"reflect"
	"testing"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"
)

func TestProblemDetailsFromError(t *testing.T) {
	testCases := []struct {
		err        error
		statusCode int
		problem    probs.ProblemType
	}{
		// boulder/core error types
		{core.InternalServerError("foo"), 500, probs.ServerInternalProblem},
		{core.NotSupportedError("foo"), 501, probs.ServerInternalProblem},
		{core.MalformedRequestError("foo"), 400, probs.MalformedProblem},
		{core.UnauthorizedError("foo"), 403, probs.UnauthorizedProblem},
		{core.NotFoundError("foo"), 404, probs.MalformedProblem},
		{core.SignatureValidationError("foo"), 400, probs.MalformedProblem},
		{core.RateLimitedError("foo"), 429, probs.RateLimitedProblem},
		{core.LengthRequiredError("foo"), 411, probs.MalformedProblem},
		{core.BadNonceError("foo"), 400, probs.BadNonceProblem},
		// boulder/errors error types
		{berrors.InternalServerError("foo"), 500, probs.ServerInternalProblem},
		{berrors.NotSupportedError("foo"), 501, probs.ServerInternalProblem},
		{berrors.MalformedError("foo"), 400, probs.MalformedProblem},
		{berrors.UnauthorizedError("foo"), 403, probs.UnauthorizedProblem},
		{berrors.NotFoundError("foo"), 404, probs.MalformedProblem},
		{berrors.SignatureValidationError("foo"), 400, probs.MalformedProblem},
		{berrors.RateLimitError("foo"), 429, probs.RateLimitedProblem},
		{berrors.InvalidEmailError("foo"), 400, probs.InvalidEmailProblem},
	}
	for _, c := range testCases {
		p := problemDetailsForError(c.err, "k")
		if p.HTTPStatus != c.statusCode {
			t.Errorf("Incorrect status code for %s. Expected %d, got %d", reflect.TypeOf(c.err).Name(), c.statusCode, p.HTTPStatus)
		}
		if probs.ProblemType(p.Type) != c.problem {
			t.Errorf("Expected problem urn %#v, got %#v", c.problem, p.Type)
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
