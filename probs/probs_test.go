package probs

import (
	"testing"

	"net/http"

	"github.com/letsencrypt/boulder/test"
)

func TestProblemDetails(t *testing.T) {
	pd := &ProblemDetails{
		Type:       MalformedProblem,
		Detail:     "Wat? o.O",
		HTTPStatus: 403,
	}
	test.AssertEquals(t, pd.Error(), "urn:acme:error:malformed :: Wat? o.O")
}

func TestProblemDetailsToStatusCode(t *testing.T) {
	testCases := []struct {
		pb         *ProblemDetails
		statusCode int
	}{
		{&ProblemDetails{Type: ConnectionProblem}, http.StatusBadRequest},
		{&ProblemDetails{Type: MalformedProblem}, http.StatusBadRequest},
		{&ProblemDetails{Type: ServerInternalProblem}, http.StatusInternalServerError},
		{&ProblemDetails{Type: TLSProblem}, http.StatusBadRequest},
		{&ProblemDetails{Type: UnauthorizedProblem}, http.StatusForbidden},
		{&ProblemDetails{Type: UnknownHostProblem}, http.StatusBadRequest},
		{&ProblemDetails{Type: RateLimitedProblem}, statusTooManyRequests},
		{&ProblemDetails{Type: BadNonceProblem}, http.StatusBadRequest},
		{&ProblemDetails{Type: InvalidEmailProblem}, http.StatusBadRequest},
		{&ProblemDetails{Type: "foo"}, http.StatusInternalServerError},
		{&ProblemDetails{Type: "foo", HTTPStatus: 200}, 200},
		{&ProblemDetails{Type: ConnectionProblem, HTTPStatus: 200}, 200},
	}

	for _, c := range testCases {
		p := ProblemDetailsToStatusCode(c.pb)
		if c.statusCode != p {
			t.Errorf("Incorrect status code for %s. Expected %d, got %d", c.pb.Type, c.statusCode, p)
		}
	}
}
