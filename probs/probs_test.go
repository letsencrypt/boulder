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

func TestProblemDetailsConvenience(t *testing.T) {
	testCases := []struct {
		pb           *ProblemDetails
		expectedType ProblemType
		statusCode   int
		detail       string
	}{
		{InvalidEmail("invalid email detail"), InvalidEmailProblem, http.StatusBadRequest, "invalid email detail"},
		{ConnectionFailure("connection failure detail"), ConnectionProblem, http.StatusBadRequest, "connection failure detail"},
		{Malformed("malformed detail"), MalformedProblem, http.StatusBadRequest, "malformed detail"},
		{ServerInternal("internal error detail"), ServerInternalProblem, http.StatusInternalServerError, "internal error detail"},
		{Unauthorized("unauthorized detail"), UnauthorizedProblem, http.StatusForbidden, "unauthorized detail"},
		{UnknownHost("unknown host detail"), UnknownHostProblem, http.StatusBadRequest, "unknown host detail"},
		{RateLimited("rate limited detail"), RateLimitedProblem, statusTooManyRequests, "rate limited detail"},
		{BadNonce("bad nonce detail"), BadNonceProblem, http.StatusBadRequest, "bad nonce detail"},
		{TLSError("TLS error detail"), TLSProblem, http.StatusBadRequest, "TLS error detail"},
		{RejectedIdentifier("rejected identifier detail"), RejectedIdentifierProblem, http.StatusBadRequest, "rejected identifier detail"},
		{UnsupportedIdentifier("unsupported identifier detail"), UnsupportedIdentifierProblem, http.StatusBadRequest, "unsupported identifier detail"},
	}

	for _, c := range testCases {
		if c.pb.Type != c.expectedType {
			t.Errorf("Incorrect problem type. Expected %s got %s", c.expectedType, c.pb.Type)
		}

		if c.pb.HTTPStatus != c.statusCode {
			t.Errorf("Incorrect HTTP Status. Expected %d got %d", c.statusCode, c.pb.HTTPStatus)
		}

		if c.pb.Detail != c.detail {
			t.Errorf("Incorrect detail message. Expected %s got %s", c.detail, c.pb.Detail)
		}
	}
}
