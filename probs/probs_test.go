package probs

import (
	"testing"

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
