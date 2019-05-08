package errors

import (
	"testing"

	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/test"
)

// TestWithSubErrors tests that a top level boulder error can be updated with
// suberrors.
func TestWithSubErrors(t *testing.T) {
	topErr := RateLimitError("don't you think you have enough certificates already?")

	initialSubErrors := []SubBoulderError{
		SubBoulderError{
			Identifier:   identifier.DNSIdentifier("example.com"),
			BoulderError: *RateLimitError("everyone uses this example domain"),
		},
		SubBoulderError{
			Identifier:   identifier.DNSIdentifier("what about example.com"),
			BoulderError: *RateLimitError("try a real identifier value next time"),
		},
	}

	moreSubErrors := []SubBoulderError{
		SubBoulderError{
			Identifier:   identifier.DNSIdentifier("letsencrypt.org"),
			BoulderError: *UnauthorizedError("nope"),
		},
	}

	outResult := topErr.WithSubErrors(initialSubErrors)
	test.AssertEquals(t, topErr, outResult)
	test.AssertEquals(t, len(topErr.SubErrors), len(initialSubErrors))
	_ = topErr.WithSubErrors(moreSubErrors)
	test.AssertEquals(t, len(topErr.SubErrors), len(initialSubErrors)+len(moreSubErrors))
}
