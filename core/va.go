package core

import "golang.org/x/net/context"

// ValidationAuthority defines the public interface for the Boulder VA
type ValidationAuthority interface {
	// PerformValidation checks the challenge with the given index in the
	// given Authorization and returns the updated ValidationRecords.
	//
	// A failure to validate the Challenge will result in a error of type
	// *probs.ProblemDetails.
	//
	// TODO(#1626): remove authz parameter
	PerformValidation(ctx context.Context, domain string, challenge Challenge, authz Authorization) ([]ValidationRecord, error)
}
