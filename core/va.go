// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import "golang.org/x/net/context"

// ValidationAuthority defines the public interface for the Boulder VA
type ValidationAuthority interface {
	// [RegistrationAuthority]
	// TODO(#1167): remove
	UpdateValidations(context.Context, Authorization, int) error
	// PerformValidation checks the challenge with the given index in the
	// given Authorization and returns the updated ValidationRecords.
	//
	// A failure to validate the Challenge will result in a error of type
	// *probs.ProblemDetails.
	//
	// TODO(#1626): remove authz parameter
	PerformValidation(context.Context, string, Challenge, Authorization) ([]ValidationRecord, error)
	IsSafeDomain(context.Context, *IsSafeDomainRequest) (*IsSafeDomainResponse, error)
}

// IsSafeDomainRequest is the request struct for the IsSafeDomain call. The Domain field
// should be just a domain with no leading scheme or trailing path.
type IsSafeDomainRequest struct {
	Domain string
}

// IsSafeDomainResponse is the response struct for the IsSafeDomain call. The
// IsSafe bool is true if and only if the third-party safe browing API says the
// domain is safe.
type IsSafeDomainResponse struct {
	IsSafe bool
}
