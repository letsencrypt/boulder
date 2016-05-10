// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"golang.org/x/net/context"

	vaPB "github.com/letsencrypt/boulder/va/proto"
)

// ValidationAuthority defines the public interface for the Boulder VA
type ValidationAuthority interface {
	// [RegistrationAuthority]
	// TODO(#1167): remove
	UpdateValidations(ctx context.Context, authz Authorization, challengeIndex int) error
	// PerformValidation checks the challenge with the given index in the
	// given Authorization and returns the updated ValidationRecords.
	//
	// A failure to validate the Challenge will result in a error of type
	// *probs.ProblemDetails.
	//
	// TODO(#1626): remove authz parameter
	PerformValidation(ctx context.Context, domain string, challenge Challenge, authz Authorization) ([]ValidationRecord, error)
	IsSafeDomain(ctx context.Context, req *vaPB.IsSafeDomainRequest) (resp *vaPB.IsDomainSafe, err error)
}
