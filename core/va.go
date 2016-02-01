// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

// ValidationAuthority defines the public interface for the Boulder VA
type ValidationAuthority interface {
	// [RegistrationAuthority] Deprecated; to be removed.
	UpdateValidations(Authorization, int) error
	// [RegistrationAuthority]
	UpdateValidation(*UpdateValidationRequest) error
	IsSafeDomain(*IsSafeDomainRequest) (*IsSafeDomainResponse, error)
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

// UpdateValidationRequest is the request struct for the UpdateValidation call.
type UpdateValidationRequest struct {
	// The authorization containing the challenge to update.
	Authorization Authorization

	// The index of the challenge in the authorization to update.
	ChallengeIndex int

	// Optional. JWK account key thumbprint in base64url form. If not specified,
	// account key validation is not performed.
	AccountKeyThumbprint string
}
