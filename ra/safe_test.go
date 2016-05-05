// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ra

import (
	"errors"
	"testing"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/test"
)

func TestChecksVASafeDomain(t *testing.T) {
	va, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()

	va.IsNotSafe = true

	_, err := ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	if err == nil {
		t.Errorf("want UnauthorizedError, got nil")
	} else if _, ok := err.(core.UnauthorizedError); !ok {
		t.Errorf("want UnauthorizedError, got %T", err)
	}
}

func TestHandlesVASafeDomainError(t *testing.T) {
	va, _, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	va.IsSafeDomainErr = errors.New("welp")

	_, err := ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	if err == nil {
		t.Errorf("want InternalServerError, got nil")
	} else if _, ok := err.(core.InternalServerError); !ok {
		t.Errorf("want InternalServerError, got %T", err)
	}
}

func TestAllowsNullSafeDomainCheck(t *testing.T) {
	_, sa, ra, _, cleanUp := initAuthorities(t)
	defer cleanUp()
	ra.dc = nil

	authz, err := ra.NewAuthorization(ctx, AuthzRequest, Registration.ID)
	test.AssertNotError(t, err, "NewAuthorization failed")

	dbAuthz, err := sa.GetAuthorization(ctx, authz.ID)
	test.AssertNotError(t, err, "Could not fetch authorization from database")
	assertAuthzEqual(t, authz, dbAuthz)
}
