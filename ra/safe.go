// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ra

import (
	"github.com/letsencrypt/boulder/core"
	"golang.org/x/net/context"
)

// TODO(jmhodges): remove once VA is deployed and stable with IsSafeDomain
// replace with just a call to ra.VA.IsSafeDomain

// DomainCheck is a little struct that allows the RA to call the VA's
// IsSafeDomain if its not-nil, or fails open if not. This is so that the RA can
// be deployed before the VA can respond to the IsSafeDomain RPC.
type DomainCheck struct {
	VA core.ValidationAuthority
}

// IsSafe returns true if the VA's IsSafeDomain RPC says the domain is safe or
// if DomainCheck is nil.
func (d *DomainCheck) IsSafe(ctx context.Context, domain string) (bool, error) {
	// This nil check allows us to not actually call
	if d == nil {
		return true, nil
	}

	resp, err := d.VA.IsSafeDomain(ctx, &core.IsSafeDomainRequest{Domain: domain})
	if err != nil {
		return false, err
	}
	return resp.IsSafe, nil
}
