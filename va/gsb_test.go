// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package va

import (
	"errors"
	"testing"

	"github.com/cactus/go-statsd-client/statsd"
	"github.com/golang/mock/gomock"
	"github.com/jmhodges/clock"
	safebrowsing "github.com/letsencrypt/go-safe-browsing-api"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
)

func TestIsSafeDomain(t *testing.T) {
	// TODO(jmhodges): use more of the GSB lib by teaching it how to not make
	// http requests
	// This test is mocked out at the wrong level (SafeBrowsing) because the gsb lib
	// we rely on is a little funny and overcomplicated, but still hasn't
	// learned out how not make HTTP requests in tests.

	stats, _ := statsd.NewNoopClient()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	sbc := NewMockSafeBrowsing(ctrl)
	sbc.EXPECT().IsListed("good.com").Return("", nil)
	sbc.EXPECT().IsListed("bad.com").Return("bad", nil)
	sbc.EXPECT().IsListed("errorful.com").Return("", errors.New("welp"))
	sbc.EXPECT().IsListed("outofdate.com").Return("", safebrowsing.ErrOutOfDateHashes)
	va := NewValidationAuthorityImpl(&cmd.PortConfig{}, sbc, nil, stats, clock.NewFake())

	resp, err := va.IsSafeDomain(ctx, &core.IsSafeDomainRequest{Domain: "good.com"})
	if err != nil {
		t.Errorf("good.com: want no error, got '%s'", err)
	}
	if !resp.IsSafe {
		t.Errorf("good.com: want true, got %t", resp.IsSafe)
	}
	resp, err = va.IsSafeDomain(ctx, &core.IsSafeDomainRequest{Domain: "bad.com"})
	if err != nil {
		t.Errorf("bad.com: want no error, got '%s'", err)
	}
	if resp.IsSafe {
		t.Errorf("bad.com: want false, got %t", resp.IsSafe)
	}
	_, err = va.IsSafeDomain(ctx, &core.IsSafeDomainRequest{Domain: "errorful.com"})
	if err == nil {
		t.Errorf("errorful.com: want error, got none")
	}
	resp, err = va.IsSafeDomain(ctx, &core.IsSafeDomainRequest{Domain: "outofdate.com"})
	if err != nil {
		t.Errorf("outofdate.com: want no error, got '%s'", err)
	}
	if !resp.IsSafe {
		t.Errorf("outofdate.com: IsSafeDomain should fail open on out of date hashes")
	}
}

func TestAllowNilInIsSafeDomain(t *testing.T) {
	stats, _ := statsd.NewNoopClient()
	va := NewValidationAuthorityImpl(&cmd.PortConfig{}, nil, nil, stats, clock.NewFake())

	// Be cool with a nil SafeBrowsing. This will happen in prod when we have
	// flag mismatch between the VA and RA.
	resp, err := va.IsSafeDomain(ctx, &core.IsSafeDomainRequest{Domain: "example.com"})
	if err != nil {
		t.Errorf("nil SafeBrowsing, unexpected error: %s", err)
	} else if !resp.IsSafe {
		t.Errorf("nil Safebrowsing, should fail open but failed closed")
	}
}
