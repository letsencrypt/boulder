package va

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	vaPB "github.com/letsencrypt/boulder/va/proto"
)

func TestIsSafeDomain(t *testing.T) {
	// TODO(jmhodges): use more of the GSB lib by teaching it how to not make
	// http requests
	// This test is mocked out at the wrong level (SafeBrowsing) because the gsb lib
	// we rely on is a little funny and overcomplicated, but still hasn't
	// learned out how not make HTTP requests in tests.

	stats := metrics.NewNoopScope()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	sbc := NewMockSafeBrowsing(ctrl)
	sbc.EXPECT().IsListed("good.com").Return("", nil)
	sbc.EXPECT().IsListed("bad.com").Return("bad", nil)
	sbc.EXPECT().IsListed("errorful.com").Return("", errors.New("welp"))
	va := NewValidationAuthorityImpl(
		&cmd.PortConfig{},
		sbc,
		nil,
		nil,
		0,
		"user agent 1.0",
		"letsencrypt.org",
		stats,
		clock.NewFake(),
		blog.NewMock())

	domain := "good.com"
	resp, err := va.IsSafeDomain(ctx, &vaPB.IsSafeDomainRequest{Domain: &domain})
	if err != nil {
		t.Errorf("good.com: want no error, got '%s'", err)
	}
	if !resp.GetIsSafe() {
		t.Errorf("good.com: want true, got %t", resp.GetIsSafe())
	}

	domain = "bad.com"
	resp, err = va.IsSafeDomain(ctx, &vaPB.IsSafeDomainRequest{Domain: &domain})
	if err != nil {
		t.Errorf("bad.com: want no error, got '%s'", err)
	}
	if resp.GetIsSafe() {
		t.Errorf("bad.com: want false, got %t", resp.GetIsSafe())
	}

	// If there is an error looking up a domain (e.g. because of a GSB outage),
	// then we expect the VA to allow the authz to be created without error.
	domain = "errorful.com"
	resp, err = va.IsSafeDomain(ctx, &vaPB.IsSafeDomainRequest{Domain: &domain})
	if err != nil {
		t.Errorf("errorful.com: want no error, got %v", resp)
	}
	if !resp.GetIsSafe() {
		t.Errorf("errorful.com: want true, got %t", resp.GetIsSafe())
	}
}

func TestAllowNilInIsSafeDomain(t *testing.T) {
	stats := metrics.NewNoopScope()
	va := NewValidationAuthorityImpl(
		&cmd.PortConfig{},
		nil,
		nil,
		nil,
		0,
		"user agent 1.0",
		"letsencrypt.org",
		stats,
		clock.NewFake(),
		blog.NewMock())

	// Be cool with a nil SafeBrowsing. This will happen in prod when we have
	// flag mismatch between the VA and RA.
	domain := "example.com"
	resp, err := va.IsSafeDomain(ctx, &vaPB.IsSafeDomainRequest{Domain: &domain})
	if err != nil {
		t.Errorf("nil SafeBrowsing, unexpected error: %s", err)
	}
	if !resp.GetIsSafe() {
		t.Errorf("nil Safebrowsing, should fail open but failed closed")
	}
}
