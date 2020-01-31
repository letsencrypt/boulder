package wfe2

import (
	"net/http"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/web"
)

func TestRequiredStale(t *testing.T) {
	testCases := []struct {
		name           string
		req            *http.Request
		logEvent       *web.RequestEvent
		expectRequired bool
	}{
		{
			name:           "not GET",
			req:            &http.Request{Method: http.MethodPost},
			logEvent:       &web.RequestEvent{},
			expectRequired: false,
		},
		{
			name:           "GET, not getAPIPrefix",
			req:            &http.Request{Method: http.MethodGet},
			logEvent:       &web.RequestEvent{},
			expectRequired: false,
		},
		{
			name:           "GET, getAPIPrefix",
			req:            &http.Request{Method: http.MethodGet},
			logEvent:       &web.RequestEvent{Endpoint: getAPIPrefix + "whatever"},
			expectRequired: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			test.AssertEquals(t, requiredStale(tc.req, tc.logEvent), tc.expectRequired)
		})
	}
}

func TestSaleEnoughToGETOrder(t *testing.T) {
	fc := clock.NewFake()
	wfe := WebFrontEndImpl{clk: fc, staleTimeout: time.Minute * 30}
	fc.Add(time.Hour * 24)
	created := fc.Now().UnixNano()
	fc.Add(time.Hour)
	prob := wfe.staleEnoughToGETOrder(&corepb.Order{
		Created: &created,
	})
	test.Assert(t, prob == nil, "wfe.staleEnoughToGETOrder returned a non-nil problem")
}
