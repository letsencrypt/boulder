// go:generate mockgen -source ./gsb.go -destination mock_gsb_test.go -package va SafeBrowsing

package va

import (
	safebrowsingv4 "github.com/google/safebrowsing"
	"golang.org/x/net/context"

	"github.com/letsencrypt/boulder/canceled"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	vaPB "github.com/letsencrypt/boulder/va/proto"
)

// SafeBrowsing is an interface for a third-party safe browsing API client.
type SafeBrowsing interface {
	// IsListed returns a non-empty string if the domain was bad. Specifically,
	// it is which Google Safe Browsing list the domain was found on.
	IsListed(ctx context.Context, url string) (list string, err error)
}

// SafeBrowsingV4 is an interface around the functions from Google
// safebrowsing's v4 API's *SafeBrowser type that we use. Using this interface
// allows mocking for tests
type SafeBrowsingV4 interface {
	LookupURLsContext(ctx context.Context, urls []string) (threats [][]safebrowsingv4.URLThreat, err error)
}

// IsSafeDomain returns true if the domain given is determined to be safe by a
// third-party safe browsing API. It's meant be called by the RA before pending
// authorization creation. If no third-party client was provided, it fails open
// and increments a Skips metric.
func (va *ValidationAuthorityImpl) IsSafeDomain(ctx context.Context, req *vaPB.IsSafeDomainRequest) (*vaPB.IsDomainSafe, error) {
	if req == nil || req.Domain == nil {
		return nil, bgrpc.ErrMissingParameters
	}
	status := va.isSafeDomain(ctx, *req.Domain)
	return &vaPB.IsDomainSafe{IsSafe: &status}, nil
}

// isSafeDomain returns true if the VA considers the given domain safe. If the
// backend errors, we consider the domain safe, so this function never returns
// error.
func (va *ValidationAuthorityImpl) isSafeDomain(ctx context.Context, domain string) bool {
	stats := va.stats.NewScope("IsSafeDomain")
	stats.Inc("IsSafeDomain.Requests", 1)
	if va.safeBrowsing == nil {
		stats.Inc("IsSafeDomain.Skips", 1)
		return true
	}

	list, err := va.safeBrowsing.IsListed(ctx, domain)
	if canceled.Is(err) {
		// Sometimes an IsListed request will be canceled because the main
		// validation failed, causing the parent context to be canceled.
		stats.Inc("IsSafeDomain.Canceled", 1)
		return true
	}
	if err != nil {
		stats.Inc("IsSafeDomain.Errors", 1)
		// In the event of an error checking the GSB status we allow the domain in
		// question to be treated as safe to avoid coupling the availability of the
		// VA to the GSB API. This is acceptable for Let's Encrypt because we do not
		// have a hard commitment to GSB filtering in our CP/CPS.
		return true
	}
	stats.Inc("IsSafeDomain.Successes", 1)
	if list == "" {
		stats.Inc("IsSafeDomain.Status.Good", 1)
		return true
	}
	stats.Inc("IsSafeDomain.Status.Bad", 1)
	return false
}
