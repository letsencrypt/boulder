// go:generate mockgen -source ./gsb.go -destination mock_gsb_test.go -package va

package va

import (
	safebrowsing "github.com/letsencrypt/go-safe-browsing-api"
	"golang.org/x/net/context"

	bgrpc "github.com/letsencrypt/boulder/grpc"
	vaPB "github.com/letsencrypt/boulder/va/proto"
)

// SafeBrowsing is an interface for an third-party safe browing API client.
type SafeBrowsing interface {
	// IsListed returns a non-empty string if the domain was bad. Specifically,
	// that list is which Google Safe Browsing list the domain was found on.
	IsListed(url string) (list string, err error)
}

// IsSafeDomain returns true if the domain given is determined to be safe by an
// third-party safe browsing API. It's meant be called by the RA before pending
// authorization creation. If no third-party client was provided, it fails open
// and increments a Skips metric.
func (va *ValidationAuthorityImpl) IsSafeDomain(ctx context.Context, req *vaPB.IsSafeDomainRequest) (*vaPB.IsDomainSafe, error) {
	if req == nil || req.Domain == nil {
		return nil, bgrpc.ErrMissingParameters
	}
	va.stats.Inc("VA.IsSafeDomain.Requests", 1, 1.0)
	if va.safeBrowsing == nil {
		va.stats.Inc("VA.IsSafeDomain.Skips", 1, 1.0)
		status := true
		return &vaPB.IsDomainSafe{IsSafe: &status}, nil
	}

	list, err := va.safeBrowsing.IsListed(*req.Domain)
	if err != nil {
		va.stats.Inc("VA.IsSafeDomain.Errors", 1, 1.0)
		if err == safebrowsing.ErrOutOfDateHashes {
			va.stats.Inc("VA.IsSafeDomain.OutOfDateHashErrors", 1, 1.0)
			status := true
			return &vaPB.IsDomainSafe{IsSafe: &status}, nil
		}
		return nil, err
	}
	va.stats.Inc("VA.IsSafeDomain.Successes", 1, 1.0)
	status := (list == "")
	if status {
		va.stats.Inc("VA.IsSafeDomain.Status.Good", 1, 1.0)
	} else {
		va.stats.Inc("VA.IsSafeDomain.Status.Bad", 1, 1.0)
	}
	return &vaPB.IsDomainSafe{IsSafe: &status}, nil
}
