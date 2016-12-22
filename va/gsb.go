// go:generate mockgen -source ./gsb.go -destination mock_gsb_test.go -package va

package va

import (
	safebrowsing "github.com/letsencrypt/go-safe-browsing-api"
	"golang.org/x/net/context"

	bgrpc "github.com/letsencrypt/boulder/grpc"
	vaPB "github.com/letsencrypt/boulder/va/proto"
)

// SafeBrowsing is an interface for a third-party safe browing API client.
type SafeBrowsing interface {
	// IsListed returns a non-empty string if the domain was bad. Specifically,
	// it is which Google Safe Browsing list the domain was found on.
	IsListed(url string) (list string, err error)
}

// IsSafeDomain returns true if the domain given is determined to be safe by a
// third-party safe browsing API. It's meant be called by the RA before pending
// authorization creation. If no third-party client was provided, it fails open
// and increments a Skips metric.
func (va *ValidationAuthorityImpl) IsSafeDomain(ctx context.Context, req *vaPB.IsSafeDomainRequest) (*vaPB.IsDomainSafe, error) {
	if req == nil || req.Domain == nil {
		return nil, bgrpc.ErrMissingParameters
	}
	stats := va.stats.NewScope("IsSafeDomain")
	stats.Inc("IsSafeDomain.Requests", 1)
	if va.safeBrowsing == nil {
		stats.Inc("IsSafeDomain.Skips", 1)
		status := true
		return &vaPB.IsDomainSafe{IsSafe: &status}, nil
	}

	list, err := va.safeBrowsing.IsListed(*req.Domain)
	if err != nil {
		stats.Inc("IsSafeDomain.Errors", 1)
		if err == safebrowsing.ErrOutOfDateHashes {
			stats.Inc("IsSafeDomain.OutOfDateHashErrors", 1)
			status := true
			return &vaPB.IsDomainSafe{IsSafe: &status}, nil
		}
		return nil, err
	}
	stats.Inc("IsSafeDomain.Successes", 1)
	status := (list == "")
	if status {
		stats.Inc("IsSafeDomain.Status.Good", 1)
	} else {
		stats.Inc("IsSafeDomain.Status.Bad", 1)
	}
	return &vaPB.IsDomainSafe{IsSafe: &status}, nil
}
