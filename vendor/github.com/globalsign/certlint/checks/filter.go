package checks

import (
	"time"

	"github.com/globalsign/certlint/certdata"
)

// Filter defines condition on when a check is performed or not
type Filter struct {
	Type          []string
	IssuedBefore  *time.Time
	IssuedAfter   *time.Time
	ExpiresBefore *time.Time
	ExpiresAfter  *time.Time
}

// Check returns true if a certificate complies with the given filter
func (f *Filter) Check(d *certdata.Data) bool {
	// Is certificate recognised as one of the given types
	if len(f.Type) > 0 {
		var inFilter bool
		for _, t := range f.Type {
			if d.Type == t {
				inFilter = true
			}
		}
		if !inFilter {
			return false
		}
	}

	// Issued before given date
	if f.IssuedBefore != nil && !d.Cert.NotBefore.Before(*f.IssuedBefore) {
		return false
	}
	// Issued after given date
	if f.IssuedAfter != nil && !d.Cert.NotBefore.After(*f.IssuedAfter) {
		return false
	}
	// Expires before given date
	if f.ExpiresBefore != nil && !d.Cert.NotBefore.Before(*f.ExpiresBefore) {
		return false
	}
	// Expires after given date
	if f.ExpiresAfter != nil && !d.Cert.NotAfter.After(*f.ExpiresAfter) {
		return false
	}

	return true
}
