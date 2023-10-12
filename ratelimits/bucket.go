package ratelimits

import (
	"fmt"
	"net"
	"strconv"

	"github.com/letsencrypt/boulder/core"
)

// Bucket identifies a specific subscriber rate limit bucket to the Limiter.
type Bucket struct {
	name Name
	key  string
}

// BucketWithCost is a bucket with an associated cost.
type BucketWithCost struct {
	Bucket
	cost int64
}

// WithCost returns a BucketWithCost for the provided cost.
func (b Bucket) WithCost(cost int64) BucketWithCost {
	return BucketWithCost{b, cost}
}

// NewRegistrationsPerIPAddressBucket returns a Bucket for the provided IP
// address.
func NewRegistrationsPerIPAddressBucket(ip net.IP) (Bucket, error) {
	id := ip.String()
	err := validateIdForName(NewRegistrationsPerIPAddress, id)
	if err != nil {
		return Bucket{}, err
	}
	return Bucket{
		name: NewRegistrationsPerIPAddress,
		key:  joinWithColon(NewRegistrationsPerIPAddress.EnumString(), id),
	}, nil
}

// NewRegistrationsPerIPv6RangeBucket returns a Bucket for the /48 IPv6 range
// containing the provided IPv6 address.
func NewRegistrationsPerIPv6RangeBucket(ip net.IP) (Bucket, error) {
	if ip.To4() != nil {
		return Bucket{}, fmt.Errorf("invalid IPv6 address, %q must be an IPv6 address", ip.String())
	}
	ipMask := net.CIDRMask(48, 128)
	ipNet := &net.IPNet{IP: ip.Mask(ipMask), Mask: ipMask}
	id := ipNet.String()
	err := validateIdForName(NewRegistrationsPerIPv6Range, id)
	if err != nil {
		return Bucket{}, err
	}
	return Bucket{
		name: NewRegistrationsPerIPv6Range,
		key:  joinWithColon(NewRegistrationsPerIPv6Range.EnumString(), id),
	}, nil
}

// NewOrdersPerAccountBucket returns a Bucket for the provided ACME registration
// Id.
func NewOrdersPerAccountBucket(regId int64) (Bucket, error) {
	id := strconv.FormatInt(regId, 10)
	err := validateIdForName(NewOrdersPerAccount, id)
	if err != nil {
		return Bucket{}, err
	}
	return Bucket{
		name: NewOrdersPerAccount,
		key:  joinWithColon(NewOrdersPerAccount.EnumString(), id),
	}, nil
}

// NewFailedAuthorizationsPerAccountBucket returns a Bucket for the provided
// ACME registration Id.
func NewFailedAuthorizationsPerAccountBucket(regId int64) (Bucket, error) {
	id := strconv.FormatInt(regId, 10)
	err := validateIdForName(FailedAuthorizationsPerAccount, id)
	if err != nil {
		return Bucket{}, err
	}
	return Bucket{
		name: FailedAuthorizationsPerAccount,
		key:  joinWithColon(FailedAuthorizationsPerAccount.EnumString(), id),
	}, nil
}

// NewCertificatesPerDomainBucket returns a Bucket for the provided order domain
// name.
func NewCertificatesPerDomainBucket(orderName string) (Bucket, error) {
	err := validateIdForName(CertificatesPerDomain, orderName)
	if err != nil {
		return Bucket{}, err
	}
	return Bucket{
		name: CertificatesPerDomain,
		key:  joinWithColon(CertificatesPerDomain.EnumString(), orderName),
	}, nil
}

// NewCertificatesPerDomainPerAccountBucket returns a Bucket for the provided
// ACME registration Id.
func NewCertificatesPerDomainPerAccountBucket(regId int64) (Bucket, error) {
	id := strconv.FormatInt(regId, 10)
	err := validateIdForName(CertificatesPerDomainPerAccount, id)
	if err != nil {
		return Bucket{}, err
	}
	return Bucket{
		name: CertificatesPerDomainPerAccount,
		key:  joinWithColon(CertificatesPerDomainPerAccount.EnumString(), id),
	}, nil
}

// NewCertificatesPerDomainBucketsWithCost returns a slice of BucketWithCost for
// the provided order domain names and an additional BucketWithCost for
// certificatesPerDomainPerAccount.
func NewCertificatesPerDomainBucketsWithCost(regId int64, orderDomains []string, cost int64) ([]BucketWithCost, error) {
	var buckets []BucketWithCost
	for _, name := range DomainsForRateLimiting(orderDomains) {
		bucket, err := NewCertificatesPerDomainBucket(name)
		if err != nil {
			return nil, err
		}
		buckets = append(buckets, bucket.WithCost(cost))
	}
	bucket, err := NewCertificatesPerDomainPerAccountBucket(regId)
	if err != nil {
		return nil, err
	}
	buckets = append(buckets, bucket.WithCost(cost))
	return buckets, nil
}

// NewCertificatesPerFQDNSetBucket returns a Bucket for the provided order
// domain names.
func NewCertificatesPerFQDNSetBucket(orderNames []string) (Bucket, error) {
	id := string(core.HashNames(orderNames))
	err := validateIdForName(CertificatesPerFQDNSet, id)
	if err != nil {
		return Bucket{}, err
	}
	return Bucket{
		name: CertificatesPerFQDNSet,
		key:  joinWithColon(CertificatesPerFQDNSet.EnumString(), id),
	}, nil
}
