package ratelimits

import (
	"fmt"
	"net"
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
