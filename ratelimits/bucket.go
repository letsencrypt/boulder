package ratelimits

import (
	"fmt"
	"net"
)

// BucketId should only be created using the New*BucketId functions. It is used
// by the Limiter to look up the bucket and limit overrides for a specific
// subscriber and limit.
type BucketId struct {
	// limit is the name of the associated rate limit. It is used for looking up
	// default limits.
	limit Name

	// bucketKey is the limit Name enum (e.g. "1") concatenated with the
	// subscriber identifier specific to the associate limit Name type.
	bucketKey string
}

// NewRegistrationsPerIPAddressBucketId returns a BucketId for the provided IP
// address.
func NewRegistrationsPerIPAddressBucketId(ip net.IP) (BucketId, error) {
	id := ip.String()
	err := validateIdForName(NewRegistrationsPerIPAddress, id)
	if err != nil {
		return BucketId{}, err
	}
	return BucketId{
		limit:     NewRegistrationsPerIPAddress,
		bucketKey: joinWithColon(NewRegistrationsPerIPAddress.EnumString(), id),
	}, nil
}

// NewRegistrationsPerIPv6RangeBucketId returns a BucketId for the /48 IPv6
// range containing the provided IPv6 address.
func NewRegistrationsPerIPv6RangeBucketId(ip net.IP) (BucketId, error) {
	if ip.To4() != nil {
		return BucketId{}, fmt.Errorf("invalid IPv6 address, %q must be an IPv6 address", ip.String())
	}
	ipMask := net.CIDRMask(48, 128)
	ipNet := &net.IPNet{IP: ip.Mask(ipMask), Mask: ipMask}
	id := ipNet.String()
	err := validateIdForName(NewRegistrationsPerIPv6Range, id)
	if err != nil {
		return BucketId{}, err
	}
	return BucketId{
		limit:     NewRegistrationsPerIPv6Range,
		bucketKey: joinWithColon(NewRegistrationsPerIPv6Range.EnumString(), id),
	}, nil
}
