package ratelimits

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/letsencrypt/boulder/core"
)

// BucketId should only be created using the New*BucketId functions. It is used
// by the Limiter to look up the bucket and limit overrides for a specific
// subscriber and limit.
type BucketId struct {
	// limitName is the name of the associated rate limit. It is used for
	// looking up default limits.
	limitName Name

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
		limitName: NewRegistrationsPerIPAddress,
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
		limitName: NewRegistrationsPerIPv6Range,
		bucketKey: joinWithColon(NewRegistrationsPerIPv6Range.EnumString(), id),
	}, nil
}

// NewOrdersPerAccountBucketId returns a BucketId for the provided ACME
// registration Id.
func NewOrdersPerAccountBucketId(regId int64) (BucketId, error) {
	id := strconv.FormatInt(regId, 10)
	err := validateIdForName(NewOrdersPerAccount, id)
	if err != nil {
		return BucketId{}, err
	}
	return BucketId{
		limitName: NewOrdersPerAccount,
		bucketKey: joinWithColon(NewOrdersPerAccount.EnumString(), id),
	}, nil
}

// NewFailedAuthorizationsPerAccountBucketId returns a BucketId for the provided
// ACME registration Id.
func NewFailedAuthorizationsPerAccountBucketId(regId int64) (BucketId, error) {
	id := strconv.FormatInt(regId, 10)
	err := validateIdForName(FailedAuthorizationsPerAccount, id)
	if err != nil {
		return BucketId{}, err
	}
	return BucketId{
		limitName: FailedAuthorizationsPerAccount,
		bucketKey: joinWithColon(FailedAuthorizationsPerAccount.EnumString(), id),
	}, nil
}

// NewCertificatesPerDomainBucketId returns a BucketId for the provided order
// domain name.
func NewCertificatesPerDomainBucketId(orderName string) (BucketId, error) {
	err := validateIdForName(CertificatesPerDomain, orderName)
	if err != nil {
		return BucketId{}, err
	}
	return BucketId{
		limitName: CertificatesPerDomain,
		bucketKey: joinWithColon(CertificatesPerDomain.EnumString(), orderName),
	}, nil
}

func newCertificatesPerDomainPerAccountBucketId(regId int64) (BucketId, error) {
	id := strconv.FormatInt(regId, 10)
	err := validateIdForName(CertificatesPerDomainPerAccount, id)
	if err != nil {
		return BucketId{}, err
	}
	return BucketId{
		limitName: CertificatesPerDomainPerAccount,
		bucketKey: joinWithColon(CertificatesPerDomainPerAccount.EnumString(), id),
	}, nil
}

// NewCertificatesPerDomainTransactions returns a slice of Transactions for the
// provided order domain names. The cost specified will be applied per eTLD+1
// name present in the orderDomains.
//
// Note: when overrides to the CertificatesPerDomainPerAccount are configured
// for the subscriber, the cost:
//   - MUST be consumed from the CertificatesPerDomainPerAccount bucket and
//   - SHOULD be consumed from each CertificatesPerDomain bucket, if possible.
//
// When a CertificatesPerDomainPerAccount override is configured, all of the
// CertificatesPerDomain transactions returned by this function will be marked
// as optimistic and the combined cost of all of these transactions will be
// specified in a CertificatesPerDomainPerAccount transaction as well.
func NewCertificatesPerDomainTransactions(limiter *Limiter, regId int64, orderDomains []string, cost int64) ([]Transaction, error) {
	id, err := newCertificatesPerDomainPerAccountBucketId(regId)
	if err != nil {
		return nil, err
	}
	certsPerDomainPerAccountLimit, err := limiter.getLimit(CertificatesPerDomainPerAccount, id.bucketKey)
	if err != nil {
		if !errors.Is(err, errLimitDisabled) {
			return nil, err
		}
	}

	var txns []Transaction
	var certsPerDomainPerAccountCost int64
	for _, name := range DomainsForRateLimiting(orderDomains) {
		bucketId, err := NewCertificatesPerDomainBucketId(name)
		if err != nil {
			return nil, err
		}
		certsPerDomainPerAccountCost += cost
		if certsPerDomainPerAccountLimit.isOverride {
			txns = append(txns, newOptimisticTransaction(bucketId, cost))
		} else {
			txns = append(txns, NewTransaction(bucketId, cost))
		}
	}
	if certsPerDomainPerAccountLimit.isOverride {
		txns = append(txns, NewTransaction(id, certsPerDomainPerAccountCost))
	}
	return txns, nil
}

// NewCertificatesPerFQDNSetBucket returns a BucketId for the provided order
// domain names.
func NewCertificatesPerFQDNSetBucket(orderNames []string) (BucketId, error) {
	id := string(core.HashNames(orderNames))
	err := validateIdForName(CertificatesPerFQDNSet, id)
	if err != nil {
		return BucketId{}, err
	}
	return BucketId{
		limitName: CertificatesPerFQDNSet,
		bucketKey: joinWithColon(CertificatesPerFQDNSet.EnumString(), id),
	}, nil
}
