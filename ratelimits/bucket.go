package ratelimits

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/letsencrypt/boulder/core"
)

// bucketId should only be created using the new*bucketId functions. It is used
// by the Limiter to look up the bucket and limit overrides for a specific
// subscriber and limit.
type bucketId struct {
	// limitName is the name of the associated rate limit. It is used for
	// looking up default limits.
	limitName Name

	// bucketKey is the limit Name enum (e.g. "1") concatenated with the
	// subscriber identifier specific to the associate limit Name type.
	bucketKey string
}

func newIPAddressBucketId(name Name, ip net.IP) (bucketId, error) { //nolint: unparam
	id := ip.String()
	err := validateIdForName(name, id)
	if err != nil {
		return bucketId{}, err
	}
	return bucketId{
		limitName: name,
		bucketKey: joinWithColon(name.EnumString(), id),
	}, nil
}

func ipv6RangeCIDRBucketId(name Name, ip net.IP) (bucketId, error) {
	if ip.To4() != nil {
		return bucketId{}, fmt.Errorf("invalid IPv6 address, %q must be an IPv6 address", ip.String())
	}
	ipMask := net.CIDRMask(48, 128)
	ipNet := &net.IPNet{IP: ip.Mask(ipMask), Mask: ipMask}
	id := ipNet.String()
	err := validateIdForName(name, id)
	if err != nil {
		return bucketId{}, err
	}
	return bucketId{
		limitName: name,
		bucketKey: joinWithColon(name.EnumString(), id),
	}, nil
}

func newRegIdBucketId(name Name, regId int64) (bucketId, error) {
	id := strconv.FormatInt(regId, 10)
	err := validateIdForName(name, id)
	if err != nil {
		return bucketId{}, err
	}
	return bucketId{
		limitName: name,
		bucketKey: joinWithColon(name.EnumString(), id),
	}, nil
}

func newDomainBucketId(name Name, orderName string) (bucketId, error) {
	err := validateIdForName(name, orderName)
	if err != nil {
		return bucketId{}, err
	}
	return bucketId{
		limitName: name,
		bucketKey: joinWithColon(name.EnumString(), orderName),
	}, nil
}

func newFQDNSetBucketId(name Name, orderNames []string) (bucketId, error) {
	id := string(core.HashNames(orderNames))
	err := validateIdForName(name, id)
	if err != nil {
		return bucketId{}, err
	}
	return bucketId{
		limitName: name,
		bucketKey: joinWithColon(name.EnumString(), id),
	}, nil
}

// Transaction is a cost to be spent or refunded from a specific bucket
// identified by the bucketId.
type Transaction struct {
	bucketId
	cost int64

	// optimistic indicates to the limiter that the cost should be spent if
	// possible, but should not be denied if the bucket lacks the capacity to
	// satisfy the cost. Note: optimistic transactions are only supported by
	// limiter.BatchSpend().
	optimistic bool

	// checkOnly indicates to the limiter that the cost should be checked but
	// not spent or refunded. Note: checkOnly transactions are only supported by
	// limiter.BatchSpend(). Outside of batches callers should use
	// limiter.Check().
	checkOnly bool
}

// newTransaction creates a new Transaction for the provided BucketId and cost.
func newTransaction(b bucketId, cost int64) Transaction {
	return Transaction{
		bucketId: b,
		cost:     cost,
	}
}

// newCheckOnlyTransaction creates a new check-only Transaction for the provided
// BucketId and cost. Check-only transactions will not have their cost deducted
// from the bucket's capacity. Note: check-only transactions are only supported
// by limiter.BatchSpend() and limiter.BatchRefund().
func newCheckOnlyTransaction(b bucketId, cost int64) Transaction {
	return Transaction{
		bucketId:  b,
		cost:      cost,
		checkOnly: true,
	}
}

// newOptimisticTransaction creates a new optimistic Transaction for the
// provided BucketId and cost. Optimistic transactions will not be denied if the
// bucket lacks the capacity to satisfy the cost. Note: optimistic transactions
// are only supported by limiter.BatchSpend().
func newOptimisticTransaction(b bucketId, cost int64) Transaction {
	return Transaction{
		bucketId:   b,
		cost:       cost,
		optimistic: true,
	}
}

// NewRegistrationsPerIPAddressTransaction returns a Transaction for the
// provided IP address.
func NewRegistrationsPerIPAddressTransaction(ip net.IP, cost int64) (Transaction, error) {
	bucketId, err := newIPAddressBucketId(NewRegistrationsPerIPAddress, ip)
	if err != nil {
		return Transaction{}, err
	}
	return newTransaction(bucketId, cost), nil
}

// NewRegistrationsPerIPv6RangeTransaction returns a Transaction for the /48
// IPv6 range containing the provided IPv6 address.
func NewRegistrationsPerIPv6RangeTransaction(ip net.IP, cost int64) (Transaction, error) {
	bucketId, err := ipv6RangeCIDRBucketId(NewRegistrationsPerIPv6Range, ip)
	if err != nil {
		return Transaction{}, err
	}
	return newTransaction(bucketId, cost), nil
}

// NewOrdersPerAccountTransaction returns a Transaction for the provided ACME
// registration Id.
func NewOrdersPerAccountTransaction(regId, cost int64) (Transaction, error) {
	bucketId, err := newRegIdBucketId(NewOrdersPerAccount, regId)
	if err != nil {
		return Transaction{}, err
	}
	return newTransaction(bucketId, cost), nil
}

// NewFailedAuthorizationsPerAccountCheckOnlyTransaction returns a Transaction
// for the provided ACME registration Id, which when processed as part of a
// batch call will only check the bucket's capacity and not spend or refund the
// cost.
func NewFailedAuthorizationsPerAccountCheckOnlyTransaction(regId, cost int64) (Transaction, error) {
	bucketId, err := newRegIdBucketId(FailedAuthorizationsPerAccount, regId)
	if err != nil {
		return Transaction{}, err
	}
	return newCheckOnlyTransaction(bucketId, cost), nil
}

// NewFailedAuthorizationsPerAccountTransaction returns a Transaction for the
// provided ACME registration Id.
func NewFailedAuthorizationsPerAccountTransaction(regId, cost int64) (Transaction, error) {
	bucketId, err := newRegIdBucketId(FailedAuthorizationsPerAccount, regId)
	if err != nil {
		return Transaction{}, err
	}
	return newTransaction(bucketId, cost), nil
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
	certsPerDomainPerAccountId, err := newRegIdBucketId(CertificatesPerDomainPerAccount, regId)
	if err != nil {
		return nil, err
	}
	certsPerDomainPerAccountLimit, err := limiter.getLimit(CertificatesPerDomainPerAccount, certsPerDomainPerAccountId.bucketKey)
	if err != nil {
		if !errors.Is(err, errLimitDisabled) {
			return nil, err
		}
	}

	var txns []Transaction
	var certsPerDomainPerAccountCost int64
	for _, name := range DomainsForRateLimiting(orderDomains) {
		certsPerDomainId, err := newDomainBucketId(CertificatesPerDomain, name)
		if err != nil {
			return nil, err
		}
		certsPerDomainPerAccountCost += cost
		if certsPerDomainPerAccountLimit.isOverride {
			// SHOULD be consumed from each CertificatesPerDomain bucket, if possible.
			txns = append(txns, newOptimisticTransaction(certsPerDomainId, cost))
		} else {
			txns = append(txns, newTransaction(certsPerDomainId, cost))
		}
	}
	if certsPerDomainPerAccountLimit.isOverride {
		// MUST be consumed from the CertificatesPerDomainPerAccount bucket.
		txns = append(txns, newTransaction(certsPerDomainPerAccountId, certsPerDomainPerAccountCost))
	}
	return txns, nil
}

// NewCertificatesPerFQDNSetTransaction returns a Transaction for the provided
// order domain names.
func NewCertificatesPerFQDNSetTransaction(orderNames []string, cost int64) (Transaction, error) {
	bucketId, err := newFQDNSetBucketId(CertificatesPerFQDNSet, orderNames)
	if err != nil {
		return Transaction{}, err
	}
	return newTransaction(bucketId, cost), nil
}
