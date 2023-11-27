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
	// subscriber identifier specific to the associated limit Name type.
	bucketKey string
}

// newIPAddressBucketId validates and returns a bucketId for limits that use the
// 'enum:ipAddress' bucket key format.
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

// newIPv6RangeCIDRBucketId validates and returns a bucketId for limits that use
// the 'enum:ipv6RangeCIDR' bucket key format.
func newIPv6RangeCIDRBucketId(name Name, ip net.IP) (bucketId, error) {
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

// newRegIdBucketId validates ands returns a bucketId for limits that use the
// 'enum:regId' bucket key format.
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

// newDomainBucketId validates and returns a bucketId for limits that use the
// 'enum:domain' bucket key format.
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

// newFQDNSetBucketId validates and returns a bucketId for limits that use the
// 'enum:fqdnSet' bucket key format.
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

// Transaction is used to represent a single rate limit Transaction. It contains
// the bucketId and cost of the Transaction, and flags indicating how the
// Transaction should be processed. Acceptable check and spend combinations are:
//   - check-and-spend: when check and spend are true, the cost will be checked
//     against the bucket's capacity and spent/refunded, when possible.
//   - check-only: when only check is true, the cost will be checked against the
//     bucket's capacity, but will never be spent/refunded.
//   - spend-only: when only spend is true, spending is best-effort. Regardless
//     of the bucket's capacity, the transaction will be considered "allowed".
type Transaction struct {
	bucketId
	cost  int64
	check bool
	spend bool
}

func (t Transaction) checkOnly() bool {
	return t.check && !t.spend
}

func (t Transaction) spendOnly() bool {
	return t.spend && !t.check
}

func newTransaction(b bucketId, cost int64) Transaction {
	return Transaction{
		bucketId: b,
		cost:     cost,
		check:    true,
		spend:    true,
	}
}

func newCheckOnlyTransaction(b bucketId, cost int64) Transaction {
	return Transaction{
		bucketId: b,
		cost:     cost,
		check:    true,
	}
}

func newSpendOnlyTransaction(b bucketId, cost int64) Transaction {
	return Transaction{
		bucketId: b,
		cost:     cost,
		spend:    true,
	}
}

// RegistrationsPerIPAddressTransaction returns a Transaction for the
// NewRegistrationsPerIPAddress limit for the provided IP address.
func RegistrationsPerIPAddressTransaction(ip net.IP, cost int64) (Transaction, error) {
	bucketId, err := newIPAddressBucketId(NewRegistrationsPerIPAddress, ip)
	if err != nil {
		return Transaction{}, err
	}
	return newTransaction(bucketId, cost), nil
}

// RegistrationsPerIPv6RangeTransaction returns a Transaction for the
// NewRegistrationsPerIPv6Range limit for the /48 IPv6 range which contains the
// provided IPv6 address.
func RegistrationsPerIPv6RangeTransaction(ip net.IP, cost int64) (Transaction, error) {
	bucketId, err := newIPv6RangeCIDRBucketId(NewRegistrationsPerIPv6Range, ip)
	if err != nil {
		return Transaction{}, err
	}
	return newTransaction(bucketId, cost), nil
}

// OrdersPerAccountTransaction returns a Transaction for the NewOrdersPerAccount
// limit for the provided ACME registration Id.
func OrdersPerAccountTransaction(regId, cost int64) (Transaction, error) {
	bucketId, err := newRegIdBucketId(NewOrdersPerAccount, regId)
	if err != nil {
		return Transaction{}, err
	}
	return newTransaction(bucketId, cost), nil
}

// FailedAuthorizationsPerAccountCheckOnlyTransaction returns a 0 cost
// check-only Transaction for the provided ACME registration Id for the
// FailedAuthorizationsPerAccount limit.
func FailedAuthorizationsPerAccountCheckOnlyTransaction(regId int64) (Transaction, error) {
	bucketId, err := newRegIdBucketId(FailedAuthorizationsPerAccount, regId)
	if err != nil {
		return Transaction{}, err
	}
	return newCheckOnlyTransaction(bucketId, 0), nil
}

// FailedAuthorizationsPerAccountTransaction returns a Transaction for the
// FailedAuthorizationsPerAccount limit for the provided ACME registration Id.
func FailedAuthorizationsPerAccountTransaction(regId, cost int64) (Transaction, error) {
	bucketId, err := newRegIdBucketId(FailedAuthorizationsPerAccount, regId)
	if err != nil {
		return Transaction{}, err
	}
	return newTransaction(bucketId, cost), nil
}

// CertificatesPerDomainTransactions returns a slice of Transactions for the for
// the provided order domain names. An error is returned if any of the order
// domain names are invalid. When a CertificatesPerDomainPerAccount override is
// configured, two types of Transactions are returned:
//   - CertificatesPerDomain Transaction(s), which will NOT be denied if the
//     bucket lacks the capacity to satisfy the cost, and
//   - a CertificatesPerDomainPerAccount Transaction, which will be denied if
//     the bucket lacks the capacity to satisfy combined cost of each
//     CertificatesPerDomain Transaction(s).
//
// When a CertificatesPerDomainPerAccount override is NOT configured, only
// CertificatesPerDomain Transactions, which will be denied if the bucket lacks
// the required capacity, are returned.
func CertificatesPerDomainTransactions(limiter *Limiter, regId int64, orderDomains []string, cost int64) ([]Transaction, error) {
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
			txns = append(txns, newSpendOnlyTransaction(certsPerDomainId, cost))
		} else {
			txns = append(txns, newTransaction(certsPerDomainId, cost))
		}
	}
	if certsPerDomainPerAccountLimit.isOverride {
		txns = append(txns, newTransaction(certsPerDomainPerAccountId, certsPerDomainPerAccountCost))
	}
	return txns, nil
}

// CertificatesPerFQDNSetTransaction returns a Transaction for the provided
// order domain names.
func CertificatesPerFQDNSetTransaction(orderNames []string, cost int64) (Transaction, error) {
	bucketId, err := newFQDNSetBucketId(CertificatesPerFQDNSet, orderNames)
	if err != nil {
		return Transaction{}, err
	}
	return newTransaction(bucketId, cost), nil
}
