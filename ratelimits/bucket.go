package ratelimits

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/letsencrypt/boulder/core"
)

// ErrInvalidCost indicates that the cost specified was < 0.
var ErrInvalidCost = fmt.Errorf("invalid cost, must be >= 0")

// ErrInvalidCostOverLimit indicates that the cost specified was > limit.Burst.
var ErrInvalidCostOverLimit = fmt.Errorf("invalid cost, must be <= limit.Burst")

// newIPAddressBucketKey validates and returns a bucketKey for limits that use
// the 'enum:ipAddress' bucket key format.
func newIPAddressBucketKey(name Name, ip net.IP) (string, error) { //nolint: unparam
	id := ip.String()
	err := validateIdForName(name, id)
	if err != nil {
		return "", err
	}
	return joinWithColon(name.EnumString(), id), nil
}

// newIPv6RangeCIDRBucketKey validates and returns a bucketKey for limits that
// use the 'enum:ipv6RangeCIDR' bucket key format.
func newIPv6RangeCIDRBucketKey(name Name, ip net.IP) (string, error) {
	if ip.To4() != nil {
		return "", fmt.Errorf("invalid IPv6 address, %q must be an IPv6 address", ip.String())
	}
	ipMask := net.CIDRMask(48, 128)
	ipNet := &net.IPNet{IP: ip.Mask(ipMask), Mask: ipMask}
	id := ipNet.String()
	err := validateIdForName(name, id)
	if err != nil {
		return "", err
	}
	return joinWithColon(name.EnumString(), id), nil
}

// newRegIdBucketKey validates ands returns a bucketKey for limits that use the
// 'enum:regId' bucket key format.
func newRegIdBucketKey(name Name, regId int64) (string, error) {
	id := strconv.FormatInt(regId, 10)
	err := validateIdForName(name, id)
	if err != nil {
		return "", err
	}
	return joinWithColon(name.EnumString(), id), nil
}

// newDomainBucketKey validates and returns a bucketKey for limits that use the
// 'enum:domain' bucket key format.
func newDomainBucketKey(name Name, orderName string) (string, error) {
	err := validateIdForName(name, orderName)
	if err != nil {
		return "", err
	}
	return joinWithColon(name.EnumString(), orderName), nil
}

// newRegIdDomainBucketKey validates and returns a bucketKey for limits that use
// the 'enum:regId:domain' bucket key format.
func newRegIdDomainBucketKey(name Name, regId int64, orderName string) (string, error) {
	regIdStr := strconv.FormatInt(regId, 10)
	err := validateIdForName(name, joinWithColon(regIdStr, orderName))
	if err != nil {
		return "", err
	}
	return joinWithColon(name.EnumString(), regIdStr, orderName), nil
}

// newFQDNSetBucketKey validates and returns a bucketKey for limits that use the
// 'enum:fqdnSet' bucket key format.
func newFQDNSetBucketKey(name Name, orderNames []string) (string, error) {
	id := string(core.HashNames(orderNames))
	err := validateIdForName(name, id)
	if err != nil {
		return "", err
	}
	return joinWithColon(name.EnumString(), id), nil
}

// Transaction is used to represent a single rate limit Transaction. It contains
// the bucketKey identifying the limit and subscriber. A cost which MUST be
// greater than or equal to 0. Cost is variable to allow for limits such as
// CertificatesPerDomainPerAccount, where the cost is the number of domain names
// in the order. The check and spend fields are are not mutually exclusive, and
// indicate how the limiter should process the Transaction; the following are
// acceptable combinations of both:
//   - check-and-spend: when check and spend are both true, the cost will be
//     checked against the bucket's capacity and spent/refunded, when possible.
//   - check-only: when only check is true, the cost will be checked against the
//     bucket's capacity, but will never be spent/refunded.
//   - spend-only: when only spend is true, spending is best-effort. Regardless
//     of the bucket's capacity, the transaction will be considered "allowed".
//   - allow-only: when neither check nor spend are true, the transaction will
//     be considered "allowed" regardless of the bucket's capacity. This is
//     useful for limits that are disabled.
type Transaction struct {
	bucketKey string
	limit     limit
	cost      int64
	check     bool
	spend     bool
}

func (txn Transaction) checkOnly() bool {
	return txn.check && !txn.spend
}

func (txn Transaction) spendOnly() bool {
	return txn.spend && !txn.check
}

func (txn Transaction) allowOnly() bool {
	return !txn.check && !txn.spend
}

func (txn Transaction) validate() error {
	if txn.allowOnly() {
		return nil
	}
	if txn.cost < 0 {
		return ErrInvalidCost
	}
	if txn.cost > txn.limit.Burst {
		return ErrInvalidCostOverLimit
	}
	return nil
}

func newTransaction(limit limit, bucketKey string, cost int64) Transaction {
	return Transaction{
		bucketKey: bucketKey,
		limit:     limit,
		cost:      cost,
		check:     true,
		spend:     true,
	}
}

func newCheckOnlyTransaction(limit limit, bucketKey string, cost int64) Transaction {
	return Transaction{
		bucketKey: bucketKey,
		limit:     limit,
		cost:      cost,
		check:     true,
	}
}

func newSpendOnlyTransaction(limit limit, bucketKey string, cost int64) Transaction {
	return Transaction{
		bucketKey: bucketKey,
		limit:     limit,
		cost:      cost,
		spend:     true,
	}
}

func newAllowOnlyTransaction() Transaction {
	// Zero values are sufficient.
	return Transaction{}
}

// TransactionBuilder is used to build Transactions for various rate limits.
// Each rate limit has a corresponding method that returns a Transaction for
// that limit. Call NewTransactionBuilder to create a new *TransactionBuilder.
type TransactionBuilder struct {
	*limitRegistry
}

// NewTransactionBuilder returns a new *TransactionBuilder. The provided
// defaults and overrides paths are expected to be paths to YAML files that
// contain the default and override limits, respectively. Overrides is optional,
// defaults is required.
func NewTransactionBuilder(defaults, overrides string) (*TransactionBuilder, error) {
	registry, err := newLimitRegistry(defaults, overrides)
	if err != nil {
		return nil, err
	}
	return &TransactionBuilder{registry}, nil
}

// RegistrationsPerIPAddressTransaction returns a Transaction for the
// NewRegistrationsPerIPAddress limit for the provided IP address.
func (builder *TransactionBuilder) RegistrationsPerIPAddressTransaction(ip net.IP) (Transaction, error) {
	bucketKey, err := newIPAddressBucketKey(NewRegistrationsPerIPAddress, ip)
	if err != nil {
		return Transaction{}, err
	}
	limit, err := builder.getLimit(NewRegistrationsPerIPAddress, bucketKey)
	if err != nil {
		if errors.Is(err, errLimitDisabled) {
			return newAllowOnlyTransaction(), nil
		}
		return Transaction{}, err
	}
	txn := newTransaction(limit, bucketKey, 1)
	return txn, txn.validate()
}

// RegistrationsPerIPv6RangeTransaction returns a Transaction for the
// NewRegistrationsPerIPv6Range limit for the /48 IPv6 range which contains the
// provided IPv6 address.
func (builder *TransactionBuilder) RegistrationsPerIPv6RangeTransaction(ip net.IP) (Transaction, error) {
	bucketKey, err := newIPv6RangeCIDRBucketKey(NewRegistrationsPerIPv6Range, ip)
	if err != nil {
		return Transaction{}, err
	}
	limit, err := builder.getLimit(NewRegistrationsPerIPAddress, bucketKey)
	if err != nil {
		if errors.Is(err, errLimitDisabled) {
			return newAllowOnlyTransaction(), nil
		}
		return Transaction{}, err
	}
	txn := newTransaction(limit, bucketKey, 1)
	return txn, txn.validate()
}

// OrdersPerAccountTransaction returns a Transaction for the NewOrdersPerAccount
// limit for the provided ACME registration Id.
func (builder *TransactionBuilder) OrdersPerAccountTransaction(regId int64) (Transaction, error) {
	bucketKey, err := newRegIdBucketKey(NewOrdersPerAccount, regId)
	if err != nil {
		return Transaction{}, err
	}
	limit, err := builder.getLimit(NewRegistrationsPerIPAddress, bucketKey)
	if err != nil {
		if errors.Is(err, errLimitDisabled) {
			return newAllowOnlyTransaction(), nil
		}
		return Transaction{}, err
	}
	txn := newTransaction(limit, bucketKey, 1)
	return txn, txn.validate()
}

// FailedAuthorizationsPerAccountCheckOnlyTransaction returns a check-only
// Transaction for the provided ACME registration Id for the
// FailedAuthorizationsPerAccount limit.
func (builder *TransactionBuilder) FailedAuthorizationsPerAccountCheckOnlyTransaction(regId int64) (Transaction, error) {
	bucketKey, err := newRegIdBucketKey(FailedAuthorizationsPerAccount, regId)
	if err != nil {
		return Transaction{}, err
	}
	limit, err := builder.getLimit(NewRegistrationsPerIPAddress, bucketKey)
	if err != nil {
		if errors.Is(err, errLimitDisabled) {
			return newAllowOnlyTransaction(), nil
		}
		return Transaction{}, err
	}
	txn := newCheckOnlyTransaction(limit, bucketKey, 1)
	return txn, txn.validate()
}

// FailedAuthorizationsPerAccountTransaction returns a Transaction for the
// FailedAuthorizationsPerAccount limit for the provided ACME registration Id.
func (builder *TransactionBuilder) FailedAuthorizationsPerAccountTransaction(regId int64) (Transaction, error) {
	bucketKey, err := newRegIdBucketKey(FailedAuthorizationsPerAccount, regId)
	if err != nil {
		return Transaction{}, err
	}
	limit, err := builder.getLimit(NewRegistrationsPerIPAddress, bucketKey)
	if err != nil {
		if errors.Is(err, errLimitDisabled) {
			return newAllowOnlyTransaction(), nil
		}
		return Transaction{}, err
	}
	txn := newTransaction(limit, bucketKey, 1)
	return txn, txn.validate()
}

// CertificatesPerDomainTransactions returns a slice of Transactions for the for
// the provided order domain names. An error is returned if any of the order
// domain names are invalid. When a CertificatesPerDomainPerAccount override is
// configured, two types of Transactions are returned:
//   - A spend-only Transaction for each per domain bucket. Spend-only transactions
//     will not be denied if the bucket lacks the capacity to satisfy the cost.
//   - A check-and-spend Transaction for each per account per domain bucket. Check-
//     and-spend transactions will be denied if the bucket lacks the capacity to
//     satisfy the cost.
//
// When a CertificatesPerDomainPerAccount override is not configured, a check-
// and-spend Transaction is returned for each per domain bucket.
func (builder *TransactionBuilder) CertificatesPerDomainTransactions(regId int64, orderDomains []string) ([]Transaction, error) {
	perAccountLimitBucketKey, err := newRegIdBucketKey(CertificatesPerDomainPerAccount, regId)
	if err != nil {
		return nil, err
	}
	perAccountLimit, err := builder.getLimit(CertificatesPerDomainPerAccount, perAccountLimitBucketKey)
	if err != nil {
		if !errors.Is(err, errLimitDisabled) {
			return nil, err
		}
	}

	var txns []Transaction
	var perAccountPerDomainCost int64
	for _, name := range DomainsForRateLimiting(orderDomains) {
		perDomainBucketKey, err := newDomainBucketKey(CertificatesPerDomain, name)
		if err != nil {
			return nil, err
		}
		perDomainLimit, err := builder.getLimit(CertificatesPerDomain, perDomainBucketKey)
		if err != nil {
			if !errors.Is(err, errLimitDisabled) {
				return nil, err
			}
		}
		perAccountPerDomainCost += 1
		if perAccountLimit.isOverride {
			// An override is configured for the CertificatesPerDomainPerAccount
			// limit.
			perAccountPerDomainKey, err := newRegIdDomainBucketKey(CertificatesPerDomainPerAccount, regId, name)
			if err != nil {
				return nil, err
			}
			// Add a check-and-spend transaction for each per account per domain
			// bucket.
			txn := newTransaction(perAccountLimit, perAccountPerDomainKey, perAccountPerDomainCost)
			err = txn.validate()
			if err != nil {
				return nil, err
			}
			txns = append(txns, txn)

			// Add a spend-only transaction for each per domain bucket.
			txn = newSpendOnlyTransaction(perDomainLimit, perDomainBucketKey, 1)
			err = txn.validate()
			if err != nil {
				return nil, err
			}
			txns = append(txns, txn)
		} else {
			// Add a check-and-spend transaction for each per domain bucket.
			txn := newTransaction(perDomainLimit, perDomainBucketKey, 1)
			err = txn.validate()
			if err != nil {
				return nil, err
			}
			txns = append(txns, txn)
		}
	}
	return txns, nil
}

// CertificatesPerFQDNSetTransaction returns a Transaction for the provided
// order domain names.
func (builder *TransactionBuilder) CertificatesPerFQDNSetTransaction(orderNames []string) (Transaction, error) {
	bucketKey, err := newFQDNSetBucketKey(CertificatesPerFQDNSet, orderNames)
	if err != nil {
		return Transaction{}, err
	}
	limit, err := builder.getLimit(NewRegistrationsPerIPAddress, bucketKey)
	if err != nil {
		if errors.Is(err, errLimitDisabled) {
			return newAllowOnlyTransaction(), nil
		}
		return Transaction{}, err
	}
	txn := newTransaction(limit, bucketKey, 1)
	return txn, txn.validate()
}
