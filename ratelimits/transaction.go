package ratelimits

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

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

// newRegIdBucketKey validates and returns a bucketKey for limits that use the
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

// NewRegIdDomainBucketKey validates and returns a bucketKey for limits that use
// the 'enum:regId:domain' bucket key format. This function is exported for use
// in ra.resetAccountPausingLimit.
func NewRegIdDomainBucketKey(name Name, regId int64, orderName string) (string, error) {
	regIdStr := strconv.FormatInt(regId, 10)
	err := validateIdForName(name, joinWithColon(regIdStr, orderName))
	if err != nil {
		return "", err
	}
	return joinWithColon(name.EnumString(), regIdStr, orderName), nil
}

// newFQDNSetBucketKey validates and returns a bucketKey for limits that use the
// 'enum:fqdnSet' bucket key format.
func newFQDNSetBucketKey(name Name, orderNames []string) (string, error) { //nolint: unparam
	err := validateIdForName(name, strings.Join(orderNames, ","))
	if err != nil {
		return "", err
	}
	id := fmt.Sprintf("%x", core.HashNames(orderNames))
	return joinWithColon(name.EnumString(), id), nil
}

// Transaction represents a single rate limit operation. It includes a
// bucketKey, which combines the specific rate limit enum with a unique
// identifier to form the key where the state of the "bucket" can be referenced
// or stored by the Limiter, the rate limit being enforced, a cost which MUST be
// >= 0, and check/spend fields, which indicate how the Transaction should be
// processed. The following are acceptable combinations of check/spend:
//   - check-and-spend: when check and spend are both true, the cost will be
//     checked against the bucket's capacity and spent/refunded, when possible.
//   - check-only: when only check is true, the cost will be checked against the
//     bucket's capacity, but will never be spent/refunded.
//   - spend-only: when only spend is true, spending is best-effort. Regardless
//     of the bucket's capacity, the transaction will be considered "allowed".
//   - allow-only: when neither check nor spend are true, the transaction will
//     be considered "allowed" regardless of the bucket's capacity. This is
//     useful for limits that are disabled.
//
// The zero value of Transaction is an allow-only transaction and is valid even if
// it would fail validateTransaction (for instance because cost and burst are zero).
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

func validateTransaction(txn Transaction) (Transaction, error) {
	if txn.cost < 0 {
		return Transaction{}, ErrInvalidCost
	}
	if txn.limit.Burst == 0 {
		// This should never happen. If the limit was loaded from a file,
		// Burst was validated then. If this is a zero-valued Transaction
		// (that is, an allow-only transaction), then validateTransaction
		// shouldn't be called because zero-valued transactions are automatically
		// valid.
		return Transaction{}, fmt.Errorf("invalid limit, burst must be > 0")
	}
	if txn.cost > txn.limit.Burst {
		return Transaction{}, ErrInvalidCostOverLimit
	}
	return txn, nil
}

func newTransaction(limit limit, bucketKey string, cost int64) (Transaction, error) {
	return validateTransaction(Transaction{
		bucketKey: bucketKey,
		limit:     limit,
		cost:      cost,
		check:     true,
		spend:     true,
	})
}

func newCheckOnlyTransaction(limit limit, bucketKey string, cost int64) (Transaction, error) {
	return validateTransaction(Transaction{
		bucketKey: bucketKey,
		limit:     limit,
		cost:      cost,
		check:     true,
	})
}

func newSpendOnlyTransaction(limit limit, bucketKey string, cost int64) (Transaction, error) {
	return validateTransaction(Transaction{
		bucketKey: bucketKey,
		limit:     limit,
		cost:      cost,
		spend:     true,
	})
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

// registrationsPerIPAddressTransaction returns a Transaction for the
// NewRegistrationsPerIPAddress limit for the provided IP address.
func (builder *TransactionBuilder) registrationsPerIPAddressTransaction(ip net.IP) (Transaction, error) {
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
	return newTransaction(limit, bucketKey, 1)
}

// registrationsPerIPv6RangeTransaction returns a Transaction for the
// NewRegistrationsPerIPv6Range limit for the /48 IPv6 range which contains the
// provided IPv6 address.
func (builder *TransactionBuilder) registrationsPerIPv6RangeTransaction(ip net.IP) (Transaction, error) {
	bucketKey, err := newIPv6RangeCIDRBucketKey(NewRegistrationsPerIPv6Range, ip)
	if err != nil {
		return Transaction{}, err
	}
	limit, err := builder.getLimit(NewRegistrationsPerIPv6Range, bucketKey)
	if err != nil {
		if errors.Is(err, errLimitDisabled) {
			return newAllowOnlyTransaction(), nil
		}
		return Transaction{}, err
	}
	return newTransaction(limit, bucketKey, 1)
}

// ordersPerAccountTransaction returns a Transaction for the NewOrdersPerAccount
// limit for the provided ACME registration Id.
func (builder *TransactionBuilder) ordersPerAccountTransaction(regId int64) (Transaction, error) {
	bucketKey, err := newRegIdBucketKey(NewOrdersPerAccount, regId)
	if err != nil {
		return Transaction{}, err
	}
	limit, err := builder.getLimit(NewOrdersPerAccount, bucketKey)
	if err != nil {
		if errors.Is(err, errLimitDisabled) {
			return newAllowOnlyTransaction(), nil
		}
		return Transaction{}, err
	}
	return newTransaction(limit, bucketKey, 1)
}

// FailedAuthorizationsPerDomainPerAccountCheckOnlyTransactions returns a slice
// of Transactions for the provided order domain names. An error is returned if
// any of the order domain names are invalid. This method should be used for
// checking capacity, before allowing more authorizations to be created.
//
// Precondition: len(orderDomains) < maxNames.
func (builder *TransactionBuilder) FailedAuthorizationsPerDomainPerAccountCheckOnlyTransactions(regId int64, orderDomains []string) ([]Transaction, error) {
	// FailedAuthorizationsPerDomainPerAccount limit uses the 'enum:regId'
	// bucket key format for overrides.
	perAccountBucketKey, err := newRegIdBucketKey(FailedAuthorizationsPerDomainPerAccount, regId)
	if err != nil {
		return nil, err
	}
	limit, err := builder.getLimit(FailedAuthorizationsPerDomainPerAccount, perAccountBucketKey)
	if err != nil {
		if errors.Is(err, errLimitDisabled) {
			return []Transaction{newAllowOnlyTransaction()}, nil
		}
		return nil, err
	}

	var txns []Transaction
	for _, name := range orderDomains {
		// FailedAuthorizationsPerDomainPerAccount limit uses the
		// 'enum:regId:domain' bucket key format for transactions.
		perDomainPerAccountBucketKey, err := NewRegIdDomainBucketKey(FailedAuthorizationsPerDomainPerAccount, regId, name)
		if err != nil {
			return nil, err
		}

		// Add a check-only transaction for each per domain per account bucket.
		// The cost is 0, as we are only checking that the account and domain
		// pair aren't already over the limit.
		txn, err := newCheckOnlyTransaction(limit, perDomainPerAccountBucketKey, 1)
		if err != nil {
			return nil, err
		}
		txns = append(txns, txn)
	}
	return txns, nil
}

// FailedAuthorizationsPerDomainPerAccountSpendOnlyTransaction returns a spend-
// only Transaction for the provided order domain name. An error is returned if
// the order domain name is invalid. This method should be used for spending
// capacity, as a result of a failed authorization.
func (builder *TransactionBuilder) FailedAuthorizationsPerDomainPerAccountSpendOnlyTransaction(regId int64, orderDomain string) (Transaction, error) {
	// FailedAuthorizationsPerDomainPerAccount limit uses the 'enum:regId'
	// bucket key format for overrides.
	perAccountBucketKey, err := newRegIdBucketKey(FailedAuthorizationsPerDomainPerAccount, regId)
	if err != nil {
		return Transaction{}, err
	}
	limit, err := builder.getLimit(FailedAuthorizationsPerDomainPerAccount, perAccountBucketKey)
	if err != nil {
		if errors.Is(err, errLimitDisabled) {
			return newAllowOnlyTransaction(), nil
		}
		return Transaction{}, err
	}

	// FailedAuthorizationsPerDomainPerAccount limit uses the
	// 'enum:regId:domain' bucket key format for transactions.
	perDomainPerAccountBucketKey, err := NewRegIdDomainBucketKey(FailedAuthorizationsPerDomainPerAccount, regId, orderDomain)
	if err != nil {
		return Transaction{}, err
	}
	txn, err := newSpendOnlyTransaction(limit, perDomainPerAccountBucketKey, 1)
	if err != nil {
		return Transaction{}, err
	}

	return txn, nil
}

// FailedAuthorizationsForPausingPerDomainPerAccountTransaction returns a
// Transaction for the provided order domain name. An error is returned if
// the order domain name is invalid. This method should be used for spending
// capacity, as a result of a failed authorization.
func (builder *TransactionBuilder) FailedAuthorizationsForPausingPerDomainPerAccountTransaction(regId int64, orderDomain string) (Transaction, error) {
	// FailedAuthorizationsForPausingPerDomainPerAccount limit uses the 'enum:regId'
	// bucket key format for overrides.
	perAccountBucketKey, err := newRegIdBucketKey(FailedAuthorizationsForPausingPerDomainPerAccount, regId)
	if err != nil {
		return Transaction{}, err
	}
	limit, err := builder.getLimit(FailedAuthorizationsForPausingPerDomainPerAccount, perAccountBucketKey)
	if err != nil {
		if errors.Is(err, errLimitDisabled) {
			return newAllowOnlyTransaction(), nil
		}
		return Transaction{}, err
	}

	// FailedAuthorizationsForPausingPerDomainPerAccount limit uses the
	// 'enum:regId:domain' bucket key format for transactions.
	perDomainPerAccountBucketKey, err := NewRegIdDomainBucketKey(FailedAuthorizationsForPausingPerDomainPerAccount, regId, orderDomain)
	if err != nil {
		return Transaction{}, err
	}

	txn, err := newTransaction(limit, perDomainPerAccountBucketKey, 1)
	if err != nil {
		return Transaction{}, err
	}

	return txn, nil
}

// certificatesPerDomainCheckOnlyTransactions returns a slice of Transactions
// for the provided order domain names. An error is returned if any of the order
// domain names are invalid. This method should be used for checking capacity,
// before allowing more orders to be created. If a CertificatesPerDomainPerAccount
// override is active, a check-only Transaction is created for each per account
// per domain bucket. Otherwise, a check-only Transaction is generated for each
// global per domain bucket. This method should be used for checking capacity,
// before allowing more orders to be created.
//
// Precondition: All orderDomains must comply with policy.WellFormedDomainNames.
func (builder *TransactionBuilder) certificatesPerDomainCheckOnlyTransactions(regId int64, orderDomains []string) ([]Transaction, error) {
	perAccountLimitBucketKey, err := newRegIdBucketKey(CertificatesPerDomainPerAccount, regId)
	if err != nil {
		return nil, err
	}
	accountOverride := true
	perAccountLimit, err := builder.getLimit(CertificatesPerDomainPerAccount, perAccountLimitBucketKey)
	if err != nil {
		// The CertificatesPerDomainPerAccount limit never has a default. If there is an override for it,
		// the above call will return the override. But if there is none, it will return errLimitDisabled.
		// In that case we want to continue, but make sure we don't reference `perAccountLimit` because it
		// is not a valid limit.
		if errors.Is(err, errLimitDisabled) {
			accountOverride = false
		} else {
			return nil, err
		}
	}

	var txns []Transaction
	for _, name := range FQDNsToETLDsPlusOne(orderDomains) {
		perDomainBucketKey, err := newDomainBucketKey(CertificatesPerDomain, name)
		if err != nil {
			return nil, err
		}
		if accountOverride {
			if !perAccountLimit.isOverride() {
				return nil, fmt.Errorf("shouldn't happen: CertificatesPerDomainPerAccount limit is not an override")
			}
			perAccountPerDomainKey, err := NewRegIdDomainBucketKey(CertificatesPerDomainPerAccount, regId, name)
			if err != nil {
				return nil, err
			}
			// Add a check-only transaction for each per account per domain
			// bucket.
			txn, err := newCheckOnlyTransaction(perAccountLimit, perAccountPerDomainKey, 1)
			if err != nil {
				if errors.Is(err, errLimitDisabled) {
					continue
				}
				return nil, err
			}
			txns = append(txns, txn)
		} else {
			// Use the per domain bucket key when no per account per domain override
			// is configured.
			perDomainLimit, err := builder.getLimit(CertificatesPerDomain, perDomainBucketKey)
			if err != nil {
				if errors.Is(err, errLimitDisabled) {
					continue
				}
				return nil, err
			}
			// Add a check-only transaction for each per domain bucket.
			txn, err := newCheckOnlyTransaction(perDomainLimit, perDomainBucketKey, 1)
			if err != nil {
				return nil, err
			}
			txns = append(txns, txn)
		}
	}
	return txns, nil
}

// CertificatesPerDomainSpendOnlyTransactions returns a slice of Transactions
// for the specified order domain names. It returns an error if any domain names
// are invalid. If a CertificatesPerDomainPerAccount override is configured, it
// generates two types of Transactions:
//   - A spend-only Transaction for each per-account, per-domain bucket, which
//     enforces the limit on certificates issued per domain for each account.
//   - A spend-only Transaction for each per-domain bucket, which enforces the
//     global limit on certificates issued per domain.
//
// If no CertificatesPerDomainPerAccount override is present, it returns a
// spend-only Transaction for each global per-domain bucket. This method should
// be used for spending capacity, when a certificate is issued.
//
// Precondition: orderDomains must all pass policy.WellFormedDomainNames.
func (builder *TransactionBuilder) CertificatesPerDomainSpendOnlyTransactions(regId int64, orderDomains []string) ([]Transaction, error) {
	perAccountLimitBucketKey, err := newRegIdBucketKey(CertificatesPerDomainPerAccount, regId)
	if err != nil {
		return nil, err
	}
	accountOverride := true
	perAccountLimit, err := builder.getLimit(CertificatesPerDomainPerAccount, perAccountLimitBucketKey)
	if err != nil {
		// The CertificatesPerDomainPerAccount limit never has a default. If there is an override for it,
		// the above call will return the override. But if there is none, it will return errLimitDisabled.
		// In that case we want to continue, but make sure we don't reference `perAccountLimit` because it
		// is not a valid limit.
		if errors.Is(err, errLimitDisabled) {
			accountOverride = false
		} else {
			return nil, err
		}
	}

	var txns []Transaction
	for _, name := range FQDNsToETLDsPlusOne(orderDomains) {
		perDomainBucketKey, err := newDomainBucketKey(CertificatesPerDomain, name)
		if err != nil {
			return nil, err
		}
		if accountOverride {
			if !perAccountLimit.isOverride() {
				return nil, fmt.Errorf("shouldn't happen: CertificatesPerDomainPerAccount limit is not an override")
			}
			perAccountPerDomainKey, err := NewRegIdDomainBucketKey(CertificatesPerDomainPerAccount, regId, name)
			if err != nil {
				return nil, err
			}
			// Add a spend-only transaction for each per account per domain
			// bucket.
			txn, err := newSpendOnlyTransaction(perAccountLimit, perAccountPerDomainKey, 1)
			if err != nil {
				return nil, err
			}
			txns = append(txns, txn)

			perDomainLimit, err := builder.getLimit(CertificatesPerDomain, perDomainBucketKey)
			if err != nil {
				if errors.Is(err, errLimitDisabled) {
					continue
				}
				return nil, err
			}

			// Add a spend-only transaction for each per domain bucket.
			txn, err = newSpendOnlyTransaction(perDomainLimit, perDomainBucketKey, 1)
			if err != nil {
				return nil, err
			}
			txns = append(txns, txn)
		} else {
			// Use the per domain bucket key when no per account per domain
			// override is configured.
			perDomainLimit, err := builder.getLimit(CertificatesPerDomain, perDomainBucketKey)
			if err != nil {
				if errors.Is(err, errLimitDisabled) {
					continue
				}
				return nil, err
			}
			// Add a spend-only transaction for each per domain bucket.
			txn, err := newSpendOnlyTransaction(perDomainLimit, perDomainBucketKey, 1)
			if err != nil {
				return nil, err
			}
			txns = append(txns, txn)
		}
	}
	return txns, nil
}

// certificatesPerFQDNSetCheckOnlyTransaction returns a check-only Transaction
// for the provided order domain names. This method should only be used for
// checking capacity, before allowing more orders to be created.
func (builder *TransactionBuilder) certificatesPerFQDNSetCheckOnlyTransaction(orderNames []string) (Transaction, error) {
	bucketKey, err := newFQDNSetBucketKey(CertificatesPerFQDNSet, orderNames)
	if err != nil {
		return Transaction{}, err
	}
	limit, err := builder.getLimit(CertificatesPerFQDNSet, bucketKey)
	if err != nil {
		if errors.Is(err, errLimitDisabled) {
			return newAllowOnlyTransaction(), nil
		}
		return Transaction{}, err
	}
	return newCheckOnlyTransaction(limit, bucketKey, 1)
}

// CertificatesPerFQDNSetSpendOnlyTransaction returns a spend-only Transaction
// for the provided order domain names. This method should only be used for
// spending capacity, when a certificate is issued.
func (builder *TransactionBuilder) CertificatesPerFQDNSetSpendOnlyTransaction(orderNames []string) (Transaction, error) {
	bucketKey, err := newFQDNSetBucketKey(CertificatesPerFQDNSet, orderNames)
	if err != nil {
		return Transaction{}, err
	}
	limit, err := builder.getLimit(CertificatesPerFQDNSet, bucketKey)
	if err != nil {
		if errors.Is(err, errLimitDisabled) {
			return newAllowOnlyTransaction(), nil
		}
		return Transaction{}, err
	}
	return newSpendOnlyTransaction(limit, bucketKey, 1)
}

// NewOrderLimitTransactions takes in values from a new-order request and
// returns the set of rate limit transactions that should be evaluated before
// allowing the request to proceed.
//
// Precondition: names must be a list of DNS names that all pass
// policy.WellFormedDomainNames.
func (builder *TransactionBuilder) NewOrderLimitTransactions(regId int64, names []string, isRenewal bool) ([]Transaction, error) {
	makeTxnError := func(err error, limit Name) error {
		return fmt.Errorf("error constructing rate limit transaction for %s rate limit: %w", limit, err)
	}

	var transactions []Transaction
	if !isRenewal {
		txn, err := builder.ordersPerAccountTransaction(regId)
		if err != nil {
			return nil, makeTxnError(err, NewOrdersPerAccount)
		}
		transactions = append(transactions, txn)
	}

	txns, err := builder.FailedAuthorizationsPerDomainPerAccountCheckOnlyTransactions(regId, names)
	if err != nil {
		return nil, makeTxnError(err, FailedAuthorizationsPerDomainPerAccount)
	}
	transactions = append(transactions, txns...)

	if !isRenewal {
		txns, err := builder.certificatesPerDomainCheckOnlyTransactions(regId, names)
		if err != nil {
			return nil, makeTxnError(err, CertificatesPerDomain)
		}
		transactions = append(transactions, txns...)
	}

	txn, err := builder.certificatesPerFQDNSetCheckOnlyTransaction(names)
	if err != nil {
		return nil, makeTxnError(err, CertificatesPerFQDNSet)
	}
	return append(transactions, txn), nil
}

// NewAccountLimitTransactions takes in an IP address from a new-account request
// and returns the set of rate limit transactions that should be evaluated
// before allowing the request to proceed.
func (builder *TransactionBuilder) NewAccountLimitTransactions(ip net.IP) ([]Transaction, error) {
	makeTxnError := func(err error, limit Name) error {
		return fmt.Errorf("error constructing rate limit transaction for %s rate limit: %w", limit, err)
	}

	var transactions []Transaction
	txn, err := builder.registrationsPerIPAddressTransaction(ip)
	if err != nil {
		return nil, makeTxnError(err, NewRegistrationsPerIPAddress)
	}
	transactions = append(transactions, txn)

	if ip.To4() != nil {
		// This request was made from an IPv4 address.
		return transactions, nil
	}

	txn, err = builder.registrationsPerIPv6RangeTransaction(ip)
	if err != nil {
		return nil, makeTxnError(err, NewRegistrationsPerIPv6Range)
	}
	return append(transactions, txn), nil
}
