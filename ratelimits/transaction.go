package ratelimits

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/identifier"
	blog "github.com/letsencrypt/boulder/log"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

// ErrInvalidCost indicates that the cost specified was < 0.
var ErrInvalidCost = fmt.Errorf("invalid cost, must be >= 0")

// ErrInvalidCostOverLimit indicates that the cost specified was > limit.Burst.
var ErrInvalidCostOverLimit = fmt.Errorf("invalid cost, must be <= limit.Burst")

// newIPAddressBucketKey returns a bucketKey for limits that use
// the 'enum:ipAddress' bucket key format.
func newIPAddressBucketKey(name Name, ip netip.Addr) string {
	return joinWithColon(name.EnumString(), ip.String())
}

// newIPv6RangeCIDRBucketKey returns a bucketKey for limits that
// use the 'enum:ipv6RangeCIDR' bucket key format.
func newIPv6RangeCIDRBucketKey(name Name, prefix netip.Prefix) string {
	return joinWithColon(name.EnumString(), prefix.String())
}

// newRegIdBucketKey returns a bucketKey for limits that use the
// 'enum:regId' bucket key format.
func newRegIdBucketKey(name Name, regId int64) string {
	return joinWithColon(name.EnumString(), strconv.FormatInt(regId, 10))
}

// newDomainOrCIDRBucketKey returns a bucketKey for limits that use
// the 'enum:domainOrCIDR' bucket key formats.
func newDomainOrCIDRBucketKey(name Name, domainOrCIDR string) string {
	return joinWithColon(name.EnumString(), domainOrCIDR)
}

// newRegIdIdentValueBucketKey returns a bucketKey for limits that use the
// 'enum:regId:identValue' bucket key format.
func newRegIdIdentValueBucketKey(name Name, regId int64, orderIdent string) string {
	return joinWithColon(name.EnumString(), strconv.FormatInt(regId, 10), orderIdent)
}

// newFQDNSetBucketKey validates and returns a bucketKey for limits that use the
// 'enum:fqdnSet' bucket key format.
func newFQDNSetBucketKey(name Name, orderIdents identifier.ACMEIdentifiers) string {
	return joinWithColon(name.EnumString(), fmt.Sprintf("%x", core.HashIdentifiers(orderIdents)))
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
//   - reset-only: when reset is true, the bucket will be reset to full capacity.
//   - allow-only: when neither check nor spend are true, the transaction will
//     be considered "allowed" regardless of the bucket's capacity. This is
//     useful for limits that are disabled.
//
// The zero value of Transaction is an allow-only transaction and is valid even if
// it would fail validateTransaction (for instance because cost and burst are zero).
type Transaction struct {
	bucketKey string
	limit     *Limit
	cost      int64
	check     bool
	spend     bool
	reset     bool
}

func (txn Transaction) checkOnly() bool {
	return txn.check && !txn.spend && !txn.reset
}

func (txn Transaction) spendOnly() bool {
	return txn.spend && !txn.check && !txn.reset
}

func (txn Transaction) allowOnly() bool {
	return !txn.check && !txn.spend && !txn.reset
}

func (txn Transaction) resetOnly() bool {
	return txn.reset && !txn.check && !txn.spend
}

func validateTransaction(txn Transaction) (Transaction, error) {
	if txn.limit == nil {
		return Transaction{}, fmt.Errorf("invalid limit, must not be nil")
	}
	if txn.reset {
		if txn.check || txn.spend {
			return Transaction{}, fmt.Errorf("invalid reset transaction, check and spend must be false")
		}
		if txn.limit.Burst == 0 {
			return Transaction{}, fmt.Errorf("invalid limit, burst must be > 0")
		}
		return txn, nil
	}
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

func newTransaction(limit *Limit, bucketKey string, cost int64) (Transaction, error) {
	return validateTransaction(Transaction{
		bucketKey: bucketKey,
		limit:     limit,
		cost:      cost,
		check:     true,
		spend:     true,
	})
}

func newCheckOnlyTransaction(limit *Limit, bucketKey string, cost int64) (Transaction, error) {
	return validateTransaction(Transaction{
		bucketKey: bucketKey,
		limit:     limit,
		cost:      cost,
		check:     true,
	})
}

func newSpendOnlyTransaction(limit *Limit, bucketKey string, cost int64) (Transaction, error) {
	return validateTransaction(Transaction{
		bucketKey: bucketKey,
		limit:     limit,
		cost:      cost,
		spend:     true,
	})
}

func newResetTransaction(limit *Limit, bucketKey string) (Transaction, error) {
	return validateTransaction(Transaction{
		bucketKey: bucketKey,
		limit:     limit,
		reset:     true,
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

func (builder *TransactionBuilder) Ready() bool {
	return builder.limitRegistry.overridesLoaded
}

// GetOverridesFunc is used to pass in the sa.GetEnabledRateLimitOverrides
// method to NewTransactionBuilderFromDatabase, rather than storing a full
// sa.SQLStorageAuthority. This makes testing significantly simpler.
type GetOverridesFunc func(context.Context, *emptypb.Empty, ...grpc.CallOption) (grpc.ServerStreamingClient[sapb.RateLimitOverrideResponse], error)

// NewTransactionBuilderFromDatabase returns a new *TransactionBuilder. The
// provided defaults path is expected to be a path to a YAML file that contains
// the default limits. The provided overrides function is expected to be an SA's
// GetEnabledRateLimitOverrides. Both are required.
func NewTransactionBuilderFromDatabase(defaults string, overrides GetOverridesFunc, stats prometheus.Registerer, logger blog.Logger) (*TransactionBuilder, error) {
	defaultsData, err := loadDefaultsFromFile(defaults)
	if err != nil {
		return nil, err
	}

	refresher := func(ctx context.Context, errorGauge prometheus.Gauge, logger blog.Logger) (Limits, error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		stream, err := overrides(ctx, &emptypb.Empty{})
		if err != nil {
			return nil, fmt.Errorf("fetching enabled overrides: %w", err)
		}

		overrides := make(Limits)
		var errorCount float64
		for {
			resp, err := stream.Recv()
			if err != nil {
				if err == io.EOF {
					break
				}
				return nil, fmt.Errorf("reading overrides stream: %w", err)
			}

			override := &Limit{
				Burst:      resp.Override.Burst,
				Count:      resp.Override.Count,
				Period:     config.Duration{Duration: resp.Override.Period.AsDuration()},
				Name:       Name(resp.Override.LimitEnum),
				isOverride: true,
			}

			err = ValidateLimit(override)
			if err != nil {
				logger.Errf("hydrating %s override with key %q: %s", override.Name.String(), resp.Override.BucketKey, err)
				errorCount++
				continue
			}

			overrides[resp.Override.BucketKey] = override
		}
		errorGauge.Set(errorCount)
		return overrides, nil
	}

	return NewTransactionBuilder(defaultsData, refresher, stats, logger)
}

// NewTransactionBuilderFromFiles returns a new *TransactionBuilder. The
// provided defaults and overrides paths are expected to be paths to YAML files
// that contain the default and override limits, respectively. Overrides is
// optional, defaults is required.
func NewTransactionBuilderFromFiles(defaults string, overrides string, stats prometheus.Registerer, logger blog.Logger) (*TransactionBuilder, error) {
	defaultsData, err := loadDefaultsFromFile(defaults)
	if err != nil {
		return nil, err
	}

	if overrides == "" {
		return NewTransactionBuilder(defaultsData, nil, stats, logger)
	}

	refresher := func(ctx context.Context, _ prometheus.Gauge, _ blog.Logger) (Limits, error) {
		overridesData, err := loadOverridesFromFile(overrides)
		if err != nil {
			return nil, err
		}
		return parseOverrideLimits(overridesData)
	}

	return NewTransactionBuilder(defaultsData, refresher, stats, logger)
}

// NewTransactionBuilder returns a new *TransactionBuilder. A defaults map is
// required.
func NewTransactionBuilder(defaultConfigs LimitConfigs, refresher OverridesRefresher, stats prometheus.Registerer, logger blog.Logger) (*TransactionBuilder, error) {
	defaults, err := parseDefaultLimits(defaultConfigs)
	if err != nil {
		return nil, err
	}

	if refresher == nil {
		refresher = func(context.Context, prometheus.Gauge, blog.Logger) (Limits, error) {
			return nil, nil
		}
	}

	overridesTimestamp := promauto.With(stats).NewGauge(prometheus.GaugeOpts{
		Namespace: "ratelimits",
		Subsystem: "overrides",
		Name:      "timestamp_seconds",
		Help:      "A gauge with the last timestamp when overrides were successfully loaded",
	})

	overridesErrors := promauto.With(stats).NewGauge(prometheus.GaugeOpts{
		Namespace: "ratelimits",
		Subsystem: "overrides",
		Name:      "errors",
		Help:      "A gauge with the number of errors while last trying to load overrides",
	})

	overridesPerLimit := promauto.With(stats).NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "ratelimits",
		Subsystem: "overrides",
		Name:      "active",
		Help:      "A gauge with the number of overrides, partitioned by rate limit",
	}, []string{"limit"})

	registry := &limitRegistry{
		defaults:         defaults,
		refreshOverrides: refresher,
		logger:           logger,

		overridesTimestamp: overridesTimestamp,
		overridesErrors:    overridesErrors,
		overridesPerLimit:  *overridesPerLimit,
	}

	return &TransactionBuilder{registry}, nil
}

// registrationsPerIPAddressTransaction returns a Transaction for the
// NewRegistrationsPerIPAddress limit for the provided IP address.
func (builder *TransactionBuilder) registrationsPerIPAddressTransaction(ip netip.Addr) (Transaction, error) {
	bucketKey := newIPAddressBucketKey(NewRegistrationsPerIPAddress, ip)
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
func (builder *TransactionBuilder) registrationsPerIPv6RangeTransaction(ip netip.Addr) (Transaction, error) {
	prefix, err := coveringIPPrefix(NewRegistrationsPerIPv6Range, ip)
	if err != nil {
		return Transaction{}, fmt.Errorf("computing covering prefix for %q: %w", ip, err)
	}
	bucketKey := newIPv6RangeCIDRBucketKey(NewRegistrationsPerIPv6Range, prefix)

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
	bucketKey := newRegIdBucketKey(NewOrdersPerAccount, regId)
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
// of Transactions for the provided order identifiers. An error is returned if
// any of the order identifiers' values are invalid. This method should be used
// for checking capacity, before allowing more authorizations to be created.
//
// Precondition: len(orderIdents) < maxNames.
func (builder *TransactionBuilder) FailedAuthorizationsPerDomainPerAccountCheckOnlyTransactions(regId int64, orderIdents identifier.ACMEIdentifiers) ([]Transaction, error) {
	// FailedAuthorizationsPerDomainPerAccount limit uses the 'enum:regId'
	// bucket key format for overrides.
	perAccountBucketKey := newRegIdBucketKey(FailedAuthorizationsPerDomainPerAccount, regId)
	limit, err := builder.getLimit(FailedAuthorizationsPerDomainPerAccount, perAccountBucketKey)
	if err != nil {
		if errors.Is(err, errLimitDisabled) {
			return []Transaction{newAllowOnlyTransaction()}, nil
		}
		return nil, err
	}

	var txns []Transaction
	for _, ident := range orderIdents {
		// FailedAuthorizationsPerDomainPerAccount limit uses the
		// 'enum:regId:identValue' bucket key format for transactions.
		perIdentValuePerAccountBucketKey := newRegIdIdentValueBucketKey(FailedAuthorizationsPerDomainPerAccount, regId, ident.Value)

		// Add a check-only transaction for each per identValue per account
		// bucket.
		txn, err := newCheckOnlyTransaction(limit, perIdentValuePerAccountBucketKey, 1)
		if err != nil {
			return nil, err
		}
		txns = append(txns, txn)
	}
	return txns, nil
}

// FailedAuthorizationsPerDomainPerAccountSpendOnlyTransaction returns a spend-
// only Transaction for the provided order identifier. An error is returned if
// the order identifier's value is invalid. This method should be used for
// spending capacity, as a result of a failed authorization.
func (builder *TransactionBuilder) FailedAuthorizationsPerDomainPerAccountSpendOnlyTransaction(regId int64, orderIdent identifier.ACMEIdentifier) (Transaction, error) {
	// FailedAuthorizationsPerDomainPerAccount limit uses the 'enum:regId'
	// bucket key format for overrides.
	perAccountBucketKey := newRegIdBucketKey(FailedAuthorizationsPerDomainPerAccount, regId)
	limit, err := builder.getLimit(FailedAuthorizationsPerDomainPerAccount, perAccountBucketKey)
	if err != nil {
		if errors.Is(err, errLimitDisabled) {
			return newAllowOnlyTransaction(), nil
		}
		return Transaction{}, err
	}

	// FailedAuthorizationsPerDomainPerAccount limit uses the
	// 'enum:regId:identValue' bucket key format for transactions.
	perIdentValuePerAccountBucketKey := newRegIdIdentValueBucketKey(FailedAuthorizationsPerDomainPerAccount, regId, orderIdent.Value)
	txn, err := newSpendOnlyTransaction(limit, perIdentValuePerAccountBucketKey, 1)
	if err != nil {
		return Transaction{}, err
	}

	return txn, nil
}

// FailedAuthorizationsForPausingPerDomainPerAccountTransaction returns a
// Transaction for the provided order identifier. An error is returned if the
// order identifier's value is invalid. This method should be used for spending
// capacity, as a result of a failed authorization.
func (builder *TransactionBuilder) FailedAuthorizationsForPausingPerDomainPerAccountTransaction(regId int64, orderIdent identifier.ACMEIdentifier) (Transaction, error) {
	// FailedAuthorizationsForPausingPerDomainPerAccount limit uses the 'enum:regId'
	// bucket key format for overrides.
	perAccountBucketKey := newRegIdBucketKey(FailedAuthorizationsForPausingPerDomainPerAccount, regId)
	limit, err := builder.getLimit(FailedAuthorizationsForPausingPerDomainPerAccount, perAccountBucketKey)
	if err != nil {
		if errors.Is(err, errLimitDisabled) {
			return newAllowOnlyTransaction(), nil
		}
		return Transaction{}, err
	}

	// FailedAuthorizationsForPausingPerDomainPerAccount limit uses the
	// 'enum:regId:identValue' bucket key format for transactions.
	perIdentValuePerAccountBucketKey := newRegIdIdentValueBucketKey(FailedAuthorizationsForPausingPerDomainPerAccount, regId, orderIdent.Value)
	txn, err := newTransaction(limit, perIdentValuePerAccountBucketKey, 1)
	if err != nil {
		return Transaction{}, err
	}

	return txn, nil
}

// certificatesPerDomainCheckOnlyTransactions returns a slice of Transactions
// for the provided order identifiers. It returns an error if any of the order
// identifiers' values are invalid. This method should be used for checking
// capacity, before allowing more orders to be created. If a
// CertificatesPerDomainPerAccount override is active, a check-only Transaction
// is created for each per account per domainOrCIDR bucket. Otherwise, a
// check-only Transaction is generated for each global per domainOrCIDR bucket.
// This method should be used for checking capacity, before allowing more orders
// to be created.
//
// Precondition: All orderIdents must comply with policy.WellFormedIdentifiers.
func (builder *TransactionBuilder) certificatesPerDomainCheckOnlyTransactions(regId int64, orderIdents identifier.ACMEIdentifiers) ([]Transaction, error) {
	if len(orderIdents) > 100 {
		return nil, fmt.Errorf("unwilling to process more than 100 rate limit transactions, got %d", len(orderIdents))
	}

	perAccountLimitBucketKey := newRegIdBucketKey(CertificatesPerDomainPerAccount, regId)
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

	coveringIdents, err := coveringIdentifiers(orderIdents)
	if err != nil {
		return nil, err
	}

	var txns []Transaction
	for _, ident := range coveringIdents {
		perDomainOrCIDRBucketKey := newDomainOrCIDRBucketKey(CertificatesPerDomain, ident)
		if accountOverride {
			if !perAccountLimit.isOverride {
				return nil, fmt.Errorf("shouldn't happen: CertificatesPerDomainPerAccount limit is not an override")
			}
			perAccountPerDomainOrCIDRBucketKey := newRegIdIdentValueBucketKey(CertificatesPerDomainPerAccount, regId, ident)
			// Add a check-only transaction for each per account per identValue
			// bucket.
			txn, err := newCheckOnlyTransaction(perAccountLimit, perAccountPerDomainOrCIDRBucketKey, 1)
			if err != nil {
				if errors.Is(err, errLimitDisabled) {
					continue
				}
				return nil, err
			}
			txns = append(txns, txn)
		} else {
			// Use the per domainOrCIDR bucket key when no per account per
			// domainOrCIDR override is configured.
			perDomainOrCIDRLimit, err := builder.getLimit(CertificatesPerDomain, perDomainOrCIDRBucketKey)
			if err != nil {
				if errors.Is(err, errLimitDisabled) {
					continue
				}
				return nil, err
			}
			// Add a check-only transaction for each per domainOrCIDR bucket.
			txn, err := newCheckOnlyTransaction(perDomainOrCIDRLimit, perDomainOrCIDRBucketKey, 1)
			if err != nil {
				return nil, err
			}
			txns = append(txns, txn)
		}
	}
	return txns, nil
}

// CertificatesPerDomainSpendOnlyTransactions returns a slice of Transactions
// for the provided order identifiers. It returns an error if any of the order
// identifiers' values are invalid. If a CertificatesPerDomainPerAccount
// override is configured, it generates two types of Transactions:
//   - A spend-only Transaction for each per-account, per-domainOrCIDR bucket,
//     which enforces the limit on certificates issued per domainOrCIDR for
//     each account.
//   - A spend-only Transaction for each per-domainOrCIDR bucket, which
//     enforces the global limit on certificates issued per domainOrCIDR.
//
// If no CertificatesPerDomainPerAccount override is present, it returns a
// spend-only Transaction for each global per-domainOrCIDR bucket. This method
// should be used for spending capacity, when a certificate is issued.
//
// Precondition: orderIdents must all pass policy.WellFormedIdentifiers.
func (builder *TransactionBuilder) CertificatesPerDomainSpendOnlyTransactions(regId int64, orderIdents identifier.ACMEIdentifiers) ([]Transaction, error) {
	if len(orderIdents) > 100 {
		return nil, fmt.Errorf("unwilling to process more than 100 rate limit transactions, got %d", len(orderIdents))
	}

	perAccountLimitBucketKey := newRegIdBucketKey(CertificatesPerDomainPerAccount, regId)
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

	coveringIdents, err := coveringIdentifiers(orderIdents)
	if err != nil {
		return nil, err
	}

	var txns []Transaction
	for _, ident := range coveringIdents {
		perDomainOrCIDRBucketKey := newDomainOrCIDRBucketKey(CertificatesPerDomain, ident)
		if accountOverride {
			if !perAccountLimit.isOverride {
				return nil, fmt.Errorf("shouldn't happen: CertificatesPerDomainPerAccount limit is not an override")
			}
			perAccountPerDomainOrCIDRBucketKey := newRegIdIdentValueBucketKey(CertificatesPerDomainPerAccount, regId, ident)
			// Add a spend-only transaction for each per account per
			// domainOrCIDR bucket.
			txn, err := newSpendOnlyTransaction(perAccountLimit, perAccountPerDomainOrCIDRBucketKey, 1)
			if err != nil {
				return nil, err
			}
			txns = append(txns, txn)

			perDomainOrCIDRLimit, err := builder.getLimit(CertificatesPerDomain, perDomainOrCIDRBucketKey)
			if err != nil {
				if errors.Is(err, errLimitDisabled) {
					continue
				}
				return nil, err
			}

			// Add a spend-only transaction for each per domainOrCIDR bucket.
			txn, err = newSpendOnlyTransaction(perDomainOrCIDRLimit, perDomainOrCIDRBucketKey, 1)
			if err != nil {
				return nil, err
			}
			txns = append(txns, txn)
		} else {
			// Use the per domainOrCIDR bucket key when no per account per
			// domainOrCIDR override is configured.
			perDomainOrCIDRLimit, err := builder.getLimit(CertificatesPerDomain, perDomainOrCIDRBucketKey)
			if err != nil {
				if errors.Is(err, errLimitDisabled) {
					continue
				}
				return nil, err
			}
			// Add a spend-only transaction for each per domainOrCIDR bucket.
			txn, err := newSpendOnlyTransaction(perDomainOrCIDRLimit, perDomainOrCIDRBucketKey, 1)
			if err != nil {
				return nil, err
			}
			txns = append(txns, txn)
		}
	}
	return txns, nil
}

// certificatesPerFQDNSetCheckOnlyTransaction returns a check-only Transaction
// for the provided order identifiers. This method should only be used for
// checking capacity, before allowing more orders to be created.
func (builder *TransactionBuilder) certificatesPerFQDNSetCheckOnlyTransaction(orderIdents identifier.ACMEIdentifiers) (Transaction, error) {
	bucketKey := newFQDNSetBucketKey(CertificatesPerFQDNSet, orderIdents)
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
// for the provided order identifiers. This method should only be used for
// spending capacity, when a certificate is issued.
func (builder *TransactionBuilder) CertificatesPerFQDNSetSpendOnlyTransaction(orderIdents identifier.ACMEIdentifiers) (Transaction, error) {
	bucketKey := newFQDNSetBucketKey(CertificatesPerFQDNSet, orderIdents)
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
// Precondition: idents must be a list of identifiers that all pass
// policy.WellFormedIdentifiers.
func (builder *TransactionBuilder) NewOrderLimitTransactions(regId int64, idents identifier.ACMEIdentifiers, isRenewal bool) ([]Transaction, error) {
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

	txns, err := builder.FailedAuthorizationsPerDomainPerAccountCheckOnlyTransactions(regId, idents)
	if err != nil {
		return nil, makeTxnError(err, FailedAuthorizationsPerDomainPerAccount)
	}
	transactions = append(transactions, txns...)

	if !isRenewal {
		txns, err := builder.certificatesPerDomainCheckOnlyTransactions(regId, idents)
		if err != nil {
			return nil, makeTxnError(err, CertificatesPerDomain)
		}
		transactions = append(transactions, txns...)
	}

	txn, err := builder.certificatesPerFQDNSetCheckOnlyTransaction(idents)
	if err != nil {
		return nil, makeTxnError(err, CertificatesPerFQDNSet)
	}
	return append(transactions, txn), nil
}

// NewAccountLimitTransactions takes in an IP address from a new-account request
// and returns the set of rate limit transactions that should be evaluated
// before allowing the request to proceed.
func (builder *TransactionBuilder) NewAccountLimitTransactions(ip netip.Addr) ([]Transaction, error) {
	makeTxnError := func(err error, limit Name) error {
		return fmt.Errorf("error constructing rate limit transaction for %s rate limit: %w", limit, err)
	}

	var transactions []Transaction
	txn, err := builder.registrationsPerIPAddressTransaction(ip)
	if err != nil {
		return nil, makeTxnError(err, NewRegistrationsPerIPAddress)
	}
	transactions = append(transactions, txn)

	if ip.Is4() {
		// This request was made from an IPv4 address.
		return transactions, nil
	}

	txn, err = builder.registrationsPerIPv6RangeTransaction(ip)
	if err != nil {
		return nil, makeTxnError(err, NewRegistrationsPerIPv6Range)
	}
	return append(transactions, txn), nil
}

func (builder *TransactionBuilder) NewPausingResetTransactions(regId int64, orderIdent identifier.ACMEIdentifier) ([]Transaction, error) {
	perAccountBucketKey := newRegIdBucketKey(FailedAuthorizationsForPausingPerDomainPerAccount, regId)
	limit, err := builder.getLimit(FailedAuthorizationsForPausingPerDomainPerAccount, perAccountBucketKey)
	if err != nil {
		if errors.Is(err, errLimitDisabled) {
			return []Transaction{newAllowOnlyTransaction()}, nil
		}
		return nil, err
	}

	perIdentValuePerAccountBucketKey := newRegIdIdentValueBucketKey(FailedAuthorizationsForPausingPerDomainPerAccount, regId, orderIdent.Value)
	txn, err := newResetTransaction(limit, perIdentValuePerAccountBucketKey)
	if err != nil {
		return nil, err
	}

	return []Transaction{txn}, nil
}

// LimitOverrideRequestsPerIPAddressTransaction returns a Transaction for the
// LimitOverrideRequestsPerIPAddress limit for the provided IP address. This
// limit is used to rate limit requests to the SFE override request endpoint.
func (builder *TransactionBuilder) LimitOverrideRequestsPerIPAddressTransaction(ip netip.Addr) (Transaction, error) {
	bucketKey := newIPAddressBucketKey(LimitOverrideRequestsPerIPAddress, ip)
	limit, err := builder.getLimit(LimitOverrideRequestsPerIPAddress, bucketKey)
	if err != nil {
		if errors.Is(err, errLimitDisabled) {
			return newAllowOnlyTransaction(), nil
		}
		return Transaction{}, err
	}
	return newTransaction(limit, bucketKey, 1)
}
