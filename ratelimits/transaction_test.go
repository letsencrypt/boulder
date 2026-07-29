package ratelimits

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"testing"
	"time"

	io_prometheus_client "github.com/prometheus/client_model/go"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/identifier"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/mocks"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/test"
)

func TestNewTransactionBuilderFromFiles_WithBadLimitsPath(t *testing.T) {
	t.Parallel()
	_, err := NewTransactionBuilderFromFiles("testdata/does-not-exist.yml", "", metrics.NoopRegisterer, blog.NewMock())
	test.AssertError(t, err, "should error")

	_, err = NewTransactionBuilderFromFiles("testdata/defaults.yml", "testdata/does-not-exist.yml", metrics.NoopRegisterer, blog.NewMock())
	test.AssertError(t, err, "should error")
}

func sortTransactions(txns []Transaction) []Transaction {
	sort.Slice(txns, func(i, j int) bool {
		return txns[i].bucketKey < txns[j].bucketKey
	})
	return txns
}

func TestNewRegistrationsPerIPAddressTransactions(t *testing.T) {
	t.Parallel()

	tb, err := NewTransactionBuilderFromFiles("../test/config-next/ratelimit-defaults.yml", "", metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "creating TransactionBuilder")

	// A check-and-spend transaction for the global limit.
	txn, err := tb.registrationsPerIPAddressTransaction(netip.MustParseAddr("1.2.3.4"))
	test.AssertNotError(t, err, "creating transaction")
	test.AssertEquals(t, txn.bucketKey, "1:1.2.3.4")
	test.Assert(t, txn.check && txn.spend, "should be check-and-spend")
}

func TestNewRegistrationsPerIPv6AddressTransactions(t *testing.T) {
	t.Parallel()

	tb, err := NewTransactionBuilderFromFiles("../test/config-next/ratelimit-defaults.yml", "", metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "creating TransactionBuilder")

	// A check-and-spend transaction for the global limit.
	txn, err := tb.registrationsPerIPv6RangeTransaction(netip.MustParseAddr("2001:db8::1"))
	test.AssertNotError(t, err, "creating transaction")
	test.AssertEquals(t, txn.bucketKey, "2:2001:db8::/48")
	test.Assert(t, txn.check && txn.spend, "should be check-and-spend")
}

func TestNewOrdersPerAccountTransactions(t *testing.T) {
	t.Parallel()

	tb, err := NewTransactionBuilderFromFiles("../test/config-next/ratelimit-defaults.yml", "", metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "creating TransactionBuilder")

	// A check-and-spend transaction for the global limit.
	txn, err := tb.ordersPerAccountTransaction(123456789)
	test.AssertNotError(t, err, "creating transaction")
	test.AssertEquals(t, txn.bucketKey, "3:123456789")
	test.Assert(t, txn.check && txn.spend, "should be check-and-spend")
}

func TestFailedAuthorizationsPerDomainPerAccountTransactions(t *testing.T) {
	t.Parallel()

	tb, err := NewTransactionBuilderFromFiles("../test/config-next/ratelimit-defaults.yml", "testdata/working_override_13371338.yml", metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "creating TransactionBuilder")
	err = tb.loadOverrides(context.Background())
	test.AssertNotError(t, err, "loading overrides")

	// A check-only transaction for the default per-account limit.
	txns, err := tb.FailedAuthorizationsPerDomainPerAccountCheckOnlyTransactions(123456789, identifier.NewDNSSlice([]string{"so.many.labels.here.example.com"}))
	test.AssertNotError(t, err, "creating transactions")
	test.AssertEquals(t, len(txns), 1)
	test.AssertEquals(t, txns[0].bucketKey, "4:123456789:so.many.labels.here.example.com")
	test.Assert(t, txns[0].checkOnly(), "should be check-only")
	test.Assert(t, !txns[0].limit.isOverride, "should not be an override")

	// A spend-only transaction for the default per-account limit.
	txn, err := tb.FailedAuthorizationsPerDomainPerAccountSpendOnlyTransaction(123456789, identifier.NewDNS("so.many.labels.here.example.com"))
	test.AssertNotError(t, err, "creating transaction")
	test.AssertEquals(t, txn.bucketKey, "4:123456789:so.many.labels.here.example.com")
	test.Assert(t, txn.spendOnly(), "should be spend-only")
	test.Assert(t, !txn.limit.isOverride, "should not be an override")

	// A check-only transaction for the per-account limit override.
	txns, err = tb.FailedAuthorizationsPerDomainPerAccountCheckOnlyTransactions(13371338, identifier.NewDNSSlice([]string{"so.many.labels.here.example.com"}))
	test.AssertNotError(t, err, "creating transactions")
	test.AssertEquals(t, len(txns), 1)
	test.AssertEquals(t, txns[0].bucketKey, "4:13371338:so.many.labels.here.example.com")
	test.Assert(t, txns[0].checkOnly(), "should be check-only")
	test.Assert(t, txns[0].limit.isOverride, "should be an override")

	// A spend-only transaction for the per-account limit override.
	txn, err = tb.FailedAuthorizationsPerDomainPerAccountSpendOnlyTransaction(13371338, identifier.NewDNS("so.many.labels.here.example.com"))
	test.AssertNotError(t, err, "creating transaction")
	test.AssertEquals(t, txn.bucketKey, "4:13371338:so.many.labels.here.example.com")
	test.Assert(t, txn.spendOnly(), "should be spend-only")
	test.Assert(t, txn.limit.isOverride, "should be an override")
}

func TestFailedAuthorizationsForPausingPerDomainPerAccountTransactions(t *testing.T) {
	t.Parallel()

	tb, err := NewTransactionBuilderFromFiles("../test/config-next/ratelimit-defaults.yml", "testdata/working_override_13371338.yml", metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "creating TransactionBuilder")
	err = tb.loadOverrides(context.Background())
	test.AssertNotError(t, err, "loading overrides")

	// A transaction for the per-account limit override.
	txn, err := tb.FailedAuthorizationsForPausingPerDomainPerAccountTransaction(13371338, identifier.NewDNS("so.many.labels.here.example.com"))
	test.AssertNotError(t, err, "creating transaction")
	test.AssertEquals(t, txn.bucketKey, "8:13371338:so.many.labels.here.example.com")
	test.Assert(t, txn.check && txn.spend, "should be check and spend")
	test.Assert(t, txn.limit.isOverride, "should be an override")
}

func TestCertificatesPerDomainTransactions(t *testing.T) {
	t.Parallel()

	tb, err := NewTransactionBuilderFromFiles("../test/config-next/ratelimit-defaults.yml", "", metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "creating TransactionBuilder")

	// One check-only transaction for the global limit.
	txns, err := tb.certificatesPerDomainCheckOnlyTransactions(123456789, identifier.NewDNSSlice([]string{"so.many.labels.here.example.com"}))
	test.AssertNotError(t, err, "creating transactions")
	test.AssertEquals(t, len(txns), 1)
	test.AssertEquals(t, txns[0].bucketKey, "5:example.com")
	test.Assert(t, txns[0].checkOnly(), "should be check-only")

	// One spend-only transaction for the global limit.
	txns, err = tb.CertificatesPerDomainSpendOnlyTransactions(123456789, identifier.NewDNSSlice([]string{"so.many.labels.here.example.com"}))
	test.AssertNotError(t, err, "creating transactions")
	test.AssertEquals(t, len(txns), 1)
	test.AssertEquals(t, txns[0].bucketKey, "5:example.com")
	test.Assert(t, txns[0].spendOnly(), "should be spend-only")
}

func TestCertificatesPerDomainPerAccountTransactions(t *testing.T) {
	t.Parallel()

	tb, err := NewTransactionBuilderFromFiles("../test/config-next/ratelimit-defaults.yml", "testdata/working_override_13371338.yml", metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "creating TransactionBuilder")
	err = tb.loadOverrides(context.Background())
	test.AssertNotError(t, err, "loading overrides")

	// We only expect a single check-only transaction for the per-account limit
	// override. We can safely ignore the global limit when an override is
	// present.
	txns, err := tb.certificatesPerDomainCheckOnlyTransactions(13371338, identifier.NewDNSSlice([]string{"so.many.labels.here.example.com"}))
	test.AssertNotError(t, err, "creating transactions")
	test.AssertEquals(t, len(txns), 1)
	test.AssertEquals(t, txns[0].bucketKey, "6:13371338:example.com")
	test.Assert(t, txns[0].checkOnly(), "should be check-only")
	test.Assert(t, txns[0].limit.isOverride, "should be an override")

	// Same as above, but with multiple example.com domains.
	txns, err = tb.certificatesPerDomainCheckOnlyTransactions(13371338, identifier.NewDNSSlice([]string{"so.many.labels.here.example.com", "z.example.com"}))
	test.AssertNotError(t, err, "creating transactions")
	test.AssertEquals(t, len(txns), 1)
	test.AssertEquals(t, txns[0].bucketKey, "6:13371338:example.com")
	test.Assert(t, txns[0].checkOnly(), "should be check-only")
	test.Assert(t, txns[0].limit.isOverride, "should be an override")

	// Same as above, but with different domains.
	txns, err = tb.certificatesPerDomainCheckOnlyTransactions(13371338, identifier.NewDNSSlice([]string{"so.many.labels.here.example.com", "z.example.net"}))
	test.AssertNotError(t, err, "creating transactions")
	txns = sortTransactions(txns)
	test.AssertEquals(t, len(txns), 2)
	test.AssertEquals(t, txns[0].bucketKey, "6:13371338:example.com")
	test.Assert(t, txns[0].checkOnly(), "should be check-only")
	test.Assert(t, txns[0].limit.isOverride, "should be an override")
	test.AssertEquals(t, txns[1].bucketKey, "6:13371338:example.net")
	test.Assert(t, txns[1].checkOnly(), "should be check-only")
	test.Assert(t, txns[1].limit.isOverride, "should be an override")

	// Two spend-only transactions, one for the global limit and one for the
	// per-account limit override.
	txns, err = tb.CertificatesPerDomainSpendOnlyTransactions(13371338, identifier.NewDNSSlice([]string{"so.many.labels.here.example.com"}))
	test.AssertNotError(t, err, "creating TransactionBuilder")
	test.AssertEquals(t, len(txns), 2)
	txns = sortTransactions(txns)
	test.AssertEquals(t, txns[0].bucketKey, "5:example.com")
	test.Assert(t, txns[0].spendOnly(), "should be spend-only")
	test.Assert(t, !txns[0].limit.isOverride, "should not be an override")

	test.AssertEquals(t, txns[1].bucketKey, "6:13371338:example.com")
	test.Assert(t, txns[1].spendOnly(), "should be spend-only")
	test.Assert(t, txns[1].limit.isOverride, "should be an override")
}

func TestCertificatesPerFQDNSetTransactions(t *testing.T) {
	t.Parallel()

	tb, err := NewTransactionBuilderFromFiles("../test/config-next/ratelimit-defaults.yml", "", metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "creating TransactionBuilder")

	// A single check-only transaction for the global limit.
	txn, err := tb.certificatesPerFQDNSetCheckOnlyTransaction(identifier.NewDNSSlice([]string{"example.com", "example.net", "example.org"}))
	test.AssertNotError(t, err, "creating transaction")
	namesHash := fmt.Sprintf("%x", core.HashIdentifiers(identifier.NewDNSSlice([]string{"example.com", "example.net", "example.org"})))
	test.AssertEquals(t, txn.bucketKey, "7:"+namesHash)
	test.Assert(t, txn.checkOnly(), "should be check-only")
	test.Assert(t, !txn.limit.isOverride, "should not be an override")
}

// NewTransactionBuilder's metrics are tested in TestLoadOverrides.
func TestNewTransactionBuilder(t *testing.T) {
	t.Parallel()

	expectedBurst := int64(10000)
	expectedCount := int64(10000)
	expectedPeriod := config.Duration{Duration: time.Hour * 168}

	tb, err := NewTransactionBuilder(LimitConfigs{
		NewRegistrationsPerIPAddress.String(): &LimitConfig{
			Burst:  expectedBurst,
			Count:  expectedCount,
			Period: expectedPeriod},
	}, nil, metrics.NoopRegisterer, blog.NewMock())
	test.AssertNotError(t, err, "creating TransactionBuilder")

	newRegDefault, ok := tb.limitRegistry.defaults[NewRegistrationsPerIPAddress.EnumString()]
	test.Assert(t, ok, "NewRegistrationsPerIPAddress was not populated in registry")
	test.AssertEquals(t, newRegDefault.Burst, expectedBurst)
	test.AssertEquals(t, newRegDefault.Count, expectedCount)
	test.AssertEquals(t, newRegDefault.Period, expectedPeriod)
}

func TestNewTransactionBuilderFromDatabase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		overrides            GetOverridesFunc
		expectOverrides      map[string]Limit
		expectError          string
		expectLog            string
		expectOverrideErrors float64
	}{
		{
			name: "error fetching enabled overrides",
			overrides: func(context.Context, *emptypb.Empty, ...grpc.CallOption) (grpc.ServerStreamingClient[sapb.RateLimitOverrideResponse], error) {
				return nil, errors.New("lol no")
			},
			expectError: "fetching enabled overrides: lol no",
		},
		{
			name: "empty results",
			overrides: func(context.Context, *emptypb.Empty, ...grpc.CallOption) (grpc.ServerStreamingClient[sapb.RateLimitOverrideResponse], error) {
				return &mocks.ServerStreamClient[sapb.RateLimitOverrideResponse]{Results: []*sapb.RateLimitOverrideResponse{}}, nil
			},
		},
		{
			name: "gRPC error",
			overrides: func(context.Context, *emptypb.Empty, ...grpc.CallOption) (grpc.ServerStreamingClient[sapb.RateLimitOverrideResponse], error) {
				return &mocks.ServerStreamClient[sapb.RateLimitOverrideResponse]{Err: errors.New("i ate ur toast m8")}, nil
			},
			expectError: "reading overrides stream: i ate ur toast m8",
		},
		{
			name: "2 valid overrides",
			overrides: func(context.Context, *emptypb.Empty, ...grpc.CallOption) (grpc.ServerStreamingClient[sapb.RateLimitOverrideResponse], error) {
				return &mocks.ServerStreamClient[sapb.RateLimitOverrideResponse]{Results: []*sapb.RateLimitOverrideResponse{
					{Override: &sapb.RateLimitOverride{LimitEnum: int64(StringToName["CertificatesPerDomain"]), BucketKey: joinWithColon(CertificatesPerDomain.EnumString(), "example.com"), Period: &durationpb.Duration{Seconds: 1}, Count: 1, Burst: 1}},
					{Override: &sapb.RateLimitOverride{LimitEnum: int64(StringToName["CertificatesPerDomain"]), BucketKey: joinWithColon(CertificatesPerDomain.EnumString(), "example.net"), Period: &durationpb.Duration{Seconds: 1}, Count: 1, Burst: 1}},
				}}, nil
			},
			expectOverrides: map[string]Limit{
				joinWithColon(CertificatesPerDomain.EnumString(), "example.com"): {Burst: 1, Count: 1, Period: config.Duration{Duration: time.Second}, Name: CertificatesPerDomain, emissionInterval: 1000000000, burstOffset: 1000000000, isOverride: true},
				joinWithColon(CertificatesPerDomain.EnumString(), "example.net"): {Burst: 1, Count: 1, Period: config.Duration{Duration: time.Second}, Name: CertificatesPerDomain, emissionInterval: 1000000000, burstOffset: 1000000000, isOverride: true},
			},
		},
		{
			name: "2 valid & 4 incomplete overrides",
			overrides: func(context.Context, *emptypb.Empty, ...grpc.CallOption) (grpc.ServerStreamingClient[sapb.RateLimitOverrideResponse], error) {
				return &mocks.ServerStreamClient[sapb.RateLimitOverrideResponse]{Results: []*sapb.RateLimitOverrideResponse{
					{Override: &sapb.RateLimitOverride{LimitEnum: int64(StringToName["CertificatesPerDomain"]), BucketKey: joinWithColon(CertificatesPerDomain.EnumString(), "example.com"), Period: &durationpb.Duration{Seconds: 1}, Count: 1, Burst: 1}},
					{Override: &sapb.RateLimitOverride{LimitEnum: int64(StringToName["CertificatesPerDomain"]), BucketKey: joinWithColon(CertificatesPerDomain.EnumString(), "example.net"), Period: &durationpb.Duration{Seconds: 1}, Count: 1, Burst: 1}},
					{Override: &sapb.RateLimitOverride{LimitEnum: int64(StringToName["CertificatesPerDomain"]), BucketKey: joinWithColon(CertificatesPerDomain.EnumString(), "bad-example.com")}},
					{Override: &sapb.RateLimitOverride{LimitEnum: int64(StringToName["CertificatesPerDomain"]), BucketKey: joinWithColon(CertificatesPerDomain.EnumString(), "bad-example.net")}},
					{Override: &sapb.RateLimitOverride{LimitEnum: int64(StringToName["CertificatesPerDomain"]), BucketKey: joinWithColon(CertificatesPerDomain.EnumString(), "worse-example.com")}},
					{Override: &sapb.RateLimitOverride{LimitEnum: int64(StringToName["CertificatesPerDomain"]), BucketKey: joinWithColon(CertificatesPerDomain.EnumString(), "even-worse-example.xyz")}},
				}}, nil
			},
			expectOverrides: map[string]Limit{
				joinWithColon(CertificatesPerDomain.EnumString(), "example.com"): {Burst: 1, Count: 1, Period: config.Duration{Duration: time.Second}, Name: CertificatesPerDomain, emissionInterval: 1000000000, burstOffset: 1000000000, isOverride: true},
				joinWithColon(CertificatesPerDomain.EnumString(), "example.net"): {Burst: 1, Count: 1, Period: config.Duration{Duration: time.Second}, Name: CertificatesPerDomain, emissionInterval: 1000000000, burstOffset: 1000000000, isOverride: true},
			},
			expectLog:            fmt.Sprintf("ERR: hydrating CertificatesPerDomain override with key %q: invalid burst '0', must be > 0", joinWithColon(CertificatesPerDomain.EnumString(), "bad-example.com")),
			expectOverrideErrors: 4,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockLog := blog.NewMock()
			tb, err := NewTransactionBuilderFromDatabase("../test/config-next/ratelimit-defaults.yml", tc.overrides, metrics.NoopRegisterer, mockLog)
			test.AssertNotError(t, err, "creating TransactionBuilder")
			err = tb.limitRegistry.loadOverrides(context.Background())
			if tc.expectError != "" {
				if err == nil {
					t.Errorf("expected error for test %q but got none", tc.name)
				}
				test.AssertContains(t, err.Error(), tc.expectError)
			} else {
				test.AssertNotError(t, err, tc.name)

				if tc.expectLog != "" {
					test.AssertSliceContains(t, mockLog.GetAll(), tc.expectLog)
				}

				for bucketKey, limit := range tc.expectOverrides {
					test.AssertDeepEquals(t, tb.overrides[bucketKey], &limit)
				}
				test.AssertEquals(t, len(tb.overrides), len(tc.expectOverrides))

				var iom io_prometheus_client.Metric
				err = tb.limitRegistry.overridesErrors.Write(&iom)
				test.AssertNotError(t, err, "encoding overridesErrors metric")
				test.AssertEquals(t, iom.Gauge.GetValue(), tc.expectOverrideErrors)
			}
		})
	}
}
