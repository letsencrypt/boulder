package ctpolicy

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/letsencrypt/boulder/ctpolicy/loglist"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
)

func TestSatisfiable(t *testing.T) {
	for _, tc := range []struct {
		name string
		logs loglist.List
		want bool
	}{
		{
			name: "no logs",
			logs: nil,
			want: false,
		},
		{
			name: "one operator",
			logs: loglist.List{
				{Operator: "A"},
				{Operator: "A"},
			},
			want: false,
		},
		{
			name: "two operators",
			logs: loglist.List{
				{Operator: "A"},
				{Operator: "B"},
			},
			want: true,
		},
		{
			name: "multiple logs",
			logs: loglist.List{
				{Operator: "A"},
				{Operator: "A"},
				{Operator: "B"},
				{Operator: "C"},
			},
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := satisfiable(tc.logs)
			if got != tc.want {
				t.Errorf("satisfiable(%v) = %t, want %t", tc.logs, got, tc.want)
			}
		})
	}
}

func TestHorizon(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	day := func(d int) time.Time { return now.AddDate(0, 0, d) }

	for _, tc := range []struct {
		name string
		logs loglist.List
		want time.Time
	}{
		{
			name: "no logs",
			logs: nil,
			want: now,
		},
		{
			name: "non-sharded logs suffice forever",
			logs: loglist.List{
				{Operator: "A"},
				{Operator: "B"},
			},
			want: horizonNever,
		},
		{
			name: "horizon is the end of the earliest critical shard",
			logs: loglist.List{
				{Operator: "A", StartInclusive: day(-10), EndExclusive: day(30)},
				{Operator: "B", StartInclusive: day(-10), EndExclusive: day(60)},
			},
			want: day(30),
		},
		{
			name: "successor shard extends the horizon",
			logs: loglist.List{
				{Operator: "A", StartInclusive: day(-10), EndExclusive: day(30)},
				{Operator: "A", StartInclusive: day(30), EndExclusive: day(90)},
				{Operator: "B", StartInclusive: day(-10), EndExclusive: day(60)},
			},
			want: day(60),
		},
		{
			name: "gap between shards is the horizon",
			logs: loglist.List{
				{Operator: "A", StartInclusive: day(-10), EndExclusive: day(30)},
				{Operator: "A", StartInclusive: day(31), EndExclusive: day(90)},
				{Operator: "B"},
			},
			want: day(30),
		},
		{
			name: "coverage which only begins later does not help before it starts",
			logs: loglist.List{
				{Operator: "A", StartInclusive: day(10), EndExclusive: day(90)},
				{Operator: "B"},
			},
			want: now,
		},
		{
			name: "shards which already ended are ignored",
			logs: loglist.List{
				{Operator: "A", StartInclusive: day(-90), EndExclusive: day(-10)},
				{Operator: "A", StartInclusive: day(-10), EndExclusive: day(90)},
				{Operator: "B"},
			},
			want: day(90),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := horizon(tc.logs, now)
			if !got.Equal(tc.want) {
				t.Errorf("horizon(...) = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestHorizonMetrics(t *testing.T) {
	// Inside a synctest bubble, time.Now() is deterministic, so New computes
	// the horizon from a known instant.
	synctest.Test(t, func(t *testing.T) {
		mockLog := blog.NewMock()
		defer mockLog.Close()
		now := time.Now()
		nextMonth := now.AddDate(0, 1, 0)
		nextYear := now.AddDate(1, 0, 0)

		ctp := New(&mockPub{}, loglist.List{
			{Name: "LogA1", Operator: "OperA", EndExclusive: nextMonth},
			{Name: "LogA2", Operator: "OperA", EndExclusive: nextYear},
			{Name: "LogB1", Operator: "OperB", EndExclusive: nextYear},
		}, nil, nil, 0, mockLog, metrics.NoopRegisterer)
		test.AssertMetricWithLabelsEquals(t, ctp.horizonGauge, prometheus.Labels{}, float64(nextYear.Unix()))

		// Non-sharded logs which satisfy the policy have no horizon.
		ctp = New(&mockPub{}, loglist.List{
			{Name: "LogA1", Operator: "OperA"},
			{Name: "LogB1", Operator: "OperB"},
		}, nil, nil, 0, mockLog, metrics.NoopRegisterer)
		test.AssertMetricWithLabelsEquals(t, ctp.horizonGauge, prometheus.Labels{}, float64(horizonNever.Unix()))

		// A single operator can never satisfy the policy, so the horizon is
		// the moment of startup.
		ctp = New(&mockPub{}, loglist.List{
			{Name: "LogA1", Operator: "OperA"},
			{Name: "LogA2", Operator: "OperA"},
		}, nil, nil, 0, mockLog, metrics.NoopRegisterer)
		test.AssertMetricWithLabelsEquals(t, ctp.horizonGauge, prometheus.Labels{}, float64(now.Unix()))
	})
}
