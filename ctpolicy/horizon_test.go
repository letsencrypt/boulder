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
				{Operator: "A", Tiled: false},
				{Operator: "A", Tiled: false},
			},
			want: false,
		},
		{
			name: "all tiled",
			logs: loglist.List{
				{Operator: "A", Tiled: true},
				{Operator: "B", Tiled: true},
			},
			want: false,
		},
		{
			name: "one non-tiled, one tiled",
			logs: loglist.List{
				{Operator: "A", Tiled: false},
				{Operator: "B", Tiled: true},
			},
			want: true,
		},
		{
			name: "non-tiled log alongside another operator's tiled logs",
			logs: loglist.List{
				{Operator: "A", Tiled: false},
				{Operator: "A", Tiled: true},
				{Operator: "B", Tiled: true},
			},
			want: true,
		},
		{
			name: "two non-tiled operators",
			logs: loglist.List{
				{Operator: "A", Tiled: false},
				{Operator: "B", Tiled: false},
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
				{Operator: "A", Tiled: false},
				{Operator: "B", Tiled: true},
			},
			want: horizonNever,
		},
		{
			name: "horizon is the end of the earliest critical shard",
			logs: loglist.List{
				{Operator: "A", Tiled: false, StartInclusive: day(-10), EndExclusive: day(30)},
				{Operator: "B", Tiled: true, StartInclusive: day(-10), EndExclusive: day(60)},
			},
			want: day(30),
		},
		{
			name: "successor shard extends the horizon",
			logs: loglist.List{
				{Operator: "A", Tiled: false, StartInclusive: day(-10), EndExclusive: day(30)},
				{Operator: "A", Tiled: false, StartInclusive: day(30), EndExclusive: day(90)},
				{Operator: "B", Tiled: true, StartInclusive: day(-10), EndExclusive: day(60)},
			},
			want: day(60),
		},
		{
			name: "gap between shards is the horizon",
			logs: loglist.List{
				{Operator: "A", Tiled: false, StartInclusive: day(-10), EndExclusive: day(30)},
				{Operator: "A", Tiled: false, StartInclusive: day(31), EndExclusive: day(90)},
				{Operator: "B", Tiled: true},
			},
			want: day(30),
		},
		{
			name: "coverage which only begins later does not help before it starts",
			logs: loglist.List{
				{Operator: "A", Tiled: false, StartInclusive: day(10), EndExclusive: day(90)},
				{Operator: "B", Tiled: true},
			},
			want: now,
		},
		{
			name: "shards which already ended are ignored",
			logs: loglist.List{
				{Operator: "A", Tiled: false, StartInclusive: day(-90), EndExclusive: day(-10)},
				{Operator: "A", Tiled: false, StartInclusive: day(-10), EndExclusive: day(90)},
				{Operator: "B", Tiled: true},
			},
			want: day(90),
		},
		{
			name: "losing the last non-tiled log is the horizon",
			logs: loglist.List{
				{Operator: "A", Tiled: false, StartInclusive: day(-10), EndExclusive: day(30)},
				{Operator: "A", Tiled: true, StartInclusive: day(-10), EndExclusive: day(90)},
				{Operator: "B", Tiled: true, StartInclusive: day(-10), EndExclusive: day(90)},
			},
			want: day(30),
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
			{Name: "LogA1", Operator: "OperA", Tiled: false, EndExclusive: nextMonth},
			{Name: "LogA2", Operator: "OperA", Tiled: false, EndExclusive: nextYear},
			{Name: "LogB1", Operator: "OperB", Tiled: true, EndExclusive: nextYear},
		}, nil, nil, 0, mockLog, metrics.NoopRegisterer)
		test.AssertMetricWithLabelsEquals(t, ctp.horizonGauge, prometheus.Labels{}, float64(nextYear.Unix()))

		// Non-sharded logs which satisfy the policy have no horizon.
		ctp = New(&mockPub{}, loglist.List{
			{Name: "LogA1", Operator: "OperA", Tiled: false},
			{Name: "LogB1", Operator: "OperB", Tiled: true},
		}, nil, nil, 0, mockLog, metrics.NoopRegisterer)
		test.AssertMetricWithLabelsEquals(t, ctp.horizonGauge, prometheus.Labels{}, float64(horizonNever.Unix()))

		// A single operator can never satisfy the policy, so the horizon is
		// the moment of startup.
		ctp = New(&mockPub{}, loglist.List{
			{Name: "LogA1", Operator: "OperA", Tiled: false},
			{Name: "LogA2", Operator: "OperA", Tiled: true},
		}, nil, nil, 0, mockLog, metrics.NoopRegisterer)
		test.AssertMetricWithLabelsEquals(t, ctp.horizonGauge, prometheus.Labels{}, float64(now.Unix()))
	})
}
