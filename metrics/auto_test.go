package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestPromAdjust(t *testing.T) {
	testCases := []struct {
		input, output string
	}{
		{"RA.Foo.Bar", "Foo_Bar"},
		{"", ""},
		{"RA-FOO-BAR", "RA_FOO_BAR"},
		{"RA.FOO-BAR", "FOO_BAR"},
		{"RA.FOO-BAR", "FOO_BAR"},
		{"RA", "RA"},
		{"RA>CA", "RACA"},
		{"RA?CA!- 99 @#$%&()", "RACA_99"},
	}
	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			if result := promAdjust(tc.input); result != tc.output {
				t.Errorf("promAdjust(%q) - expected %q, got %q", tc.input, tc.output, result)
			}
		})
	}
}

func TestAutoProm(t *testing.T) {
	var calledWithName string
	var madeGauge prometheus.Gauge
	recorder := func(s string) prometheus.Collector {
		calledWithName = s
		madeGauge = prometheus.NewGauge(prometheus.GaugeOpts{Name: "hi", Help: "hi"})
		return madeGauge
	}
	ap := newAutoProm()
	result := ap.get("foo.bar", recorder)
	if calledWithName != "bar" {
		t.Errorf("expected maker function to be called with bar, got %q", calledWithName)
	}
	if result != madeGauge {
		t.Errorf("got back a different gauge than we made")
	}
	// Try again, make sure it was memoized again.
	result2 := ap.get("foo.bar", recorder)
	if result != result2 {
		t.Errorf("expected to get same result twice, got a new result")
	}
}
