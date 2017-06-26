package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestPromAdjust(t *testing.T) {
	testCases := []struct {
		input, output string
	}{
		{"Foo.Bar", "Foo_Bar"},
		{"", ""},
		{"FOO-BAR", "FOO_BAR"},
		{">CA", "CA"},
		{"?CA!- 99 @#$%&()", "CA_99"},
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
	registry := prometheus.NewRegistry()
	ap := newAutoProm(registry)
	result := ap.get("foo.bar", recorder)
	if calledWithName != "foo_bar" {
		t.Errorf("expected maker function to be called with foo_bar, got %q", calledWithName)
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

func TestAutoRegisterer(t *testing.T) {
	registry := prometheus.NewRegistry()
	ap := newAutoRegisterer(registry)
	gauge := ap.autoGauge("ima_stat")
	expected := "Desc{fqName: \"ima_stat\", help: \"auto\", constLabels: {}, variableLabels: []}"
	if gauge == nil {
		t.Fatal("gauge was nil")
	}
	gaugeDesc := gauge.Desc().String()
	if gaugeDesc != expected {
		t.Errorf("gauge description: got %q, expected %q", gaugeDesc, expected)
	}
	counter := ap.autoCounter("ima_counter")
	expected = "Desc{fqName: \"ima_counter\", help: \"auto\", constLabels: {}, variableLabels: []}"
	if counter == nil {
		t.Fatal("counter was nil")
	}
	counterDesc := counter.Desc().String()
	if counterDesc != expected {
		t.Errorf("counter description: got %q, expected %q", counterDesc, expected)
	}
	summary := ap.autoSummary("ima_summary")
	expected = "Desc{fqName: \"ima_summary\", help: \"auto\", constLabels: {}, variableLabels: []}"
	if summary == nil {
		t.Fatal("summary was nil")
	}
	summaryDesc := summary.Desc().String()
	if summaryDesc != expected {
		t.Errorf("summary description: got %q, expected %q", summaryDesc, expected)
	}
}
