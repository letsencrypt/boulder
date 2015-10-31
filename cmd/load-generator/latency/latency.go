package latency

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/codahale/hdrhistogram"
)

type histWrapper struct {
	*hdrhistogram.Histogram
}

// MarshalJSON is used to marshal histograms in a format that latency-charter.py
// understands
func (hw histWrapper) MarshalJSON() ([]byte, error) {
	var marshaler struct {
		X      []float64 `json:"x"`
		ValueY []int64   `json:"valueY"`
		CountY []int64   `json:"countY"`
	}
	for _, b := range hw.CumulativeDistribution() {
		marshaler.X = append(marshaler.X, b.Quantile/100)
		marshaler.ValueY = append(marshaler.ValueY, b.ValueAt)
		marshaler.CountY = append(marshaler.CountY, b.Count)
	}
	return json.Marshal(marshaler)
}

// String returns a string containing the histogram in the HistogramLogProcessor
// format suitable for plotting
func (hw histWrapper) String() string {
	buf := new(bytes.Buffer)
	w := new(tabwriter.Writer)
	w.Init(buf, 8, 1, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintln(w, "Value\tPercentile\tTotalCount\t\t1/1(1-Percentile)")
	for _, bracket := range hw.CumulativeDistribution() {
		percentile := bracket.Quantile / 100
		fmt.Fprintf(w, "%d\t%.5f\t%d\t\t%.2f\n", bracket.ValueAt, percentile, bracket.Count, 1.0/(1.0-percentile))
	}
	w.Flush()
	return buf.String()
}

// Map holds a bunch of HDRHistograms for recording latencies for multiple
// endpoints
type Map struct {
	lMu     *sync.Mutex
	latency map[string]*histWrapper

	minVal  int64
	maxVal  int64
	sigFigs int
}

// MarshalJSON is used to safely marshal the latency histogram map
func (e Map) MarshalJSON() ([]byte, error) {
	var marshaler struct {
		Latency map[string]*histWrapper `json:"latency"`
	}
	e.lMu.Lock()
	defer e.lMu.Unlock()
	marshaler.Latency = e.latency
	return json.Marshal(marshaler)
}

// New returns an initialized Map
func New(min, max int64, figs int) *Map {
	return &Map{
		lMu:     new(sync.Mutex),
		latency: make(map[string]*histWrapper),
		minVal:  min,
		maxVal:  max,
		sigFigs: figs,
	}
}

// Add adds a latency point for a specific endpoint to the relevant HDRHistogram
func (e *Map) Add(endpoint string, latency time.Duration) {
	e.lMu.Lock()
	defer e.lMu.Unlock()
	if _, found := e.latency[endpoint]; !found {
		e.latency[endpoint] = &histWrapper{hdrhistogram.New(e.minVal, e.maxVal, e.sigFigs)}
	}
	e.latency[endpoint].RecordValue(latency.Nanoseconds())
}

func (e *Map) String() string {
	e.lMu.Lock()
	defer e.lMu.Unlock()
	str := ""
	for e, h := range e.latency {
		str = fmt.Sprintf("%s\n\n%s:\n\n%s", str, e, h)
	}
	return str
}
