package measured_http

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	responseTime = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "response_time",
			Help: "Time taken to respond to a request",
		},
		[]string{"endpoint", "method", "code"})
)

func init() {
	prometheus.MustRegister(responseTime)
}

// responseWriterWithStatus satisfies http.ResponseWriter, but keeps track of the
// status code for gathering stats.
type responseWriterWithStatus struct {
	http.ResponseWriter
	code int
}

// WriteHeader stores a status code for generating stats.
func (r *responseWriterWithStatus) WriteHeader(code int) {
	r.code = code
	r.ResponseWriter.WriteHeader(code)
}

// MeasuredHandler wraps an http.Handler and records prometheus stats
type MeasuredHandler struct {
	http.Handler
	clk clock.Clock
}

func New(h http.Handler, clk clock.Clock) *MeasuredHandler {
	return &MeasuredHandler{
		Handler: h,
		clk:     clk,
	}
}

func endpointFromPath(path string) string {
	components := strings.Split(path, "/")
	var i int
	var v string
	for i, v = range components {
		matched, err := regexp.MatchString("^[a-z-]*$", v)
		if !matched || err != nil {
			return strings.Join(components[:i], "/")
		}
	}
	return path
}

func (h *MeasuredHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	begin := h.clk.Now()
	rwws := &responseWriterWithStatus{w, 0}
	// opy in case handlers down the chain use StripPrefix, which modifies
	// URL path.
	endpoint := endpointFromPath(r.URL.Path)

	defer func() {
		responseTime.With(prometheus.Labels{
			"endpoint": endpoint,
			"method":   r.Method,
			"code":     fmt.Sprintf("%d", rwws.code),
		}).Observe(h.clk.Since(begin).Seconds())
	}()

	h.Handler.ServeHTTP(rwws, r)
}
