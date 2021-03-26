package probers

import (
	"fmt"
	"net/http"
	"time"
)

// HTTPProbe is the exported 'Prober' object for monitors configured to
// perform HTTP requests.
type HTTPProbe struct {
	url    string
	rcodes []int
}

// Name returns a string that uniquely identifies the monitor.
func (p HTTPProbe) Name() string {
	return fmt.Sprintf("%s-%d", p.url, p.rcodes)
}

// Kind returns a name that uniquely identifies the `Kind` of `Prober`.
func (p HTTPProbe) Kind() string {
	return "HTTP"
}

// isExpected ensures that the received HTTP response code matches one
// that's expected.
func (p HTTPProbe) isExpected(received int) bool {
	for _, c := range p.rcodes {
		if received == c {
			return true
		}
	}
	return false
}

// Probe performs the configured HTTP request.
func (p HTTPProbe) Probe(timeout time.Duration) (bool, time.Duration) {
	client := http.Client{Timeout: timeout}
	start := time.Now()
	// TODO(@beautifulentropy): add support for more than HTTP GET
	resp, err := client.Get(p.url)
	if err != nil {
		return false, time.Since(start)
	}
	return p.isExpected(resp.StatusCode), time.Since(start)
}
