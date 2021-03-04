package observer

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// HTTPProbe is the exported handler object for monitors configured to
// perform HTTP requests
type HTTPProbe struct {
	URL   url.URL
	RCode int
}

// Name returns a name that uniquely identifies the monitor
func (p HTTPProbe) Name() string {
	return fmt.Sprintf("%s-%d", p.URL.String(), p.RCode)
}

// Type returns the type of prober as a string
func (p HTTPProbe) Type() string {
	return "HTTP"
}

// Do is the request handler for HTTP probes
func (p HTTPProbe) Do(timeout time.Duration) (bool, time.Duration) {
	client := http.Client{Timeout: timeout}
	start := time.Now()
	// TODO(@beautifulentropy): add support for more than HTTP GET
	resp, err := client.Get(p.URL.String())
	if err != nil {
		return false, time.Since(start)
	}
	if resp.StatusCode == p.RCode {
		return true, time.Since(start)
	}
	return false, time.Since(start)
}
