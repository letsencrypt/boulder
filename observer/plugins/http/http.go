package main

import (
	"net/http"
	"net/url"
	"time"
)

// Probe is the exported handler object for monitors configured to use
// HTTP probes
type Probe struct {
	URL   url.URL
	RCode int
}

// Do performs the HTTP request provided by the monitor settings
func (p Probe) Do(tick time.Time, timeout time.Duration) (bool, time.Duration) {
	client := http.Client{Timeout: timeout}
	resp, err := client.Get(p.URL.String())
	if err != nil {
		return false, time.Since(tick)
	}
	if resp.StatusCode == p.RCode {
		return true, time.Since(tick)
	}
	return false, time.Since(tick)
}

func main() {
	return
}
