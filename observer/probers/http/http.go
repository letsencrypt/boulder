package probers

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"slices"

	"github.com/letsencrypt/boulder/observer/obsdialer"
)

// HTTPProbe is the exported 'Prober' object for monitors configured to
// perform HTTP requests.
type HTTPProbe struct {
	url       string
	rcodes    []int
	useragent string
	insecure  bool
}

// Name returns a string that uniquely identifies the monitor.
func (p HTTPProbe) Name() string {
	insecure := ""
	if p.insecure {
		insecure = "-insecure"
	}
	return fmt.Sprintf("%s-%d-%s%s", p.url, p.rcodes, p.useragent, insecure)
}

// Kind returns a name that uniquely identifies the `Kind` of `Prober`.
func (p HTTPProbe) Kind() string {
	return "HTTP"
}

// Probe performs the configured HTTP request.
func (p HTTPProbe) Probe(ctx context.Context) error {
	client := http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: p.insecure},
		DialContext:     obsdialer.Dialer.DialContext,
	}}
	req, err := http.NewRequestWithContext(ctx, "GET", p.url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", p.useragent)

	// TODO(@beautifulentropy): add support for more than HTTP GET
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	if !slices.Contains(p.rcodes, resp.StatusCode) {
		return fmt.Errorf("got HTTP status code %d, but want one of %#v", resp.StatusCode, p.rcodes)
	}

	return nil
}
