package ccadb

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

func getBody(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "CRL-Monitor/0.1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status %d for %q: %s", resp.StatusCode, url, string(body[:400]))
	}

	return body, nil
}

// httpGet is a simple wrapper around http.Client.Do that will retry on a fixed backoff schedule
func httpGet(ctx context.Context, url string) ([]byte, error) {
	// A fixed exponential backoff schedule. The final value is zero so that we don't sleep before
	// returning the final error.
	var err error
	for _, backoff := range []int{1000, 1250, 1562, 1953, 2441, 3051, 3814, 4768, 5960, 7450, 9313, 11641, 0} {
		var body []byte
		body, err = getBody(ctx, url)
		if err == nil {
			return body, nil
		}
		time.Sleep(time.Duration(backoff) * time.Millisecond)
	}
	return nil, err
}
