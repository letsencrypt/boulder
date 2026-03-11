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

	body, err := io.ReadAll(&io.LimitedReader{R: resp.Body, N: 100_000_000})
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		// Truncate the response body in case it's too big to be useful in logs.
		if len(body) > 400 {
			body = body[:400]
		}
		return nil, fmt.Errorf("http status %d for %q: %s", resp.StatusCode, url, string(body))
	}

	return body, nil
}

// httpGet is a simple wrapper around http.Client.Do that will retry on a fixed backoff schedule
func httpGet(ctx context.Context, url string) ([]byte, error) {
	// A fixed exponential backoff schedule.
	var err error
	for _, backoff := range []int{0, 1000, 1250, 1562, 1953, 2441, 3051, 3814, 4768, 5960, 7450, 9313, 11641} {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		// This isn't a `case <-time.After`, so we give priority to `<-ctx.Done()` even on the first iteration.
		time.Sleep(time.Duration(backoff) * time.Millisecond)
		var body []byte
		body, err = getBody(ctx, url)
		if err == nil {
			return body, nil
		}
	}
	return nil, err
}
