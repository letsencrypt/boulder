package ccadb

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/letsencrypt/boulder/core"
)

var backoffSchedule = []int{0, 1000, 1250, 1562, 1953, 2441, 3051, 3814, 4768, 5960, 7450, 9313, 11641}

const userAgent = "letsencrypt/boulder-observer-http-client"

func getBody(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Read up to 400 bytes of response body to include in error logs
		body, err := io.ReadAll(core.ErrOnLimitReader(resp.Body, 400))
		if err != nil && err != core.ErrReaderLimitReached {
			return nil, err
		}

		return nil, fmt.Errorf("http status %d for %q: %s", resp.StatusCode, url, string(body))
	}

	// Read up to ~1G of response body to return to caller
	body, err := io.ReadAll(core.ErrOnLimitReader(resp.Body, core.DefaultMaxCRLRead))
	if err != nil {
		return nil, err
	}

	return body, nil
}

// httpGet is a simple wrapper around http.Client.Do that will retry on a fixed backoff schedule
func httpGet(ctx context.Context, url string) ([]byte, error) {
	var err error
	for _, backoff := range backoffSchedule {
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

// httpGetExpectingStatusCode fetches the given URL and returns nil if the given status code matches
// the returned status code. It retries on a fixed backoff schedule.
func httpGetExpectingStatusCode(ctx context.Context, url string, status int) error {
	var err error
	var resp *http.Response
	for _, backoff := range backoffSchedule {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		// This isn't a `case <-time.After`, so we give priority to `<-ctx.Done()` even on the first iteration.
		time.Sleep(time.Duration(backoff) * time.Millisecond)
		var req *http.Request
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}

		req.Header.Set("User-Agent", userAgent)
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == status {
			return nil
		}
	}
	// If the last attempt failed with a transport error, resp is nil.
	if err != nil {
		return err
	}
	return fmt.Errorf("got unexpected status code %d, expected %d", resp.StatusCode, status)
}
