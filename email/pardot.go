package email

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/core"
)

const (
	// tokenPath is the path to the Salesforce OAuth2 token endpoint.
	tokenPath = "/services/oauth2/token"

	// prospectsPath is the path to the Pardot v5 Prospects endpoint. This
	// endpoint will create a new Prospect if one does not already exist.
	prospectsPath = "/api/v5/prospects"

	// maxAttempts is the maximum number of attempts to retry a request.
	maxAttempts = 3

	// retryBackoffBase is the base for exponential backoff.
	retryBackoffBase = 2.0

	// retryBackoffMax is the maximum backoff time.
	retryBackoffMax = 10 * time.Second

	// retryBackoffMin is the minimum backoff time.
	retryBackoffMin = 200 * time.Millisecond
)

// oAuthToken holds the OAuth2 access token and its expiration.
type oAuthToken struct {
	sync.Mutex

	accessToken string
	expiresAt   time.Time
}

// PardotClient handles authentication and sending contacts to Pardot.
type PardotClient struct {
	businessUnit string
	clientId     string
	clientSecret string
	prospectsURL string
	tokenURL     string
	token        *oAuthToken
	clk          clock.Clock
}

// NewPardotClient creates a new PardotClient.
func NewPardotClient(clk clock.Clock, businessUnit, clientId, clientSecret, oauthbaseURL, pardotBaseURL string) (*PardotClient, error) {
	prospectsURL, err := url.JoinPath(pardotBaseURL, prospectsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to join upsert path: %w", err)
	}
	tokenURL, err := url.JoinPath(oauthbaseURL, tokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to join token path: %w", err)
	}

	return &PardotClient{
		businessUnit: businessUnit,
		clientId:     clientId,
		clientSecret: clientSecret,
		prospectsURL: prospectsURL,
		tokenURL:     tokenURL,

		token: &oAuthToken{},
		clk:   clk,
	}, nil
}

// updateToken updates the OAuth token if necessary.
func (pc *PardotClient) updateToken() error {
	pc.token.Lock()
	defer pc.token.Unlock()

	now := pc.clk.Now()
	if now.Before(pc.token.expiresAt.Add(-5*time.Minute)) && pc.token.accessToken != "" {
		return nil
	}

	resp, err := http.PostForm(pc.tokenURL, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {pc.clientId},
		"client_secret": {pc.clientSecret},
	})
	if err != nil {
		return fmt.Errorf("failed to retrieve token: %w", err)
	}
	defer resp.Body.Close()

	var respJSON struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if resp.StatusCode == http.StatusOK {
		err = json.NewDecoder(resp.Body).Decode(&respJSON)
		if err != nil {
			return fmt.Errorf("failed to decode token response: %w", err)
		}
		pc.token.accessToken = respJSON.AccessToken
		pc.token.expiresAt = pc.clk.Now().Add(time.Duration(respJSON.ExpiresIn) * time.Second)
		return nil
	}

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return fmt.Errorf("token request failed with status %d; while reading body: %w", resp.StatusCode, readErr)
	}
	return fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, body)
}

// redactEmail replaces all occurrences of an email address in a response body
// with "[REDACTED]".
func redactEmail(body []byte, email string) string {
	return string(bytes.ReplaceAll(body, []byte(email), []byte("[REDACTED]")))
}

// UpsertEmail sends an email to the Pardot Prospects endpoint, retrying up
// to 3 times with exponential backoff.
func (pc *PardotClient) UpsertEmail(email string) error {
	var finalErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := pc.updateToken()
		if err != nil {
			finalErr = err
		} else {
			break
		}

		if attempt < maxAttempts {
			time.Sleep(core.RetryBackoff(attempt, retryBackoffMin, retryBackoffMax, retryBackoffBase))
		}
	}

	if finalErr != nil {
		return finalErr
	}

	payload, err := json.Marshal(map[string]interface{}{
		"prospect": map[string]string{"email": email},
	})
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := http.NewRequest("POST", pc.prospectsURL, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("failed to create upsert request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+pc.token.accessToken)
		req.Header.Set("Pardot-Business-Unit-Id", pc.businessUnit)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			finalErr = fmt.Errorf("upsert request failed: %w", err)
		} else {
			defer resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				finalErr = fmt.Errorf("upsert request returned status %d; while reading body: %w", resp.StatusCode, err)
			} else {
				finalErr = fmt.Errorf("upsert request returned status %d: %s", resp.StatusCode, redactEmail(body, email))
			}
		}

		if attempt < maxAttempts {
			time.Sleep(core.RetryBackoff(attempt, retryBackoffMin, retryBackoffMax, retryBackoffBase))
		}
	}

	return finalErr
}
