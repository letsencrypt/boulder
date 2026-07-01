package salesforce

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

	// contactsPath is the path to the Pardot v5 Prospect upsert-by-email
	// endpoint. This endpoint will create a new Prospect if one does not
	// already exist with the same email address.
	//
	// https://developer.salesforce.com/docs/marketing/pardot/guide/prospect-v5.html#prospect-upsert-by-email
	contactsPath = "/api/v5/objects/prospects/do/upsertLatestByEmail"

	// maxAttempts is the maximum number of attempts to retry a request.
	maxAttempts = 3

	// retryBackoffBase is the base for exponential backoff.
	retryBackoffBase = 2.0

	// retryBackoffMax is the maximum backoff time.
	retryBackoffMax = 10 * time.Second

	// retryBackoffMin is the minimum backoff time.
	retryBackoffMin = 200 * time.Millisecond

	// tokenExpirationBuffer is the time before the token expires that we will
	// attempt to refresh it.
	tokenExpirationBuffer = 5 * time.Minute
)

// SalesforceClient is an interface for interacting with a limited set of
// Salesforce APIs. It exists to facilitate testing mocks.
type SalesforceClient interface {
	SendContact(email string) error
}

// oAuthToken holds the OAuth2 access token and its expiration.
type oAuthToken struct {
	sync.Mutex

	accessToken string
	expiresAt   time.Time
}

// SalesforceClientImpl handles authentication and sending contacts to Pardot.
type SalesforceClientImpl struct {
	businessUnit string
	clientId     string
	clientSecret string
	pardotURL    string
	tokenURL     string
	token        *oAuthToken
	clk          clock.Clock
}

var _ SalesforceClient = (*SalesforceClientImpl)(nil)

// NewSalesforceClientImpl creates a new SalesforceClientImpl.
func NewSalesforceClientImpl(clk clock.Clock, businessUnit, clientId, clientSecret, salesforceBaseURL, pardotBaseURL string) (*SalesforceClientImpl, error) {
	pardotURL, err := url.JoinPath(pardotBaseURL, contactsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to join contacts path: %w", err)
	}
	tokenURL, err := url.JoinPath(salesforceBaseURL, tokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to join token path: %w", err)
	}

	return &SalesforceClientImpl{
		businessUnit: businessUnit,
		clientId:     clientId,
		clientSecret: clientSecret,
		pardotURL:    pardotURL,
		tokenURL:     tokenURL,
		token:        &oAuthToken{},
		clk:          clk,
	}, nil
}

type oauthTokenResp struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// updateToken updates the OAuth token if necessary.
func (pc *SalesforceClientImpl) updateToken() error {
	pc.token.Lock()
	defer pc.token.Unlock()

	now := pc.clk.Now()
	if now.Before(pc.token.expiresAt.Add(-tokenExpirationBuffer)) && pc.token.accessToken != "" {
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

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(&io.LimitedReader{R: resp.Body, N: 100_000_000})
		if readErr != nil {
			return fmt.Errorf("token request failed with status %d; while reading body: %w", resp.StatusCode, readErr)
		}
		return fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, body)
	}

	var respJSON oauthTokenResp
	err = json.NewDecoder(resp.Body).Decode(&respJSON)
	if err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}
	pc.token.accessToken = respJSON.AccessToken
	pc.token.expiresAt = pc.clk.Now().Add(time.Duration(respJSON.ExpiresIn) * time.Second)

	return nil
}

// redactEmail replaces all occurrences of an email address in a response body
// with "[REDACTED]".
func redactEmail(body []byte, email string) string {
	return string(bytes.ReplaceAll(body, []byte(email), []byte("[REDACTED]")))
}

type prospect struct {
	// Email is the email address of the prospect.
	Email string `json:"email"`
}

type upsertPayload struct {
	// MatchEmail is the email address to match against existing prospects to
	// avoid adding duplicates.
	MatchEmail string `json:"matchEmail"`
	// Prospect is the prospect data to be upserted.
	Prospect prospect `json:"prospect"`
}

// SendContact submits an email to the Pardot Contacts endpoint, retrying up
// to 3 times with exponential backoff.
func (pc *SalesforceClientImpl) SendContact(email string) error {
	var err error
	for attempt := range maxAttempts {
		time.Sleep(core.RetryBackoff(attempt, retryBackoffMin, retryBackoffMax, retryBackoffBase))
		err = pc.updateToken()
		if err != nil {
			continue
		}
		break
	}
	if err != nil {
		return fmt.Errorf("failed to update token: %w", err)
	}

	payload, err := json.Marshal(upsertPayload{
		MatchEmail: email,
		Prospect:   prospect{Email: email},
	})
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	var finalErr error
	for attempt := range maxAttempts {
		time.Sleep(core.RetryBackoff(attempt, retryBackoffMin, retryBackoffMax, retryBackoffBase))

		req, err := http.NewRequest("POST", pc.pardotURL, bytes.NewReader(payload))
		if err != nil {
			finalErr = fmt.Errorf("failed to create new contact request: %w", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+pc.token.accessToken)
		req.Header.Set("Pardot-Business-Unit-Id", pc.businessUnit)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			finalErr = fmt.Errorf("create contact request failed: %w", err)
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			resp.Body.Close()
			return nil
		}

		body, err := io.ReadAll(&io.LimitedReader{R: resp.Body, N: 100_000_000})
		resp.Body.Close()

		if err != nil {
			finalErr = fmt.Errorf("create contact request returned status %d; while reading body: %w", resp.StatusCode, err)
			continue
		}
		finalErr = fmt.Errorf("create contact request returned status %d: %s", resp.StatusCode, redactEmail(body, email))
		continue
	}

	return finalErr
}
