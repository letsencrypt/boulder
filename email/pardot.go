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

	// contactsPath is the path to the Pardot v5 Prospect upsert-by-email
	// endpoint. This endpoint will create a new Prospect if one does not
	// already exist with the same email address.
	//
	// https://developer.salesforce.com/docs/marketing/pardot/guide/prospect-v5.html#prospect-upsert-by-email
	contactsPath = "/api/v5/objects/prospects/do/upsertLatestByEmail"

	// casesPath is the path to create a new Case object in Salesforce. This
	// path includes the API version (v64.0). Normally, Salesforce maintains
	// backward compatibility across versions. Update only if Salesforce retires
	// this API version (rare) or we want to make use of new Case fields
	// (unlikely).
	//
	// To check the current version for our org, see “Identify your current API
	// version”: https://help.salesforce.com/s/articleView?id=000386929&type=1
	casesPath = "/services/data/v64.0/sobjects/Case"

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
	SendCase(payload Case) error
}

// oAuthToken holds the OAuth2 access token and its expiration.
type oAuthToken struct {
	sync.Mutex

	accessToken string
	expiresAt   time.Time
}

// SalesforceClientImpl handles authentication and sending contacts to Pardot
// and creating Cases in Salesforce.
type SalesforceClientImpl struct {
	businessUnit string
	clientId     string
	clientSecret string
	pardotURL    string
	casesURL     string
	tokenURL     string
	token        *oAuthToken
	clk          clock.Clock
}

var _ SalesforceClient = &SalesforceClientImpl{}

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
	casesURL, err := url.JoinPath(salesforceBaseURL, casesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to join cases path: %w", err)
	}

	return &SalesforceClientImpl{
		businessUnit: businessUnit,
		clientId:     clientId,
		clientSecret: clientSecret,
		pardotURL:    pardotURL,
		casesURL:     casesURL,
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
		body, readErr := io.ReadAll(resp.Body)
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

		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			resp.Body.Close()
			return nil
		}

		body, err := io.ReadAll(resp.Body)
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

// Case represents the payload for populating a new Case object in Salesforce.
// For more information, see:
// https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_case.htm
// https://help.salesforce.com/s/articleView?id=platform.custom_field_types.htm&type=5
type Case struct {
	// Origin is required in all requests, a safe default is "Web".
	Origin string `json:"Origin"`

	// Subject is an optional standard field. Max length: 255 characters.
	Subject string `json:"Subject,omitempty"`

	// Description is an optional standard field. Max length: 32,768 characters.
	Description string `json:"Description,omitempty"`

	// ContactEmail is an optional standard field indicating the email address
	// of the requester. Max length: 80 characters.
	ContactEmail string `json:"ContactEmail,omitempty"`

	// Note: Fields below this point are optional custom fields.

	// Organization indicates the name of the requesting organization. Max
	// length: 255 characters.
	Organization string `json:"Organization__c,omitempty"`

	// AccountId indicates the requester's ACME Account ID. Max length: 255
	// characters.
	AccountId string `json:"Account_ID__c,omitempty"`

	// RateLimitName indicates which rate limit the override request is for. Max
	// length: 255 characters.
	RateLimitName string `json:"Rate_Limit_Name__c,omitempty"`

	// Tier indicates the requested tier of the rate limit override. Max length:
	// 255 characters.
	RateLimitTier string `json:"Rate_Limit_Tier__c,omitempty"`

	// UseCase indicates the intended to use case supplied by the requester. Max
	// length: 131,072 characters.
	UseCase string `json:"Use_Case__c,omitempty"`
}

// SendCase submits a new Case object to Salesforce. For more information, see:
// https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/dome_sobject_create.htm
func (pc *SalesforceClientImpl) SendCase(payload Case) error {
	var err error
	for attempt := range maxAttempts {
		time.Sleep(core.RetryBackoff(attempt, retryBackoffMin, retryBackoffMax, retryBackoffBase))
		err = pc.updateToken()
		if err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("failed to update token: %w", err)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal case payload: %w", err)
	}

	var finalErr error
	for attempt := range maxAttempts {
		time.Sleep(core.RetryBackoff(attempt, retryBackoffMin, retryBackoffMax, retryBackoffBase))

		req, err := http.NewRequest("POST", pc.casesURL, bytes.NewReader(body))
		if err != nil {
			finalErr = fmt.Errorf("failed to create new case request: %w", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+pc.token.accessToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			finalErr = fmt.Errorf("create case request failed: %w", err)
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			resp.Body.Close()
			return nil
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if err != nil {
			finalErr = fmt.Errorf("create case request returned status %d; while reading body: %w", resp.StatusCode, err)
			continue
		}

		finalErr = fmt.Errorf("create case request returned status %d: %s", resp.StatusCode, respBody)
		continue
	}

	return finalErr
}
