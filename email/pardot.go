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

	// casesPath is the path to create a new Case object in Salesforce.
	casesPath = "/services/data/v65.0/sobjects/Case"

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
	businessUnit    string
	clientId        string
	clientSecret    string
	endpointURL     string
	caseEndpointURL string
	tokenURL        string
	token           *oAuthToken
	clk             clock.Clock
}

var _ SalesforceClient = &SalesforceClientImpl{}

// NewSalesforceClientImpl creates a new SalesforceClientImpl.
func NewSalesforceClientImpl(clk clock.Clock, businessUnit, clientId, clientSecret, salesforceBaseURL, pardotBaseURL string) (*SalesforceClientImpl, error) {
	endpointURL, err := url.JoinPath(pardotBaseURL, contactsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to join contacts path: %w", err)
	}
	tokenURL, err := url.JoinPath(salesforceBaseURL, tokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to join token path: %w", err)
	}
	caseEndpointURL, err := url.JoinPath(salesforceBaseURL, casesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to join cases path: %w", err)
	}

	return &SalesforceClientImpl{
		businessUnit:    businessUnit,
		clientId:        clientId,
		clientSecret:    clientSecret,
		endpointURL:     endpointURL,
		caseEndpointURL: caseEndpointURL,
		tokenURL:        tokenURL,
		token:           &oAuthToken{},
		clk:             clk,
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

		req, err := http.NewRequest("POST", pc.endpointURL, bytes.NewReader(payload))
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

// Case respresents the payload for populating a new Case object in Salesforce.
// For more information, see:
// https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_case.htm
type Case struct {
	// Subject is optional. Max length: 255 characters.
	Subject string `json:"Subject,omitempty"`

	// Description is optional. Max length: 32,000 characters.
	Description string `json:"Description,omitempty"`

	// Origin is required in all requests, a safe default is "Web".
	Origin string `json:"Origin"`

	// ContactEmail is the email address of the requester. This must be a valid
	// email address.
	ContactEmail string `json:"Contact_Email,omitempty"`

	// Note: Fields below this point are SalesForce Cases custom fields. These
	// are all optional.

	// AccountId is the custom field for indicateing the requester's ACME
	// Account ID. Max length: 255 characters.
	AccountId string `json:"Account_ID__c,omitempty"`

	// Organization is the custom field for indicating the name of the
	// organization the requester is associated with. Max length: 255
	// characters.
	Organization string `json:"Organization__c,omitempty"`

	// RateLimitName is the custom field for indicating which rate limit the
	// override request is for. Max length: 255 characters.
	RateLimitName string `json:"Rate_Limit_Name__c,omitempty"`

	// Tier is the custom field for indicating which rate limit tier the
	// requester is applying for. Max length: 255 characters.
	RateLimitTier string `json:"Rate_Limit_Tier__c,omitempty"`

	// UseCase is the custom field for indicating what the requester intends to
	// use the rate limit override for. Max length: 32,768 characters.
	UseCase string `json:"Use_Case__c,omitempty"`

	// FinancialSupport is the custom field for indicating whether the user is
	// interested in financial support. Max length: 255 characters.
	//
	// TODO: This should be phased out once Advancement gives us the go ahead.
	// For now this should always be set to "Yes".
	FinancialSupport string `json:"Interested_in_Financial_Support__c,omitempty"`
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

		req, err := http.NewRequest("POST", pc.caseEndpointURL, bytes.NewReader(body))
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

		respBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			finalErr = fmt.Errorf("failed to read case response: %w", readErr)
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		finalErr = fmt.Errorf("create case request returned status %d: %s", resp.StatusCode, respBody)
	}

	return finalErr
}
