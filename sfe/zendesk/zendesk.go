package zendesk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	apiPath         = "api/v2/"
	ticketsJSONPath = apiPath + "tickets.json"
	searchJSONPath  = apiPath + "search.json"
)

// Note: This is client is NOT compatible with custom ticket statuses, it only
// supports the default Zendesk ticket statuses. For more information, see:
// https://developer.zendesk.com/api-reference/ticketing/tickets/custom_ticket_statuses
// https://developer.zendesk.com/api-reference/ticketing/tickets/tickets/#custom-ticket-statuses
var validStatuses = []string{"new", "open", "pending", "hold", "solved"}

// Client is a Zendesk client that allows you to create tickets, search for
// tickets, and add comments to tickets via the Zendesk REST API. It uses basic
// authentication with an API token.
type Client struct {
	httpClient *http.Client
	tokenEmail string
	token      string

	ticketsURL string
	searchURL  string
	updateURL  string

	nameToFieldID map[string]int64
	fieldIDToName map[int64]string
}

// NewClient creates a new Zendesk client with the provided baseURL, token, and
// tokenEmail, and a name to field id mapping. baseURL is your Zendesk URL with
// the scheme included, e.g. "https://yourdomain.zendesk.com". Token is an API
// token generated from the Zendesk Admin UI. The tokenEmail is the email
// address of the Zendesk user that created the token. The nameToFieldID must
// contain the display names and corresponding IDs of the custom fields you want
// to use in your tickets, this allows you to refer to custom fields by string
// names instead of numeric IDs when working with tickets.
func NewClient(baseURL, tokenEmail, token string, nameToFieldID map[string]int64) (*Client, error) {
	ticketsURL, err := url.JoinPath(baseURL, ticketsJSONPath)
	if err != nil {
		return nil, fmt.Errorf("failed to join tickets path: %w", err)
	}
	searchURL, err := url.JoinPath(baseURL, searchJSONPath)
	if err != nil {
		return nil, fmt.Errorf("failed to join search path: %w", err)
	}
	updateURL, err := url.JoinPath(baseURL, apiPath, "tickets")
	if err != nil {
		return nil, fmt.Errorf("failed to join comment path: %w", err)
	}
	fieldIDToName := make(map[int64]string, len(nameToFieldID))
	for name, id := range nameToFieldID {
		_, ok := fieldIDToName[id]
		if ok {
			return nil, fmt.Errorf("duplicate field ID %d for field %q", id, name)
		}
		fieldIDToName[id] = name
	}
	return &Client{
		httpClient:    &http.Client{Timeout: 15 * time.Second},
		tokenEmail:    tokenEmail,
		token:         token,
		ticketsURL:    ticketsURL,
		searchURL:     searchURL,
		updateURL:     updateURL,
		nameToFieldID: nameToFieldID,
		fieldIDToName: fieldIDToName,
	}, nil
}

// requester represents the requester of a Zendesk ticket. It contains the
// requester's name and email address. Both fields are required when creating a
// new ticket.
//
// For more information, see the Zendesk API documentation:
// https://developer.zendesk.com/documentation/ticketing/managing-tickets/creating-and-updating-tickets/#creating-a-ticket-with-a-new-requester
type requester struct {
	// Name is the name of the requester, it is a required field.
	Name string `json:"name"`

	// Email is the email address of the requester, it is a required field.
	Email string `json:"email"`
}

// comment represents a comment on a Zendesk ticket. It contains the body of the
// comment and whether the comment is public or private. The body is a required
// field when creating a new ticket or adding a comment to an existing ticket.
//
// For more information, see the Zendesk API documentation:
// https://developer.zendesk.com/api-reference/ticketing/tickets/ticket_comments/
type comment struct {
	// Body is the content of the comment, it is a required field.
	Body string `json:"body"`

	// Public indicates whether the comment is public or private.
	Public bool `json:"public"`
}

// customField represents a custom field in a Zendesk ticket. It contains the ID
// of the custom field and its value.
//
// For more information, see the Zendesk API documentation:
// https://developer.zendesk.com/documentation/ticketing/managing-tickets/creating-and-updating-tickets/#setting-custom-field-values
type customField struct {
	// ID is the ID of the custom field in Zendesk. It is a required field.
	ID int64 `json:"id"`

	// Value is the value of the custom field.
	Value string `json:"value"`
}

// ticket represents a Zendesk ticket. It contains the requester, subject,
// initial comment, and optional custom fields. The requester and subject are
// required fields when creating a new ticket.
//
// For more information, see the Zendesk API documentation:
// https://developer.zendesk.com/api-reference/ticketing/tickets/ticket_fields/#json-format
// https://developer.zendesk.com/documentation/ticketing/managing-tickets/creating-and-updating-tickets/#creating-a-ticket-with-a-new-requester
type ticket struct {
	// Requester is the requester of the ticket, it is a required field.
	Requester requester `json:"requester"`

	// Subject is the subject of the ticket, it is a required field.
	Subject string `json:"subject"`

	// Comment is the initial comment on the ticket. It is a required field. If
	// you want to add additional comments later, use the AddComment method.
	Comment comment `json:"comment"`

	// CustomFields is a list of custom fields and their corresponding values.
	// It is optional, but if you want to set custom fields you must provide
	// them here.
	//
	// For more information, see the Zendesk API documentation:
	// https://developer.zendesk.com/documentation/ticketing/managing-tickets/creating-and-updating-tickets/#setting-custom-field-values
	CustomFields []customField `json:"custom_fields,omitempty"`
}

// doJSONRequest constructs and sends an HTTP request to the Zendesk API using
// the specified method and URL. It sets the appropriate headers for JSON
// content and basic authentication using the tokenEmail and token. The response
// body or an error is returned.
//
// https://developer.zendesk.com/api-reference/introduction/requests/#request-format
// https://developer.zendesk.com/api-reference/introduction/security-and-auth/#api-token
func (c *Client) doJSONRequest(method, reqURL string, body []byte) ([]byte, error) {
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, reqURL, reader)
	if err != nil {
		return nil, fmt.Errorf("failed to create zendesk request: %w", err)
	}
	req.SetBasicAuth(c.tokenEmail+"/token", c.token)
	req.Header.Set("Accept", "application/json")
	if reader != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("zendesk request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read zendesk response body: %w", err)
	}

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("zendesk returned status %d: %s", resp.StatusCode, respBody)
	}
	return respBody, nil
}

// CreateTicket creates a new Zendesk ticket with the provided requester email,
// subject, initial comment body, and custom fields. It returns the ID of the
// created ticket or an error if the request fails. The custom fields should be
// provided as a map where the keys are the display names of the custom fields
// and the values are the desired values for those fields. The method will
// convert the display names to their corresponding field IDs using the
// nameToFieldID map provided when creating the Client. If a custom field name
// is unknown, an error will be returned.
func (c *Client) CreateTicket(requesterEmail, subject, commentBody string, fields map[string]string) (int64, error) {
	ticketContents := ticket{
		Requester: requester{
			// Here we use the requesterEmail as both the email and name. This
			// is done intentionally to keep PII to a minimum.
			Email: requesterEmail,
			Name:  requesterEmail,
		},
		Subject: subject,
		Comment: comment{
			Body:   commentBody,
			Public: true,
		},
	}
	for name, value := range fields {
		id, ok := c.nameToFieldID[name]
		if !ok {
			return 0, fmt.Errorf("unknown custom field %q", name)
		}
		ticketContents.CustomFields = append(ticketContents.CustomFields, customField{
			ID:    id,
			Value: value,
		})
	}

	// For more information on the ticket creation format, see:
	// https://developer.zendesk.com/api-reference/introduction/requests/#request-format
	body, err := json.Marshal(struct {
		Ticket ticket `json:"ticket"`
	}{Ticket: ticketContents})
	if err != nil {
		return 0, fmt.Errorf("failed to marshal zendesk ticket: %w", err)
	}

	body, err = c.doJSONRequest(http.MethodPost, c.ticketsURL, body)
	if err != nil {
		return 0, fmt.Errorf("failed to create zendesk ticket: %w", err)
	}

	// For more information on the response format, see:
	// https://developer.zendesk.com/api-reference/introduction/requests/#response-format
	var result struct {
		Ticket struct {
			ID int64 `json:"id"`
		} `json:"ticket"`
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return 0, fmt.Errorf("failed to unmarshal zendesk response: %w", err)
	}
	if result.Ticket.ID == 0 {
		return 0, fmt.Errorf("zendesk did not return a valid ticket ID")
	}
	return result.Ticket.ID, nil
}

// FindTickets returns all tickets whose custom fields match the required
// matchFields and optional status. The matchFields map should contain the
// display names of the custom fields as keys and the desired values as values.
// The method returns a map where the keys are ticket IDs and the values are
// maps of custom field names to their values. If no matchFields are supplied,
// an error is returned. If a custom field name is unknown, an error is returned.
func (c *Client) FindTickets(matchFields map[string]string, status string) (map[int64]map[string]string, error) {
	if len(matchFields) == 0 {
		return nil, fmt.Errorf("no match fields supplied")
	}

	// Below we're building a very basic search query using the Zendesk query
	// syntax, for more information see:
	// https://developer.zendesk.com/documentation/api-basics/working-with-data/searching-with-the-zendesk-api/#basic-query-syntax

	query := []string{"type:ticket"}

	if status != "" {
		if !slices.Contains(validStatuses, status) {
			return nil, fmt.Errorf("invalid status %q, must be one of %s", status, validStatuses)
		}
		query = append(query, fmt.Sprintf("status:%s", status))
	}

	for name, want := range matchFields {
		id, ok := c.nameToFieldID[name]
		if !ok {
			return nil, fmt.Errorf("unknown custom field %q", name)
		}

		// According to the Zendesk API documentation, if a value contains
		// spaces, it must be quoted. If the value does not contain spaces, it
		// must not be quoted. We have observed that the Zendesk API does reject
		// queries with improper quoting.
		val := want
		if strings.Contains(val, " ") {
			val = fmt.Sprintf("%q", val)
		}
		query = append(query, fmt.Sprintf("custom_field_%d:%s", id, val))
	}

	searchURL := c.searchURL + "?query=" + url.QueryEscape(strings.Join(query, " "))
	out := make(map[int64]map[string]string)

	for searchURL != "" {
		body, err := c.doJSONRequest(http.MethodGet, searchURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to search zendesk tickets: %w", err)
		}

		var results struct {
			Results []struct {
				ID           int64 `json:"id"`
				CustomFields []struct {
					ID    int64 `json:"id"`
					Value any   `json:"value"`
				} `json:"custom_fields"`
			} `json:"results"`
			Next *string `json:"next_page"`
		}
		err = json.Unmarshal(body, &results)
		if err != nil {
			return nil, fmt.Errorf("failed to decode zendesk response: %w", err)
		}

		for _, result := range results.Results {
			fieldMap := make(map[string]string)
			for _, cf := range result.CustomFields {
				name, ok := c.fieldIDToName[cf.ID]
				if ok {
					fieldMap[name] = fmt.Sprint(cf.Value)
				}
			}
			out[result.ID] = fieldMap
		}
		if results.Next == nil {
			break
		}
		searchURL = *results.Next
	}
	return out, nil
}

// AddComment posts the comment body to the specified ticket. The comment is
// added as a public or private comment based on the provided boolean value. An
// error is returned if the request fails.
func (c *Client) AddComment(ticketID int64, commentBody string, public bool) error {
	endpoint, err := url.JoinPath(c.updateURL, fmt.Sprintf("%d.json", ticketID))
	if err != nil {
		return fmt.Errorf("failed to join ticket path: %w", err)
	}

	// For more information on the comment format, see:
	// https://developer.zendesk.com/api-reference/ticketing/tickets/ticket_comments/
	payload := struct {
		Ticket struct {
			Comment comment `json:"comment"`
		} `json:"ticket"`
	}{}
	payload.Ticket.Comment = comment{Body: commentBody, Public: public}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal zendesk comment: %w", err)
	}

	_, err = c.doJSONRequest(http.MethodPut, endpoint, body)
	if err != nil {
		return fmt.Errorf("failed to add comment to zendesk ticket %d: %w", ticketID, err)
	}
	return nil
}

// UpdateTicketStatus updates the status of the specified ticket to the provided
// status and adds a comment with the provided body. The comment is added as a
// public or private comment based on the provided boolean value. An error is
// returned if the request fails or if the provided status is invalid.
func (c *Client) UpdateTicketStatus(ticketID int64, status string, commentBody string, public bool) error {
	if !slices.Contains(validStatuses, status) {
		return fmt.Errorf("invalid status %q, must be one of %s", status, validStatuses)
	}

	endpoint, err := url.JoinPath(c.updateURL, fmt.Sprintf("%d.json", ticketID))
	if err != nil {
		return fmt.Errorf("failed to join ticket path: %w", err)
	}

	// For more information on the status update format, see:
	// https://developer.zendesk.com/api-reference/ticketing/tickets/tickets/#update-ticket
	payload := struct {
		Ticket struct {
			Comment comment `json:"comment"`
			Status  string  `json:"status"`
		} `json:"ticket"`
	}{}
	payload.Ticket.Comment = comment{Body: commentBody, Public: public}
	payload.Ticket.Status = status

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal zendesk status update: %w", err)
	}

	_, err = c.doJSONRequest(http.MethodPut, endpoint, body)
	if err != nil {
		return fmt.Errorf("failed to update zendesk ticket %d: %w", ticketID, err)
	}
	return nil
}
