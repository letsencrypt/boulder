package zendesk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	apiPath         = "api/v2/"
	ticketsJSONPath = apiPath + "tickets.json"
	searchJSONPath  = apiPath + "search.json"
)

type Client struct {
	httpClient *http.Client
	tokenEmail string
	token      string

	ticketsURL string
	searchURL  string
	commentURL string

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
	commentURL, err := url.JoinPath(baseURL, apiPath, "tickets")
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
		commentURL:    commentURL,
		nameToFieldID: nameToFieldID,
		fieldIDToName: fieldIDToName,
	}, nil
}

type requester struct {
	// Name is the name of the requester, it is a required field.
	Name string `json:"name"`

	// Email is the email address of the requester, it is a required field.
	Email string `json:"email"`
}

type comment struct {
	// Body is the content of the comment, it is a required field.
	Body string `json:"body"`

	// Public indicates whether the comment is public or private.
	Public bool `json:"public"`
}

type customField struct {
	// ID is the ID of the custom field in Zendesk. It is a required field.
	ID int64 `json:"id"`

	// Value is the value of the custom field.
	Value string `json:"value"`
}

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
	CustomFields []customField `json:"custom_fields,omitempty"`
}

func (c *Client) newJSONRequest(method, reqURL string, body []byte) (*http.Request, error) {
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, reqURL, reader)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.tokenEmail+"/token", c.token)
	req.Header.Set("Accept", "application/json")
	if reader != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
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

	body, err := json.Marshal(struct {
		Ticket ticket `json:"ticket"`
	}{Ticket: ticketContents})
	if err != nil {
		return 0, err
	}

	req, err := c.newJSONRequest(http.MethodPost, c.ticketsURL, body)
	if err != nil {
		return 0, fmt.Errorf("failed to create zendesk request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return 0, fmt.Errorf("zendesk status %d: failed to read response body: %w", resp.StatusCode, err)
		}
		return 0, fmt.Errorf("zendesk returned status %d: %s", resp.StatusCode, respBody)
	}

	var result struct {
		Ticket struct {
			ID int64 `json:"id"`
		} `json:"ticket"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return 0, err
	}
	if result.Ticket.ID == 0 {
		return 0, fmt.Errorf("zendesk did not return a valid ticket ID")
	}
	return result.Ticket.ID, nil
}

// FindTickets returns all tickets whose custom fields match the supplied
// matchFields. The matchFields map should contain the display names of the
// custom fields as keys and the desired values as values. The method returns a
// map where the keys are ticket IDs and the values are maps of custom field
// names to their values. If no matchFields are supplied, an error is returned.
// If a custom field name is unknown, an error is returned.
func (c *Client) FindTickets(matchFields map[string]string) (map[int64]map[string]string, error) {
	if len(matchFields) == 0 {
		return nil, fmt.Errorf("no match fields supplied")
	}

	var query strings.Builder
	query.WriteString("type:ticket")

	for name, want := range matchFields {
		id, ok := c.nameToFieldID[name]
		if !ok {
			return nil, fmt.Errorf("unknown custom field %q", name)
		}
		val := want
		if strings.ContainsRune(val, ' ') {
			val = `"` + val + `"`
		}
		fmt.Fprintf(&query, " custom_field_%d:%s", id, val)
	}

	searchURL := c.searchURL + "?query=" + url.QueryEscape(query.String())
	out := make(map[int64]map[string]string)

	for searchURL != "" {
		req, err := c.newJSONRequest(http.MethodGet, searchURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create zendesk request: %w", err)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= 300 {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("zendesk status %d: failed to read response body: %w", resp.StatusCode, err)
			}
			resp.Body.Close()
			return nil, fmt.Errorf("zendesk status %d: %s", resp.StatusCode, body)
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
		err = json.NewDecoder(resp.Body).Decode(&results)
		if err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode zendesk response: %w", err)
		}
		resp.Body.Close()

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
		if results.Next != nil {
			searchURL = *results.Next
			continue
		}
		searchURL = ""
	}
	return out, nil
}

// AddComment posts the comment body to the specified ticket. The comment is
// added as a public or private comment based on the provided boolean value. An
// error is returned if the request fails.
func (c *Client) AddComment(ticketID int64, commentBody string, public bool) error {
	endpoint, err := url.JoinPath(c.commentURL, fmt.Sprintf("%d.json", ticketID))
	if err != nil {
		return fmt.Errorf("failed to join ticket path: %w", err)
	}

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

	req, err := c.newJSONRequest(http.MethodPut, endpoint, body)
	if err != nil {
		return fmt.Errorf("failed to create zendesk request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("zendesk request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("zendesk status %d: failed to read response body: %w", resp.StatusCode, err)
		}
		return fmt.Errorf("zendesk status %d: %s", resp.StatusCode, respBody)
	}
	return nil
}
