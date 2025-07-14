package zendesk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	// ticketsJSONPath is the path to Zendesk's tickets JSON endpoint.
	ticketsJSONPath = "api/v2/tickets.json"
	searchJSONPath  = "api/v2/search.json"
)

type CustomField struct {
	// name is the name of the custom field as it is displayed in Zendesk. It is
	// a required field.
	Name string `json:"-"`

	// ID is the ID of the custom field in Zendesk. It is a required field.
	ID int64 `json:"id"`
}

type Client struct {
	ticketsURL   string
	searchURL    string
	tokenEmail   string
	token        string
	customFields map[string]int64
}

// NewClient creates a new Zendesk client with the provided base URL, email, and
// token. The base URL should be the root of the Zendesk instance, e.g.,
// "https://yourdomain.zendesk.com/". The email should be the email address
// associated with the Zendesk account, and the token should be the API token
// generated in Zendesk by that account with that email address.
func NewClient(baseURL, tokenEmail, token string, fields []CustomField) (*Client, error) {
	ticketsURL, err := url.JoinPath(baseURL, ticketsJSONPath)
	if err != nil {
		return nil, fmt.Errorf("failed to join tickets path: %w", err)
	}
	searchURL, err := url.JoinPath(baseURL, searchJSONPath)
	if err != nil {
		return nil, fmt.Errorf("failed to join search path: %w", err)
	}
	customFields := make(map[string]int64)
	for _, field := range fields {
		if field.Name == "" || field.ID <= 0 {
			return nil, fmt.Errorf("invalid custom field: %v", field)
		}
		customFields[field.Name] = field.ID
	}
	return &Client{
		ticketsURL:   ticketsURL,
		searchURL:    searchURL,
		tokenEmail:   tokenEmail,
		token:        token,
		customFields: customFields,
	}, nil
}

type Requester struct {
	// Name is the name of the requester, it is a required field.
	Name string `json:"name"`

	// Email is the email address of the requester, it is a required field.
	Email string `json:"email"`
}

type Comment struct {
	// Body is the content of the comment, it is a required field.
	Body string `json:"body"`

	// Public indicates whether the comment is public or private.
	Public bool `json:"public,omitempty"`
}

type TicketField struct {
	CustomField
	// Value is the value of the custom field. It is a required field.
	Value string `json:"value"`
}

type Ticket struct {
	// Requester is the requester of the ticket, it is a required field.
	Requester Requester `json:"requester"`

	// Subject is the subject of the ticket, it is a required field.
	Subject string `json:"subject"`

	// Comment is the initial comment on the ticket. It is a required field. If
	// you want to add additional comments later, use the AddComment method.
	Comment Comment `json:"comment"`

	// TicketFields is a list of custom fields and their corresponding values.
	// It is optional, but if you want to set custom fields you must provide
	// them here.
	TicketFields []TicketField `json:"custom_fields,omitempty"`
}

// CreateTicket creates a new Zendesk ticket with the provided subject, comment,
// and custom fields. It returns the ID of the created ticket or an error if the
// request fails.
func (c *Client) CreateTicket(ticket Ticket) (int64, error) {
	payload := struct {
		Ticket Ticket `json:"ticket"`
	}{ticket}

	body, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}

	req, err := http.NewRequest("POST", c.ticketsURL, bytes.NewBuffer(body))
	if err != nil {
		return 0, err
	}
	req.SetBasicAuth(c.tokenEmail+"/token", c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return 0, fmt.Errorf("zendesk returned status %d: %s", resp.StatusCode, body)
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
	return result.Ticket.ID, nil
}

// FindTickets searches for tickets in Zendesk that match the provided custom
// fields. It returns a map of ticket IDs to their custom fields or an error if
// the request fails.
func (c *Client) FindTickets(matchFields []string) (map[int64][]TicketField, error) {
	var matchFieldsIDs []CustomField
	for _, field := range matchFields {
		id, ok := c.customFields[field]
		if !ok {
			return nil, fmt.Errorf("custom field %q not found", field)
		}
		matchFieldsIDs = append(matchFieldsIDs, CustomField{ID: id, Name: field})
	}

	var q strings.Builder
	q.WriteString("type:ticket")
	for _, match := range matchFieldsIDs {
		fmt.Fprintf(&q, ` custom_field_%d:%q`, match.ID, match.ID)
	}
	searchURL := c.searchURL + "?query=" + url.QueryEscape(q.String())

	out := make(map[int64][]TicketField)

	for searchURL != "" {
		req, _ := http.NewRequest("GET", searchURL, nil)
		req.SetBasicAuth(c.tokenEmail+"/token", c.token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}

		var response struct {
			Results []struct {
				ID           int64 `json:"id"`
				CustomFields []struct {
					ID    int64 `json:"id"`
					Value any   `json:"value"`
				} `json:"custom_fields"`
			} `json:"results"`
			Next string `json:"next_page"`
		}
		err = json.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			resp.Body.Close()
			return nil, err
		}
		resp.Body.Close()

		for _, t := range response.Results {
			var fields []TicketField
			for _, cf := range t.CustomFields {
				fields = append(fields, TicketField{
					CustomField: CustomField{
						ID: cf.ID,
					},
					Value: fmt.Sprintf("%v", cf.Value),
				})
			}
			out[t.ID] = fields
		}
		searchURL = response.Next
	}
	return out, nil
}

// AddComment posts an additional comment (public or internal) to an existing
// Zendesk ticket. It returns an error if the request fails.
func (c *Client) AddComment(ticketID int64, comment Comment, public bool) error {
	endpoint, err := url.JoinPath(c.ticketsURL, fmt.Sprintf("%d.json", ticketID))
	if err != nil {
		// This should never happen.
		return fmt.Errorf("failed to join ticket path: %w", err)
	}

	payload := struct {
		Ticket struct {
			Comment Comment `json:"comment"`
		} `json:"ticket"`
	}{}
	payload.Ticket.Comment = comment

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", endpoint, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.tokenEmail+"/token", c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("zendesk status %d: %s", resp.StatusCode, respBody)
	}
	return nil
}
