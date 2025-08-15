package zendeskfake

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

const (
	apiTokenEmail = "tester@example.com"
	apiToken      = "someToken"
)

func basicAuthHeader(email, token string) string {
	raw := email + "/token:" + token
	enc := base64.StdEncoding.EncodeToString([]byte(raw))
	return "Basic " + enc
}

func startTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()

	srv := NewServer(apiTokenEmail, apiToken, nil)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

func startTestServerWithStore(t *testing.T, store *Store) (*Server, *httptest.Server) {
	t.Helper()

	srv := NewServer(apiTokenEmail, apiToken, store)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

func doJSON(t *testing.T, method, urlStr, authHeader string, body []byte, setContentType bool) (*http.Response, []byte) {
	t.Helper()

	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, urlStr, reader)
	if err != nil {
		t.Errorf("creating request %s %s failed: %s", method, urlStr, err)
		return nil, nil
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	req.Header.Set("Accept", "application/json")
	if setContentType {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("performing %s %s failed: %s", method, urlStr, err)
		return nil, nil
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("reading response body for %s %s failed: %s", method, urlStr, err)
		err = resp.Body.Close()
		if err != nil {
			t.Errorf("closing response body for %s %s failed: %s", method, urlStr, err)
		}
		return resp, nil
	}
	err = resp.Body.Close()
	if err != nil {
		t.Errorf("closing response body for %s %s failed: %s", method, urlStr, err)
	}
	return resp, respBody
}

func postTicket(t *testing.T, baseURL string, body []byte) (*http.Response, []byte) {
	t.Helper()

	return doJSON(t, http.MethodPost, baseURL+TicketsJSONPath, basicAuthHeader(apiTokenEmail, apiToken), body, true)
}

func putComment(t *testing.T, baseURL string, id int64, body []byte) (*http.Response, []byte) {
	t.Helper()

	endpoint := fmt.Sprintf("%s%s%d.json", baseURL, TicketsPath, id)
	return doJSON(t, http.MethodPut, endpoint, basicAuthHeader(apiTokenEmail, apiToken), body, true)
}

func getSearch(t *testing.T, baseURL, query string) (*http.Response, []byte) {
	t.Helper()

	v := url.Values{}
	v.Set("query", query)
	urlStr := baseURL + SearchJSONPath + "?" + v.Encode()
	return doJSON(t, http.MethodGet, urlStr, basicAuthHeader(apiTokenEmail, apiToken), nil, false)
}

func createTicketAndReturnID(t *testing.T, baseURL string) int64 {
	t.Helper()

	payload := []byte(`{
		"ticket": {
			"requester": {"name":"R","email":"r@example.com"},
			"subject": "S",
			"comment": {"body":"B","public":true},
			"custom_fields": []
		}
	}`)
	resp, body := postTicket(t, baseURL, payload)
	if resp == nil {
		t.Errorf("unexpected nil response while creating ticket")
		return 0
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("create ticket: expected HTTP %d, got HTTP %d body=%s", http.StatusCreated, resp.StatusCode, string(body))
	}

	var out struct {
		Ticket struct {
			ID int64 `json:"id"`
		} `json:"ticket"`
	}
	err := json.Unmarshal(body, &out)
	if err != nil {
		t.Errorf("unmarshalling create ticket response failed: %s", err)
		return 0
	}
	return out.Ticket.ID
}

func TestAuthRequired(t *testing.T) {
	t.Parallel()

	_, ts := startTestServer(t)

	resp, _ := doJSON(t, http.MethodGet, ts.URL+SearchJSONPath+"?query=type:ticket", "", nil, false)
	if resp == nil {
		t.Errorf("unexpected nil response for unauthorized request")
		return
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthorized request: expected HTTP %d, got HTTP %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestAuthWrongCredentialsAllEndpoints(t *testing.T) {
	t.Parallel()

	_, ts := startTestServer(t)

	validCreate := []byte(`{"ticket":{"requester":{"name":"n","email":"e@example.com"},"subject":"s","comment":{"body":"b","public":true},"custom_fields":[]}}`)
	validUpdate := []byte(`{"ticket":{"comment":{"body":"x","public":false}}}`)

	id := createTicketAndReturnID(t, ts.URL)

	type ep struct {
		name   string
		method string
		url    string
		body   []byte
	}
	endpoints := []ep{
		{"POST /tickets.json", http.MethodPost, ts.URL + TicketsJSONPath, validCreate},
		{"GET  /search.json", http.MethodGet, ts.URL + SearchJSONPath + "?query=type:ticket", nil},
		{"PUT  /tickets/{id}.json", http.MethodPut, ts.URL + TicketsPath + strconv.FormatInt(id, 10) + ".json", validUpdate},
	}

	for _, e := range endpoints {
		t.Run(e.name+"/wrong-credentials", func(t *testing.T) {
			resp, _ := doJSON(t, e.method, e.url, basicAuthHeader("wrong@example.com", "wrong"), e.body, true)
			if resp == nil {
				t.Errorf("%s wrong-credentials: unexpected nil response", e.name)
				return
			}
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s wrong-credentials: expected HTTP %d, got HTTP %d", e.name, http.StatusUnauthorized, resp.StatusCode)
			}
		})
		t.Run(e.name+"/malformed-header", func(t *testing.T) {
			resp, _ := doJSON(t, e.method, e.url, "Basic malformed-header", e.body, true)
			if resp == nil {
				t.Errorf("%s malformed-header: unexpected nil response", e.name)
				return
			}
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s malformed-header: expected HTTP %d, got HTTP %d", e.name, http.StatusUnauthorized, resp.StatusCode)
			}
		})
	}
}

func TestCreateTicketSuccessAndStored(t *testing.T) {
	t.Parallel()

	srv, ts := startTestServer(t)

	payload := []byte(`{
		"ticket": {
			"requester": {"name":"Alice","email":"alice@example.com"},
			"subject": "Subject A",
			"comment": {"body":"Hello world","public":true},
			"custom_fields": [
				{"id": 111, "value":"pending"},
				{"id": 222, "value":"Acme"}
			]
		}
	}`)

	resp, body := postTicket(t, ts.URL, payload)
	if resp == nil {
		t.Errorf("create ticket: unexpected nil response")
		return
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("create ticket: expected HTTP %d, got HTTP %d body=%s", http.StatusCreated, resp.StatusCode, string(body))
	}

	var res struct {
		Ticket struct {
			ID int64 `json:"id"`
		} `json:"ticket"`
	}
	err := json.Unmarshal(body, &res)
	if err != nil {
		t.Errorf("unmarshal create response failed: %s", err)
		return
	}
	if res.Ticket.ID == 0 {
		t.Errorf("create ticket: expected non-zero id")
		return
	}

	got, ok := srv.GetTicket(res.Ticket.ID)
	if !ok {
		t.Errorf("ticket id %d not found in store", res.Ticket.ID)
		return
	}
	if got.Subject != "Subject A" {
		t.Errorf("ticket subject mismatch: got %q, want %q", got.Subject, "Subject A")
	}
	if len(got.Comments) != 1 || got.Comments[0].Body != "Hello world" || !got.Comments[0].Public {
		t.Errorf("ticket comment stored incorrectly: %#v (want one public 'Hello world' comment)", got.Comments)
	}
	if got.CustomFields[111] != "pending" || got.CustomFields[222] != "Acme" {
		t.Errorf("ticket custom fields stored incorrectly: %#v (want 111=%q 222=%q)", got.CustomFields, "pending", "Acme")
	}
}

func TestCreateTicketUnhappyPaths(t *testing.T) {
	t.Parallel()

	_, ts := startTestServer(t)

	cases := []struct {
		name       string
		body       []byte
		wantStatus int
	}{
		{
			name:       "bad json",
			body:       []byte(`{"ticket": { "requester": {"name":"A","email":"a@example.com"},`),
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "missing subject",
			body: []byte(`{
				"ticket": {
					"requester": {"name":"Bob","email":"bob@example.com"},
					"comment": {"body":"Hi","public":true}
				}
			}`),
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name: "missing email",
			body: []byte(`{
				"ticket": {
					"requester": {"name":"NoEmail"},
					"subject": "S",
					"comment": {"body":"B","public":true}
				}
			}`),
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name: "missing comment body",
			body: []byte(`{
				"ticket": {
					"requester": {"name":"N","email":"n@example.com"},
					"subject": "S",
					"comment": {"public":true}
				}
			}`),
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name:       "empty body",
			body:       nil,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp, body := postTicket(t, ts.URL, tc.body)
			if resp == nil {
				t.Errorf("create ticket (%s): unexpected nil response", tc.name)
				return
			}
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("create ticket (%s): expected HTTP %d, got HTTP %d body=%s", tc.name, tc.wantStatus, resp.StatusCode, string(body))
			}
		})
	}
}

func TestUpdateTicketAddsComment(t *testing.T) {
	t.Parallel()

	srv, ts := startTestServer(t)

	id := createTicketAndReturnID(t, ts.URL)

	updatePayload := []byte(`{
		"ticket": {
			"comment": {"body":"Follow-up","public":false}
		}
	}`)
	resp, body := putComment(t, ts.URL, id, updatePayload)
	if resp == nil {
		t.Errorf("update ticket: unexpected nil response")
		return
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("update ticket: expected HTTP %d, got HTTP %d body=%s", http.StatusOK, resp.StatusCode, string(body))
	}

	got, ok := srv.GetTicket(id)
	if !ok {
		t.Errorf("update ticket: id %d not found in store", id)
		return
	}
	if len(got.Comments) != 2 {
		t.Errorf("update ticket: expected 2 comments, got %d", len(got.Comments))
	} else {
		if got.Comments[1].Body != "Follow-up" || got.Comments[1].Public {
			t.Errorf("update ticket: second comment incorrect: %#v (want body=%q, public=false)", got.Comments[1], "Follow-up")
		}
	}
}

func TestUpdateTicketUnhappyPaths(t *testing.T) {
	t.Parallel()

	_, ts := startTestServer(t)

	validID := createTicketAndReturnID(t, ts.URL)

	type tc struct {
		name       string
		method     string
		path       string
		body       []byte
		wantStatus int
	}
	tests := []tc{
		{
			name:       "bad id path (non-numeric)",
			method:     http.MethodPut,
			path:       TicketsPath + "abc.json",
			body:       []byte(`{"ticket":{"comment":{"body":"x","public":false}}}`),
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "missing id segment",
			method:     http.MethodPut,
			path:       TicketsPath + ".json",
			body:       []byte(`{"ticket":{"comment":{"body":"x","public":true}}}`),
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "unknown id",
			method:     http.MethodPut,
			path:       TicketsPath + "999999.json",
			body:       []byte(`{"ticket":{"comment":{"body":"x","public":true}}}`),
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "bad json",
			method:     http.MethodPut,
			path:       TicketsPath + strconv.FormatInt(validID, 10) + ".json",
			body:       []byte(`{"ticket": {"comment":`),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing comment body",
			method:     http.MethodPut,
			path:       TicketsPath + strconv.FormatInt(validID, 10) + ".json",
			body:       []byte(`{"ticket":{"comment":{"public":true}}}`),
			wantStatus: http.StatusUnprocessableEntity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			resp, body := doJSON(t, tt.method, ts.URL+tt.path, basicAuthHeader(apiTokenEmail, apiToken), tt.body, true)
			if resp == nil {
				t.Errorf("%s: unexpected nil response", tt.name)
				return
			}
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("%s: expected HTTP %d, got HTTP %d body=%s", tt.name, tt.wantStatus, resp.StatusCode, string(body))
			}

			if tt.wantStatus == http.StatusNotFound && (strings.Contains(tt.name, "bad id path") || strings.Contains(tt.name, "missing id")) {
				ct := resp.Header.Get("Content-Type")
				if !strings.HasPrefix(ct, "application/json") {
					t.Errorf("%s: expected Content-Type application/json, got %q", tt.name, ct)
				}
				var payload struct {
					Error       string `json:"error"`
					Description string `json:"description"`
				}
				err := json.Unmarshal(body, &payload)
				if err != nil {
					t.Errorf("%s: unmarshal 404 payload failed: %s (body=%q)", tt.name, err, string(body))
				}
				if payload.Error != "RecordNotFound" || payload.Description != "Not found" {
					t.Errorf("%s: unexpected 404 payload: %#v", tt.name, payload)
				}
			}
		})
	}
}

func TestSearchNoTypeTicketReturnsEmpty(t *testing.T) {
	t.Parallel()

	_, ts := startTestServer(t)

	resp, body := getSearch(t, ts.URL, "custom_field_1:foo")
	if resp == nil {
		t.Errorf("search without type: unexpected nil response")
		return
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("search without type: expected HTTP %d, got HTTP %d", http.StatusOK, resp.StatusCode)
	}

	var out struct {
		Results []any `json:"results"`
		Next    any   `json:"next_page"`
	}
	err := json.Unmarshal(body, &out)
	if err != nil {
		t.Errorf("search without type: unmarshal response failed: %s", err)
	}
	if len(out.Results) != 0 {
		t.Errorf("search without type: expected 0 results, got %d", len(out.Results))
	}
}

func TestSearchByCustomFieldsQuotedAndUnquoted(t *testing.T) {
	t.Parallel()

	_, ts := startTestServer(t)

	payload1 := []byte(`{
		"ticket": {
			"requester": {"name":"A","email":"a@example.com"},
			"subject": "S1",
			"comment": {"body":"B1","public":true},
			"custom_fields": [
				{"id": 111, "value": "pending"},
				{"id": 222, "value": "Acme"}
			]
		}
	}`)
	resp, body := postTicket(t, ts.URL, payload1)
	if resp == nil {
		t.Errorf("create ticket 1: unexpected nil response")
		return
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("create ticket 1: expected HTTP %d, got HTTP %d body=%s", http.StatusCreated, resp.StatusCode, string(body))
	}

	payload2 := []byte(`{
		"ticket": {
			"requester": {"name":"B","email":"b@example.com"},
			"subject": "S2",
			"comment": {"body":"B2","public":true},
			"custom_fields": [
				{"id": 111, "value": "pending review"},
				{"id": 222, "value": "Acme"}
			]
		}
	}`)
	resp, body = postTicket(t, ts.URL, payload2)
	if resp == nil {
		t.Errorf("create ticket 2: unexpected nil response")
		return
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("create ticket 2: expected HTTP %d, got HTTP %d body=%s", http.StatusCreated, resp.StatusCode, string(body))
	}

	resp, body = getSearch(t, ts.URL, `type:ticket custom_field_111:pending`)
	if resp == nil {
		t.Errorf("search unquoted: unexpected nil response")
		return
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("search unquoted: expected HTTP %d, got HTTP %d", http.StatusOK, resp.StatusCode)
	}
	var res1 struct{ Results []any }
	err := json.Unmarshal(body, &res1)
	if err != nil {
		t.Errorf("search unquoted: unmarshal failed: %s", err)
	}
	if len(res1.Results) != 1 {
		t.Errorf("search unquoted: expected 1 result, got %d", len(res1.Results))
	}

	resp, body = getSearch(t, ts.URL, `type:ticket custom_field_111:"pending review"`)
	if resp == nil {
		t.Errorf("search quoted: unexpected nil response")
		return
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("search quoted: expected HTTP %d, got HTTP %d", http.StatusOK, resp.StatusCode)
	}
	var res2 struct{ Results []any }
	err = json.Unmarshal(body, &res2)
	if err != nil {
		t.Errorf("search quoted: unmarshal failed: %s", err)
	}
	if len(res2.Results) != 1 {
		t.Errorf("search quoted: expected 1 result, got %d", len(res2.Results))
	}
}

func TestSearchNewestFirstOrder(t *testing.T) {
	t.Parallel()

	_, ts := startTestServer(t)

	for i := 1; i <= 3; i++ {
		payload := fmt.Sprintf(`{
			"ticket": {
				"requester": {"name":"U%d","email":"u%d@example.com"},
				"subject": "S%d",
				"comment": {"body":"B%d","public":true},
				"custom_fields": [
					{"id": 999, "value": "x"}
				]
			}
		}`, i, i, i, i)

		resp, body := postTicket(t, ts.URL, []byte(payload))
		if resp == nil {
			t.Errorf("create ticket %d: unexpected nil response", i)
			return
		}
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("create ticket %d: expected HTTP %d, got HTTP %d body=%s", i, http.StatusCreated, resp.StatusCode, string(body))
			return
		}
	}

	type item struct {
		ID int64 `json:"id"`
	}
	type page struct {
		Results []item  `json:"results"`
		Next    *string `json:"next_page"`
	}

	var all []item

	resp, body := getSearch(t, ts.URL, `type:ticket custom_field_999:x`)
	if resp == nil {
		t.Errorf("initial search: unexpected nil response")
		return
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("initial search: expected HTTP %d, got HTTP %d", http.StatusOK, resp.StatusCode)
		return
	}
	var pg page
	err := json.Unmarshal(body, &pg)
	if err != nil {
		t.Errorf("initial search: unmarshal failed: %s", err)
		return
	}
	all = append(all, pg.Results...)

	next := pg.Next
	for next != nil && *next != "" {
		nextURL := *next
		if strings.HasPrefix(nextURL, "/") {
			nextURL = ts.URL + nextURL
		}
		resp, body = doJSON(t, http.MethodGet, nextURL, basicAuthHeader(apiTokenEmail, apiToken), nil, false)
		if resp == nil {
			t.Errorf("paginated search: unexpected nil response on next_page")
			return
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("paginated search: expected HTTP %d on next_page, got HTTP %d", http.StatusOK, resp.StatusCode)
			return
		}
		var np page
		err = json.Unmarshal(body, &np)
		if err != nil {
			t.Errorf("paginated search: unmarshal next_page failed: %s", err)
			return
		}
		all = append(all, np.Results...)
		next = np.Next
	}

	if len(all) != 3 {
		t.Errorf("expected 3 results, got %d", len(all))
		return
	}
	if !(all[0].ID > all[1].ID && all[1].ID > all[2].ID) {
		t.Errorf("order incorrect (want strictly descending IDs): %#v", all)
	}
}

func TestCapacityEviction(t *testing.T) {
	t.Parallel()

	store := NewStore(2)
	srv, ts := startTestServerWithStore(t, store)

	for i := 1; i <= 3; i++ {
		payload := fmt.Sprintf(`{
			"ticket": {
				"requester": {"name":"E%d","email":"e%d@example.com"},
				"subject": "Sub%d",
				"comment": {"body":"C%d","public":true},
				"custom_fields": [
					{"id": 111, "value": "v%d"}
				]
			}
		}`, i, i, i, i, i)

		resp, body := postTicket(t, ts.URL, []byte(payload))
		if resp == nil {
			t.Errorf("unexpected nil response creating ticket %d", i)
			return
		}
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("create ticket %d expected HTTP %d, got HTTP %d body=%s", i, http.StatusCreated, resp.StatusCode, string(body))
		}
	}

	_, ok := srv.GetTicket(1)
	if ok {
		t.Errorf("expected ticket 1 to be evicted")
	}
	_, ok = srv.GetTicket(2)
	if !ok {
		t.Errorf("expected ticket 2 to remain")
	}
	_, ok = srv.GetTicket(3)
	if !ok {
		t.Errorf("expected ticket 3 to remain")
	}
}

func TestSearchInvalidCustomFieldID(t *testing.T) {
	t.Parallel()

	_, ts := startTestServer(t)
	_ = createTicketAndReturnID(t, ts.URL)

	resp, body := getSearch(t, ts.URL, `type:ticket custom_field_abc:foo`)
	if resp == nil {
		t.Errorf("invalid custom field id search: unexpected nil response")
		return
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid custom field id search: expected HTTP %d, got HTTP %d body=%s", http.StatusBadRequest, resp.StatusCode, string(body))
	}
}

func TestSearchMissingQueryParam(t *testing.T) {
	t.Parallel()

	_, ts := startTestServer(t)

	resp, body := doJSON(t, http.MethodGet, ts.URL+SearchJSONPath, basicAuthHeader(apiTokenEmail, apiToken), nil, false)
	if resp == nil {
		t.Errorf("missing query param search: unexpected nil response")
		return
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("missing query param search: expected HTTP %d, got HTTP %d", http.StatusOK, resp.StatusCode)
	}

	var out struct {
		Results []any `json:"results"`
		Next    any   `json:"next_page"`
	}
	err := json.Unmarshal(body, &out)
	if err != nil {
		t.Errorf("missing query param search: unmarshal failed: %s", err)
	}
	if len(out.Results) != 0 {
		t.Errorf("missing query param search: expected 0 results, got %d", len(out.Results))
	}
}
