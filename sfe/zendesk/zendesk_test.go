package zendesk

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/letsencrypt/boulder/test/zendeskfake"
)

const (
	apiTokenEmail = "tester@example.com"
	apiToken      = "someToken"
)

func startMockClient(t *testing.T) (*Client, *zendeskfake.Server) {
	t.Helper()

	st := zendeskfake.NewStore(0)
	srv := zendeskfake.NewServer(apiTokenEmail, apiToken, st)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	nameToID := map[string]int64{
		"reviewStatus": 111,
		"organization": 222,
		"kind":         333,
	}

	c, err := NewClient(ts.URL, apiTokenEmail, apiToken, nameToID)
	if err != nil {
		t.Errorf("NewClient(%q) returned error: %s", ts.URL, err)
	}

	return c, srv
}

func TestNewClientWithDuplicateFieldID(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.NewServeMux())
	defer ts.Close()
	nameToID := map[string]int64{
		"a": 1,
		"b": 1,
	}
	_, err := NewClient(ts.URL, apiTokenEmail, apiToken, nameToID)
	if err == nil || !strings.Contains(err.Error(), "duplicate field ID") {
		t.Errorf("expected duplicate field ID error, got: %s", err)
	}
}

func TestNewClientBaseURLJoin(t *testing.T) {
	t.Parallel()

	base := "http://example.test"
	_, err := NewClient(base+"/", apiTokenEmail, apiToken, map[string]int64{})
	if err != nil {
		t.Errorf("NewClient with trailing slash failed: %s", err)
	}
	_, err = NewClient(base, apiTokenEmail, apiToken, map[string]int64{})
	if err != nil {
		t.Errorf("NewClient without trailing slash failed: %s", err)
	}
}

func TestCreateTicketOK(t *testing.T) {
	t.Parallel()

	c, srv := startMockClient(t)

	id, err := c.CreateTicket("alice@example.com", "Subject", "Body text", map[string]string{
		"reviewStatus": "pending",
		"organization": "Acme",
	})
	if err != nil {
		t.Errorf("CreateTicket(alice@example.com, Subject) error: %s", err)
	}
	if id == 0 {
		t.Errorf("CreateTicket returned id=0; want non-zero")
	}

	got, ok := srv.GetTicket(id)
	if !ok {
		t.Errorf("ticket id %d not stored in mock server", id)
	}
	if got.Subject != "Subject" {
		t.Errorf("subject mismatch: got %q, want %q", got.Subject, "Subject")
	}
	if len(got.Comments) != 1 || got.Comments[0].Body != "Body text" || !got.Comments[0].Public {
		t.Errorf("comments stored incorrectly: %#v (want one public comment with body %q)", got.Comments, "Body text")
	}
	if got.CustomFields[111] != "pending" || got.CustomFields[222] != "Acme" {
		t.Errorf("custom fields mismatch: %#v (want 111=%q, 222=%q)", got.CustomFields, "pending", "Acme")
	}
}

func TestCreateTicketHTTPError(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/tickets.json", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	c, err := NewClient(ts.URL, apiTokenEmail, apiToken, map[string]int64{})
	if err != nil {
		t.Errorf("NewClient(%q): %s", ts.URL, err)
	}

	_, err = c.CreateTicket("bob@example.com", "cause500", "x", nil)
	if err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Errorf("expected HTTP 500 error creating ticket, got: %s", err)
	}
}

func TestCreateTicketUnknownField(t *testing.T) {
	t.Parallel()

	c, _ := startMockClient(t)

	_, err := c.CreateTicket("x@example.com", "s", "b", map[string]string{"nope": "v"})
	if err == nil || !strings.Contains(err.Error(), "unknown custom field") {
		t.Errorf("expected unknown custom field error, got: %s", err)
	}
}

func TestCreateTicketSetsRequesterNameToEmail(t *testing.T) {
	t.Parallel()

	c, srv := startMockClient(t)

	id, err := c.CreateTicket("alice@example.com", "S", "B", nil)
	if err != nil {
		t.Errorf("CreateTicket(alice@example.com): %s", err)
	}

	got, ok := srv.GetTicket(id)
	if !ok {
		t.Errorf("ticket id %d not found in server", id)
		return
	}
	if got.Requester.Email != "alice@example.com" || got.Requester.Name != "alice@example.com" {
		t.Errorf("requester mismatch for ticket %d: %#v (want Email=%q Name=%q)", id, got.Requester, "alice@example.com", "alice@example.com")
	}
}

func TestAddCommentOK(t *testing.T) {
	t.Parallel()

	c, srv := startMockClient(t)

	id, err := c.CreateTicket("a@example.com", "s", "first", nil)
	if err != nil {
		t.Errorf("CreateTicket(a@example.com): %s", err)
	}

	err = c.AddComment(id, "second-private", false)
	if err != nil {
		t.Errorf("AddComment(id=%d): %s", id, err)
	}

	got, ok := srv.GetTicket(id)
	if !ok {
		t.Errorf("ticket id %d not stored after AddComment", id)
	}
	if len(got.Comments) != 2 {
		t.Errorf("want 2 comments after AddComment, got %d: %#v", len(got.Comments), got.Comments)
	}
	if got.Comments[1].Body != "second-private" || got.Comments[1].Public {
		t.Errorf("second comment incorrect: %#v (want body=%q, public=false)", got.Comments[1], "second-private")
	}
}

func TestAddComment404(t *testing.T) {
	t.Parallel()

	c, _ := startMockClient(t)

	err := c.AddComment(99999, "x", true)
	if err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Errorf("expected HTTP 404 when adding comment to unknown ticket, got: %s", err)
	}
}

func TestAddCommentEmptyBody422(t *testing.T) {
	t.Parallel()

	c, _ := startMockClient(t)

	id, err := c.CreateTicket("a@example.com", "s", "init", nil)
	if err != nil {
		t.Errorf("CreateTicket(a@example.com): %s", err)
	}

	err = c.AddComment(id, "", true)
	if err == nil || !strings.Contains(err.Error(), "status 422") {
		t.Errorf("expected HTTP 422 for empty comment body on ticket %d, got: %s", id, err)
	}
}

func TestUpdateTicketStatus(t *testing.T) {
	t.Parallel()

	type tc struct {
		name          string
		status        string
		comment       *comment
		expectErr     bool
		expectStatus  string
		expectComment *comment
	}

	cases := []tc{
		{
			name:         "Update to open without comment",
			status:       "open",
			expectErr:    false,
			expectStatus: "open",
		},
		{
			name:          "Update to pending with comment",
			status:        "solved",
			comment:       &comment{Body: "Resolved", Public: true},
			expectErr:     false,
			expectStatus:  "solved",
			expectComment: &comment{Body: "Resolved", Public: true},
		},
		{
			name:         "Update from new to foo (invalid status)",
			status:       "foo",
			expectErr:    true,
			expectStatus: "new",
		},
		{
			name:         "unknown id",
			status:       "open",
			expectErr:    true,
			expectStatus: "new",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fake := zendeskfake.NewServer(apiTokenEmail, apiToken, nil)
			ts := httptest.NewServer(fake.Handler())
			t.Cleanup(ts.Close)

			client, err := NewClient(ts.URL, apiTokenEmail, apiToken, map[string]int64{})
			if err != nil {
				t.Errorf("Unexpected error from NewClient(%q): %s", ts.URL, err)
			}

			client.updateURL, err = url.JoinPath(ts.URL, "/api/v2/tickets")
			if err != nil {
				t.Errorf("Failed to join update URL: %s", err)
			}

			id, err := client.CreateTicket("foo@bar.co", "Some subject", "Some comment", nil)
			if err != nil {
				t.Errorf("Unexpected error from CreateTicket: %s", err)
			}

			updateID := id
			if tc.name == "unknown id" {
				updateID = 999999
			}

			var commentBody string
			var public bool
			if tc.comment != nil {
				commentBody = tc.comment.Body
				public = tc.comment.Public
			}
			err = client.UpdateTicketStatus(updateID, tc.status, commentBody, public)
			if tc.expectErr {
				if err == nil {
					t.Errorf("Expected error for status %q, got nil", tc.status)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for UpdateTicketStatus(%d, %q): %s", updateID, tc.status, err)
				}
			}

			got, ok := fake.GetTicket(id)
			if !ok {
				t.Errorf("Ticket with id %d not found after update", id)
			}

			if got.Status != tc.expectStatus {
				t.Errorf("Expected status %q, got %q", tc.expectStatus, got.Status)
			}
			if tc.expectComment != nil {
				found := false
				for _, c := range got.Comments {
					if c.Body == tc.expectComment.Body && c.Public == tc.expectComment.Public {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected comment not found: %#v in %#v", tc.expectComment, got.Comments)
				}
			} else if len(got.Comments) > 1 {
				t.Errorf("Expected no additional comment, got %d: %#v", len(got.Comments), got.Comments)
			}
		})
	}
}

func TestFindTicketsSimple(t *testing.T) {
	t.Parallel()

	c, _ := startMockClient(t)

	_, err := c.CreateTicket("u1@example.com", "s1", "b", map[string]string{"reviewStatus": "pending", "organization": "Acme"})
	if err != nil {
		t.Errorf("creating ticket 1: %s", err)
	}
	_, err = c.CreateTicket("u2@example.com", "s2", "b", map[string]string{"reviewStatus": "approved", "organization": "Acme"})
	if err != nil {
		t.Errorf("creating ticket 2: %s", err)
	}
	id3, err := c.CreateTicket("u3@example.com", "s3", "b", map[string]string{"reviewStatus": "pending", "organization": "Beta"})
	if err != nil {
		t.Errorf("creating ticket 3: %s", err)
	}

	got, err := c.FindTickets(map[string]string{"reviewStatus": "pending"}, "new")
	if err != nil {
		t.Errorf("FindTickets(reviewStatus=pending): %s", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 results for reviewStatus=pending, got %d: %#v", len(got), got)
	}
	fields, ok := got[id3]
	if ok {
		if fields["reviewStatus"] != "pending" || fields["organization"] != "Beta" {
			t.Errorf("field name/value mapping wrong for ticket %d: %#v (want reviewStatus=%q, organization=%q)", id3, fields, "pending", "Beta")
		}
	}
}

func TestFindTicketsQuotedValueReturnsAll(t *testing.T) {
	t.Parallel()

	c, _ := startMockClient(t)

	for i := range 5 {
		_, err := c.CreateTicket("x@example.com", fmt.Sprintf("s%d", i), "b",
			map[string]string{"reviewStatus": "needs review"})
		if err != nil {
			t.Errorf("create ticket %d: %s", i, err)
		}
	}

	got, err := c.FindTickets(map[string]string{"reviewStatus": "needs review"}, "new")
	if err != nil {
		t.Errorf("FindTickets(needs review): %s", err)
	}
	if len(got) != 5 {
		t.Errorf("expected 5 results for quoted value search, got %d: %#v", len(got), got)
	}
}

func TestFindTicketsNoMatchFieldsError(t *testing.T) {
	t.Parallel()

	c, _ := startMockClient(t)

	_, err := c.FindTickets(map[string]string{}, "new")
	if err == nil || !strings.Contains(err.Error(), "no match fields") {
		t.Errorf("expected error for empty match fields, got: %s", err)
	}
}

func TestFindTicketsUnknownFieldName(t *testing.T) {
	t.Parallel()

	c, _ := startMockClient(t)

	_, err := c.FindTickets(map[string]string{"unknown": "v"}, "new")
	if err == nil || !strings.Contains(err.Error(), "unknown custom field") {
		t.Errorf("expected unknown custom field error, got: %s", err)
	}
}

func TestFindTicketsNoResults(t *testing.T) {
	t.Parallel()

	c, _ := startMockClient(t)

	_, err := c.CreateTicket("u@example.com", "s", "b", map[string]string{"reviewStatus": "approved"})
	if err != nil {
		t.Errorf("creating ticket with reviewStatus=approved: %s", err)
	}
	got, err := c.FindTickets(map[string]string{"reviewStatus": "pending"}, "new")
	if err != nil {
		t.Errorf("FindTickets(reviewStatus=pending): %s", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 results, got %d: %#v", len(got), got)
	}
}

func TestFindTicketsPaginationFollowed(t *testing.T) {
	t.Parallel()

	store := zendeskfake.NewStore(0)
	fake := zendeskfake.NewServer(apiTokenEmail, apiToken, store)

	inner := fake.Handler()
	var searchHits int32

	mux := http.NewServeMux()
	mux.HandleFunc(zendeskfake.SearchJSONPath, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&searchHits, 1)
		inner.ServeHTTP(w, r)
	})
	mux.Handle(zendeskfake.TicketsJSONPath, inner)
	mux.Handle(zendeskfake.TicketsPath, inner)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	c, err := NewClient(ts.URL, apiTokenEmail, apiToken, map[string]int64{"reviewStatus": 111})
	if err != nil {
		t.Errorf("NewClient(%q): %s", ts.URL, err)
	}

	for i := range 5 {
		if _, err := c.CreateTicket(
			fmt.Sprintf("u%d@example.com", i),
			fmt.Sprintf("s%d", i),
			"body",
			map[string]string{"reviewStatus": "needs review"},
		); err != nil {
			t.Errorf("create ticket %d: %s", i, err)
		}
	}

	got, err := c.FindTickets(map[string]string{"reviewStatus": "needs review"}, "")
	if err != nil {
		t.Errorf("FindTickets(needs review): %s", err)
	}
	if len(got) != 5 {
		t.Errorf("expected 5 merged results from paginated search, got %d: %#v", len(got), got)
	}

	if atomic.LoadInt32(&searchHits) < 3 {
		t.Errorf("expected >= 3 /search.json requests due to pagination, got %d", searchHits)
	}
}

func TestFindTicketsHTTP400(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/search.json", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad query", http.StatusBadRequest)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	c, err := NewClient(ts.URL, apiTokenEmail, apiToken, map[string]int64{"reviewStatus": 111})
	if err != nil {
		t.Errorf("NewClient(%q): %s", ts.URL, err)
	}
	_, err = c.FindTickets(map[string]string{"reviewStatus": "needs review"}, "new")
	if err == nil || !strings.Contains(err.Error(), "status 400") {
		t.Errorf("expected HTTP 400 from search, got: %s", err)
	}
}

func TestFindTicketsHTTP500(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/search.json", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	c, err := NewClient(ts.URL, apiTokenEmail, apiToken, map[string]int64{"reviewStatus": 111})
	if err != nil {
		t.Errorf("NewClient(%q): %s", ts.URL, err)
	}
	_, err = c.FindTickets(map[string]string{"reviewStatus": "needs review"}, "new")
	if err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Errorf("expected HTTP 500 from search, got: %s", err)
	}
}
