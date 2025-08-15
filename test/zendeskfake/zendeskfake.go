package zendeskfake

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	defaultTicketCapacity = 200
	searchPageSize        = 2
	apiPrefix             = "/api/v2"
	TicketsJSONPath       = apiPrefix + "/tickets.json"
	SearchJSONPath        = apiPrefix + "/search.json"
	TicketsPath           = apiPrefix + "/tickets/"
)

var (
	// ticketPathRegexp matches the tickets path with an ID at the end, e.g.
	// /api/v2/tickets/123.json. It captures the ID as the first group.
	ticketPathRegexp = regexp.MustCompile("^" + regexp.QuoteMeta(TicketsPath) + `(\d+)\.json$`)

	// customFieldRegexp matches custom fields in the format
	// custom_field_<id>:"value" or custom_field_<id>:value where <id> is the
	// field ID and "value" is the field value, allowing for both quoted and
	// unquoted values. It captures the field ID as the first group and the
	// value as the second group.
	customFieldRegexp = regexp.MustCompile(`custom_field_(\d+):("[^"]+"|\S+)`)
)

// requester represents a requester in a Zendesk ticket.
type requester struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// comment represents a comment in a Zendesk ticket.
type comment struct {
	Body   string `json:"body"`
	Public bool   `json:"public"`
}

// ticket represents all the fields of a Zendesk ticket.
type ticket struct {
	ID           int64            `json:"id"`
	Requester    requester        `json:"requester"`
	Subject      string           `json:"subject"`
	Comments     []comment        `json:"comments"`
	CustomFields map[int64]string `json:"custom_fields"`
}

// Store is a thread-safe in-memory store for tickets. It uses a stack to store
// the tickets and a map to quickly access them by ID. The stack has a fixed
// capacity, and when it is full, the oldest ticket is removed to make room.
type Store struct {
	sync.Mutex
	nextID int64
	cap    int
	stack  []*ticket
	byID   map[int64]*ticket
}

// NewStore creates a new Store with the specified capacity. If no capacity is
// specified, it defaults to 200 tickets.
func NewStore(capacity int) *Store {
	if capacity == 0 {
		capacity = defaultTicketCapacity
	}
	return &Store{
		nextID: 1,
		cap:    capacity,
		stack:  make([]*ticket, 0, defaultTicketCapacity),
		byID:   make(map[int64]*ticket, defaultTicketCapacity),
	}
}

func (s *Store) push(t *ticket) int64 {
	s.Lock()
	defer s.Unlock()

	if len(s.stack) >= s.cap {
		oldest := s.stack[0]
		delete(s.byID, oldest.ID)
		s.stack = s.stack[1:]
	}

	t.ID = s.nextID
	s.nextID++

	s.stack = append(s.stack, t)
	s.byID[t.ID] = t
	return t.ID
}

func (s *Store) addComment(id int64, c comment) error {
	s.Lock()
	defer s.Unlock()

	current, ok := s.byID[id]
	if !ok {
		return errors.New("ticket not found")
	}

	current.Comments = append(current.Comments, c)
	return nil
}

func checkBasicAuth(r *http.Request, wantEmail, wantToken string) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		return false
	}
	decodedBytes, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		return false
	}
	decoded := string(decodedBytes)
	expected := fmt.Sprintf("%s/token:%s", wantEmail, wantToken)
	return decoded == expected
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	bytes, err := json.Marshal(payload)
	if err != nil {
		log.Printf("failed to marshal response: %s", err)
		http.Error(w, "marshal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, err = w.Write(bytes)
	if err != nil {
		log.Printf("failed to write response: %s", err)
		http.Error(w, "write error", http.StatusInternalServerError)
		return
	}
}

type Server struct {
	tokenUser string
	token     string
	store     *Store
}

// NewServer creates a new Server with the specified user and token. If no store
// is provided, it creates a new Store with the default capacity.
func NewServer(tokenEmail, apiToken string, s *Store) *Server {
	if s == nil {
		s = NewStore(0)
	}
	return &Server{
		tokenUser: tokenEmail,
		token:     apiToken,
		store:     s,
	}
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok := checkBasicAuth(r, s.tokenUser, s.token)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// POST /api/v2/tickets.json
func (s *Server) createTicket(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Ticket struct {
			Requester requester `json:"requester"`
			Subject   string    `json:"subject"`
			Comment   comment   `json:"comment"`
			Custom    []struct {
				ID    int64 `json:"id"`
				Value any   `json:"value"`
			} `json:"custom_fields"`
		} `json:"ticket"`
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	if req.Ticket.Subject == "" || req.Ticket.Comment.Body == "" || req.Ticket.Requester.Email == "" {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error":       "RecordInvalid",
			"description": "Record validation errors",
		})
		return
	}

	newTicket := &ticket{
		Requester:    req.Ticket.Requester,
		Subject:      req.Ticket.Subject,
		Comments:     []comment{req.Ticket.Comment},
		CustomFields: make(map[int64]string),
	}

	for _, cf := range req.Ticket.Custom {
		newTicket.CustomFields[cf.ID] = fmt.Sprint(cf.Value)
	}

	ticketID := s.store.push(newTicket)

	writeJSON(w, http.StatusCreated, map[string]any{
		"ticket": map[string]int64{"id": ticketID},
	})
}

// PUT /api/v2/tickets/{id}.json
func (s *Server) updateTicket(w http.ResponseWriter, r *http.Request) {
	match := ticketPathRegexp.FindStringSubmatch(r.URL.Path)
	if len(match) != 2 {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error":       "RecordNotFound",
			"description": "Not found",
		})
		return
	}

	id, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error":       "RecordNotFound",
			"description": "Not found",
		})
		return
	}

	var req struct {
		Ticket struct {
			Comment comment `json:"comment"`
		} `json:"ticket"`
	}

	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	if req.Ticket.Comment.Body == "" {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error":       "RecordInvalid",
			"description": "Record validation errors",
			"details": map[string]any{
				"comment": []map[string]string{
					{"description": "Comment body can't be blank"},
				},
			},
		})
		return
	}

	err = s.store.addComment(id, req.Ticket.Comment)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error":       "RecordNotFound",
			"description": "Not found",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ticket": map[string]int64{"id": id},
	})
}

// GET /api/v2/search.json?query=...&page=...
func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	queryParam := r.URL.Query().Get("query")

	if !strings.Contains(queryParam, "type:ticket") {
		writeJSON(w, http.StatusOK, map[string]any{
			"results":   []any{},
			"next_page": nil,
			"count":     0,
		})
		return
	}

	type criterion struct {
		fieldID int64
		value   string
	}

	if strings.Contains(queryParam, "custom_field_") && !customFieldRegexp.MatchString(queryParam) {
		http.Error(w, "invalid custom field id", http.StatusBadRequest)
		return
	}

	var criteria []criterion
	matches := customFieldRegexp.FindAllStringSubmatch(queryParam, -1)
	for _, match := range matches {
		fieldID, err := strconv.ParseInt(match[1], 10, 64)
		if err != nil {
			http.Error(w, "invalid custom field id", http.StatusBadRequest)
			return
		}
		criteria = append(criteria, criterion{
			fieldID: fieldID,
			value:   strings.Trim(match[2], `"`),
		})
	}

	s.store.Lock()
	defer s.store.Unlock()

	type resultRow struct {
		id     int64
		fields []map[string]any
	}

	var resultRows []resultRow
	resultRows = make([]resultRow, 0, len(s.store.stack))

	for _, ticket := range s.store.stack {
		allMatch := true
		for _, c := range criteria {
			curr, ok := ticket.CustomFields[c.fieldID]
			if !ok || curr != c.value {
				allMatch = false
				break
			}
		}
		if !allMatch {
			continue
		}

		var cf []map[string]any
		for id, v := range ticket.CustomFields {
			cf = append(cf, map[string]any{"id": id, "value": v})
		}
		resultRows = append(resultRows, resultRow{id: ticket.ID, fields: cf})
	}

	sort.Slice(resultRows, func(i, j int) bool {
		return resultRows[i].id > resultRows[j].id
	})

	const pageSize = 2

	page := 1
	pageStr := r.URL.Query().Get("page")
	if pageStr != "" {
		pageNum, err := strconv.Atoi(pageStr)
		if err == nil && pageNum > 0 {
			page = pageNum
		}
	}

	total := len(resultRows)
	start := min((page-1)*pageSize, total)
	end := min(start+pageSize, total)

	buildNextPageURL := func(currPage int) *string {
		nextPage := currPage + 1
		if (nextPage-1)*pageSize >= total {
			return nil
		}
		u := url.URL{
			Scheme: "http",
			Host:   r.Host,
			Path:   r.URL.Path,
		}
		q := url.Values{}
		q.Set("query", queryParam)
		q.Set("page", strconv.Itoa(nextPage))
		u.RawQuery = q.Encode()
		s := u.String()
		return &s
	}

	encodedResults := make([]any, 0, end-start)
	for _, row := range resultRows[start:end] {
		encodedResults = append(encodedResults, map[string]any{
			"id":            row.id,
			"custom_fields": row.fields,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"results":   encodedResults,
		"next_page": buildNextPageURL(page),
		"count":     total,
	})
}

// Handler returns an HTTP handler that serves the Zendesk fake API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(TicketsJSONPath, s.auth(http.HandlerFunc(s.createTicket)))
	mux.Handle(SearchJSONPath, s.auth(http.HandlerFunc(s.search)))
	mux.Handle(TicketsPath, s.auth(http.HandlerFunc(s.updateTicket)))
	return mux
}

// GetTicket retrieves a ticket by its ID directly from the inner store. It
// returns a copy of the ticket to ensure that the original ticket in the store
// is never modified. If the ticket does not exist, it returns false.
func (s *Server) GetTicket(id int64) (ticket, bool) {
	s.store.Lock()
	defer s.store.Unlock()
	t, ok := s.store.byID[id]
	if !ok {
		return ticket{}, false
	}
	cp := *t
	cp.CustomFields = make(map[int64]string, len(t.CustomFields))
	maps.Copy(cp.CustomFields, t.CustomFields)
	cp.Comments = append([]comment(nil), t.Comments...)
	return cp, true
}
