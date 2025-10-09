package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/letsencrypt/boulder/cmd"
)

var contactsCap = 20

type config struct {
	// OAuthAddr is the address (e.g. IP:port) on which the Salesforce REST API
	// and OAuth API server will listen.
	//
	// Deprecated: Use SalesforceAddr instead.
	// TODO(#8410): Remove this field.
	OAuthAddr string

	// SalesforceAddr is the address (e.g. IP:port) on which the Salesforce REST
	// API and OAuth API server will listen.
	SalesforceAddr string

	// PardotAddr is the address (e.g. IP:port) on which the Pardot server will
	// listen.
	PardotAddr string

	// ExpectedClientID is the client ID that the server expects to receive in
	// requests to the /services/oauth2/token endpoint.
	ExpectedClientID string `validate:"required"`

	// ExpectedClientSecret is the client secret that the server expects to
	// receive in requests to the /services/oauth2/token endpoint.
	ExpectedClientSecret string `validate:"required"`
}

type contacts struct {
	sync.Mutex
	created []string
}

type cases struct {
	sync.Mutex
	created []map[string]any
}

type testServer struct {
	expectedClientID     string
	expectedClientSecret string
	token                string
	contacts             contacts
	cases                cases
}

func (ts *testServer) getTokenHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	if clientID != ts.expectedClientID || clientSecret != ts.expectedClientSecret {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	response := map[string]any{
		"access_token": ts.token,
		"token_type":   "Bearer",
		"expires_in":   3600,
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Printf("Failed to encode token response: %v", err)
		http.Error(w, "Failed to encode token response", http.StatusInternalServerError)
	}
}

func (ts *testServer) checkToken(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token != "Bearer "+ts.token {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
}

func (ts *testServer) upsertContactsHandler(w http.ResponseWriter, r *http.Request) {
	ts.checkToken(w, r)

	businessUnitId := r.Header.Get("Pardot-Business-Unit-Id")
	if businessUnitId == "" {
		http.Error(w, "Missing 'Pardot-Business-Unit-Id' header", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	type upsertPayload struct {
		MatchEmail string `json:"matchEmail"`
		Prospect   struct {
			Email string `json:"email"`
		} `json:"prospect"`
	}

	var payload upsertPayload
	err = json.Unmarshal(body, &payload)
	if err != nil {
		http.Error(w, "Failed to parse request body", http.StatusBadRequest)
		return
	}

	if payload.MatchEmail == "" || payload.Prospect.Email == "" {
		http.Error(w, "Missing 'matchEmail' or 'prospect.email' in request body", http.StatusBadRequest)
		return
	}

	ts.contacts.Lock()
	if len(ts.contacts.created) >= contactsCap {
		// Copying the slice in memory is inefficient, but this is a test server
		// with a small number of contacts, so it's fine.
		ts.contacts.created = ts.contacts.created[1:]
	}
	ts.contacts.created = append(ts.contacts.created, payload.Prospect.Email)
	ts.contacts.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status": "success"}`))
}

func (ts *testServer) queryContactsHandler(w http.ResponseWriter, r *http.Request) {
	ts.checkToken(w, r)

	ts.contacts.Lock()
	respContacts := slices.Clone(ts.contacts.created)
	ts.contacts.Unlock()

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(map[string]any{"contacts": respContacts})
	if err != nil {
		log.Printf("Failed to encode contacts query response: %v", err)
		http.Error(w, "Failed to encode contacts query response", http.StatusInternalServerError)
	}
}

func (ts *testServer) createCaseHandler(w http.ResponseWriter, r *http.Request) {
	ts.checkToken(w, r)

	var payload map[string]any
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	_, ok := payload["Origin"]
	if !ok {
		http.Error(w, "Missing required field: Origin", http.StatusBadRequest)
		return
	}

	ts.cases.Lock()
	ts.cases.created = append(ts.cases.created, payload)
	ts.cases.Unlock()

	resp := map[string]any{
		"id":      fmt.Sprintf("500xx00000%06dAAA", len(ts.cases.created)+1),
		"success": true,
		"errors":  []string{},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	err := json.NewEncoder(w).Encode(resp)
	if err != nil {
		log.Printf("Failed to encode case creation response: %s", err)
		http.Error(w, "Failed to encode case creation response", http.StatusInternalServerError)
	}
}

func (ts *testServer) queryCasesHandler(w http.ResponseWriter, r *http.Request) {
	ts.checkToken(w, r)

	ts.cases.Lock()
	respCases := slices.Clone(ts.cases.created)
	ts.cases.Unlock()

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(map[string]any{"cases": respCases})
	if err != nil {
		log.Printf("Failed to encode cases query response: %v", err)
		http.Error(w, "Failed to encode cases query response", http.StatusInternalServerError)
	}
}

func main() {
	// TODO(#8410): Remove the oauthAddr flag.
	oauthAddr := flag.String("oauth-addr", "", "Salesforce REST API and OAuth server listen address override (deprecated: use --salesforce-addr instead)")
	salesforceAddr := flag.String("salesforce-addr", "", "Salesforce REST API and OAuth server listen address override")
	pardotAddr := flag.String("pardot-addr", "", "Pardot server listen address override")
	configFile := flag.String("config", "", "Path to configuration file")
	flag.Parse()

	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	// TODO(#8410): Reduce this logic down to just using salesforceAddr once
	// oauthAddr is removed.
	firstNonEmpty := func(vals ...string) string {
		for _, v := range vals {
			if v != "" {
				return v
			}
		}
		return ""
	}
	c.SalesforceAddr = firstNonEmpty(*salesforceAddr, c.SalesforceAddr, *oauthAddr, c.OAuthAddr)
	if c.SalesforceAddr == "" {
		log.Fatal("--salesforce-addr or JSON salesforceAddr must be set (or use deprecated --oauth-addr or JSON oauthAddr until removed)")
	}

	if *pardotAddr != "" {
		c.PardotAddr = *pardotAddr
	}

	tokenBytes := make([]byte, 32)
	_, err = rand.Read(tokenBytes)
	if err != nil {
		log.Fatalf("Failed to generate token: %v", err)
	}

	ts := &testServer{
		expectedClientID:     c.ExpectedClientID,
		expectedClientSecret: c.ExpectedClientSecret,
		token:                fmt.Sprintf("%x", tokenBytes),
		contacts:             contacts{created: make([]string, 0, contactsCap)},
		cases:                cases{created: make([]map[string]any, 0)},
	}

	// Salesforce REST API and OAuth Server
	oauthMux := http.NewServeMux()
	oauthMux.HandleFunc("/services/oauth2/token", ts.getTokenHandler)
	oauthMux.HandleFunc("/services/data/v65.0/sobjects/Case", ts.createCaseHandler)
	oauthMux.HandleFunc("/cases", ts.queryCasesHandler)
	oauthServer := &http.Server{
		Addr:        c.SalesforceAddr,
		Handler:     oauthMux,
		ReadTimeout: 30 * time.Second,
	}

	log.Printf("pardot-test-srv Salesforce REST API and OAuth server listening at %s", c.SalesforceAddr)
	go func() {
		err := oauthServer.ListenAndServe()
		if err != nil {
			log.Fatalf("Failed to start Salesforce REST API and OAuth server: %s", err)
		}
	}()

	// Pardot API Server
	pardotMux := http.NewServeMux()
	pardotMux.HandleFunc("/api/v5/objects/prospects/do/upsertLatestByEmail", ts.upsertContactsHandler)
	pardotMux.HandleFunc("/contacts", ts.queryContactsHandler)

	pardotServer := &http.Server{
		Addr:        c.PardotAddr,
		Handler:     pardotMux,
		ReadTimeout: 30 * time.Second,
	}
	log.Printf("pardot-test-srv Salesforce Pardot API server listening at %s", c.PardotAddr)
	go func() {
		err := pardotServer.ListenAndServe()
		if err != nil {
			log.Fatalf("Failed to start Salesforce Pardot API server: %s", err)
		}
	}()

	cmd.WaitForSignal()
}
