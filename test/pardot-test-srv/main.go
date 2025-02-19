package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/letsencrypt/boulder/cmd"
)

type config struct {
	// OAuthPort is the port on which the OAuth server will listen.
	OAuthPort int

	// PardotPort is the port on which the Pardot server will listen.
	PardotPort int

	// ExpectedClientID is the client ID that the server expects to receive in
	// requests to the /services/oauth2/token endpoint.
	ExpectedClientID string

	// ExpectedClientSecret is the client secret that the server expects to
	// receive in requests to the /services/oauth2/token endpoint.
	ExpectedClientSecret string

	// DevelopmentMode is a flag that indicates whether the server is running in
	// development mode. In development mode, the server will:
	//   - provide an endpoint to expire the current token,
	//   - store contacts in memory, and
	//   - provide an endpoint to query the stored contacts.
	//
	// Only set this flag to true if you are running the server for testing
	// (e.g. within docker-compose) or local development purposes.
	DevelopmentMode bool
}

type token struct {
	sync.Mutex

	// active is the currently active token. If this field is empty, it means
	// that the token has been manually expired.
	active string
}

type createdContacts map[string]struct{}

type contacts struct {
	sync.RWMutex

	created createdContacts
}

type testServer struct {
	expectedClientID     string
	expectedClientSecret string
	token                token
	contacts             contacts
	developmentMode      bool
}

// generateToken generates a new random token.
func generateToken() string {
	bytes := make([]byte, 32)
	for i := range bytes {
		bytes[i] = byte(rand.IntN(256))
	}
	return fmt.Sprintf("%x", bytes)
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

	ts.token.Lock()
	defer ts.token.Unlock()
	if ts.token.active == "" {
		ts.token.active = generateToken()
	}

	response := map[string]interface{}{
		"access_token": ts.token.active,
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

func (ts *testServer) expireTokenHandler(w http.ResponseWriter, r *http.Request) {
	ts.token.Lock()
	ts.token.active = ""
	ts.token.Unlock()

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(map[string]string{"status": "token expired"})
	if err != nil {
		log.Printf("Failed to encode expire token response: %v", err)
		http.Error(w, "Failed to encode expire token response", http.StatusInternalServerError)
	}
}

func (ts *testServer) createContactsHandler(w http.ResponseWriter, r *http.Request) {
	ts.token.Lock()
	validToken := ts.token.active
	ts.token.Unlock()

	token := r.Header.Get("Authorization")
	businessUnitId := r.Header.Get("Pardot-Business-Unit-Id")

	if token != "Bearer "+validToken {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if businessUnitId == "" {
		http.Error(w, "Missing 'Pardot-Business-Unit-Id' header", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	type contactData struct {
		Email string `json:"email"`
	}

	var contact contactData
	err = json.Unmarshal(body, &contact)
	if err != nil {
		http.Error(w, "Failed to parse request body", http.StatusBadRequest)
		return
	}

	if contact.Email == "" {
		http.Error(w, "Missing 'email' field in request body", http.StatusBadRequest)
		return
	}

	if ts.developmentMode {
		ts.contacts.Lock()
		_, exists := ts.contacts.created[contact.Email]
		if !exists {
			ts.contacts.created[contact.Email] = struct{}{}
		}
		ts.contacts.Unlock()
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (ts *testServer) queryContactsHandler(w http.ResponseWriter, r *http.Request) {
	ts.contacts.RLock()
	respContacts := make([]string, 0, len(ts.contacts.created))
	for contact := range ts.contacts.created {
		respContacts = append(respContacts, contact)
	}
	ts.contacts.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(map[string]interface{}{"contacts": respContacts})
	if err != nil {
		log.Printf("Failed to encode contacts query response: %v", err)
		http.Error(w, "Failed to encode contacts query response", http.StatusInternalServerError)
	}
}

func main() {
	configFile := flag.String("config", "", "Path to configuration file")
	flag.Parse()

	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	file, err := os.Open(*configFile)
	cmd.FailOnError(err, "Failed to open configuration file")
	defer file.Close()
	decoder := json.NewDecoder(file)
	var c config
	err = decoder.Decode(&c)
	cmd.FailOnError(err, "Failed to decode configuration file")

	ts := &testServer{
		expectedClientID:     c.ExpectedClientID,
		expectedClientSecret: c.ExpectedClientSecret,
		contacts: contacts{
			created: make(createdContacts),
		},
		token: token{
			active: generateToken(),
		},
		developmentMode: c.DevelopmentMode,
	}

	// Oauth API
	oauthMux := http.NewServeMux()
	oauthMux.HandleFunc("/services/oauth2/token", ts.getTokenHandler)
	if c.DevelopmentMode {
		oauthMux.HandleFunc("/expire_token", ts.expireTokenHandler)
	}
	oauthServer := &http.Server{
		Addr:        fmt.Sprintf(":%d", c.OAuthPort),
		Handler:     oauthMux,
		ReadTimeout: 30 * time.Second,
	}
	log.Printf("pardot-test-srv oauth server running on port %d", c.OAuthPort)
	go func() {
		err := oauthServer.ListenAndServe()
		if err != nil {
			log.Fatalf("Failed to start OAuth server: %s", err)
		}
	}()

	// Pardot API
	pardotMux := http.NewServeMux()
	pardotMux.HandleFunc("/api/v5/objects/prospects", ts.createContactsHandler)
	if c.DevelopmentMode {
		pardotMux.HandleFunc("/contacts", ts.queryContactsHandler)
	}
	pardotServer := &http.Server{
		Addr:        fmt.Sprintf(":%d", c.PardotPort),
		Handler:     pardotMux,
		ReadTimeout: 30 * time.Second,
	}
	log.Printf("pardot-test-srv pardot server running on port %d", c.PardotPort)
	go func() {
		err := pardotServer.ListenAndServe()
		if err != nil {
			log.Fatalf("Failed to start Pardot server: %s", err)
		}
	}()

	cmd.WaitForSignal()
}
