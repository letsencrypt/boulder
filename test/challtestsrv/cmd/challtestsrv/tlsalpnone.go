package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

// addTLSALPN01 handles an HTTP POST request to add a new TLS-ALPN-01 challenge
// response for a given host.
func (srv *managementServer) addTLSALPN01(w http.ResponseWriter, r *http.Request) {
	// Read the request body
	msg, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Unmarshal the request body JSON as a request object
	var request struct {
		Host    string
		Content string
	}
	err = json.Unmarshal(msg, &request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// If the request has an empty host or content it's a bad request
	if request.Host == "" || request.Content == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Add the TLS-ALPN-01 challenge to the challenge server
	srv.challSrv.AddTLSALPNChallenge(request.Host, request.Content)
	srv.log.Printf("Added TLS-ALPN-01 challenge for host %q - key auth %q\n",
		request.Host, request.Content)
	w.WriteHeader(http.StatusOK)
}

// delTLSALPN01 handles an HTTP POST request to delete an existing TLS-ALPN-01
// challenge response for a given host.
func (srv *managementServer) delTLSALPN01(w http.ResponseWriter, r *http.Request) {
	// Read the request body
	msg, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Unmarshal the request body JSON as a request object
	var request struct {
		Host string
	}
	err = json.Unmarshal(msg, &request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// If the request has an empty host it's a bad request
	if request.Host == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Delete the TLS-ALPN-01 challenge for the given host from the challenge server
	srv.challSrv.DeleteTLSALPNChallenge(request.Host)
	srv.log.Printf("Removed TLS-ALPN-01 challenge for host %q\n", request.Host)
	w.WriteHeader(http.StatusOK)
}
