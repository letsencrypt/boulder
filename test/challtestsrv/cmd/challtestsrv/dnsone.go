package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

// addDNS01 handles an HTTP POST request to add a new DNS-01 challenge TXT
// record for a given host/value.
func (srv *managementServer) addDNS01(w http.ResponseWriter, r *http.Request) {
	// Read the request body
	msg, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Unmarshal the request body JSON as a request object
	var request struct {
		Host  string
		Value string
	}
	err = json.Unmarshal(msg, &request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// If the request has an empty host or value it's a bad request
	if request.Host == "" || request.Value == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Add the DNS-01 challenge response TXT to the challenge server
	srv.challSrv.AddDNSOneChallenge(request.Host, request.Value)
	srv.log.Printf("Added DNS-01 TXT challenge for Host %q - Value %q\n",
		request.Host, request.Value)
	w.WriteHeader(http.StatusOK)
}

// delDNS01 handles an HTTP POST request to delete an existing DNS-01 challenge
// TXT record for a given host.
func (srv *managementServer) delDNS01(w http.ResponseWriter, r *http.Request) {
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

	// If the request has an empty host value it's a bad request
	if request.Host == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Delete the DNS-01 challenge response TXT for the given host from the
	// challenge server
	srv.challSrv.DeleteDNSOneChallenge(request.Host)
	srv.log.Printf("Removed DNS-01 TXT challenge for Host %q\n", request.Host)
	w.WriteHeader(http.StatusOK)
}
