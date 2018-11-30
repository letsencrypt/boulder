package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

// addHTTP01 handles an HTTP POST request to add a new HTTP-01 challenge
// response for a given token.
func (srv *managementServer) addHTTP01(w http.ResponseWriter, r *http.Request) {
	// Read the request body
	msg, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Unmarshal the request body JSON as a request object
	var request struct {
		Token   string
		Content string
	}
	err = json.Unmarshal(msg, &request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// If the request has an empty token or content it's a bad request
	if request.Token == "" || request.Content == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Add the HTTP-01 challenge to the challenge server
	srv.challSrv.AddHTTPOneChallenge(request.Token, request.Content)
	srv.log.Printf("Added HTTP-01 challenge for token %q - key auth %q\n",
		request.Token, request.Content)
	w.WriteHeader(http.StatusOK)
}

// delHTTP01 handles an HTTP POST request to delete an existing HTTP-01
// challenge response for a given token.
func (srv *managementServer) delHTTP01(w http.ResponseWriter, r *http.Request) {
	// Read the request body
	msg, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Unmarshal the request body JSON as a request object
	var request struct {
		Token string
	}
	err = json.Unmarshal(msg, &request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// If the request has an empty token it's a bad request
	if request.Token == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Delete the HTTP-01 challenge for the given token from the challenge server
	srv.challSrv.DeleteHTTPOneChallenge(request.Token)
	srv.log.Printf("Removed HTTP-01 challenge for token %q\n", request.Token)
	w.WriteHeader(http.StatusOK)
}

// addHTTPRedirect handles an HTTP POST request to add a new 301 redirect to be
// served for the given path to the given target URL.
func (srv *managementServer) addHTTPRedirect(w http.ResponseWriter, r *http.Request) {
	// Read the request body
	msg, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Unmarshal the request body JSON as a request object
	var request struct {
		Path      string
		TargetURL string
	}
	err = json.Unmarshal(msg, &request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// If the request has an empty path or target URL it's a bad request
	if request.Path == "" || request.TargetURL == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Add the HTTP redirect to the challenge server
	srv.challSrv.AddHTTPRedirect(request.Path, request.TargetURL)
	srv.log.Printf("Added HTTP redirect for path %q to %q\n",
		request.Path, request.TargetURL)
	w.WriteHeader(http.StatusOK)
}

// delHTTPRedirect handles an HTTP POST request to delete an existing HTTP
// redirect for a given path.
func (srv *managementServer) delHTTPRedirect(w http.ResponseWriter, r *http.Request) {
	// Read the request body
	msg, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Unmarshal the request body JSON as a request object
	var request struct {
		Path string
	}
	err = json.Unmarshal(msg, &request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// If the request has an empty path it's a bad request
	if request.Path == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Delete the HTTP redirect for the given path from the challenge server
	srv.challSrv.DeleteHTTPRedirect(request.Path)
	srv.log.Printf("Removed HTTP redirect for path %q\n", request.Path)
	w.WriteHeader(http.StatusOK)
}
