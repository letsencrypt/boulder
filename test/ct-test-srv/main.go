// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// This is a test server that implements the subset of RFC6962 APIs needed to
// run Boulder's CT log submission code. Currently it only implements add-chain.
// This is used by startservers.py.
package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
)

type ctSubmissionRequest struct {
	Chain []string `json:"chain"`
}

func handler(w http.ResponseWriter, r *http.Request) {
	log.Printf("request: %s %s", r.Method, r.URL.Path)
	if r.Method != "POST" || r.URL.Path != "/ct/v1/add-chain" {
		http.NotFound(w, r)
		return
	}
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	var addChainReq ctSubmissionRequest
	err = json.Unmarshal(bodyBytes, &addChainReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{
		"sct_version": 0,
		"id": "",
		"timestamp": 1442400000,
		"extensions": "",
		"signature": "BAMARzBFAiBB5wKED8KqKhADT37n0y28fZIPiGbCfZRVKq0wNo0hrwIhAOIa2tPBF/rB1y30Y/ROh4LBmJ0mItAbTWy8XZKh7Wcp"
	}`))
}

func main() {
	s := &http.Server{
		Addr:    ":4500",
		Handler: http.HandlerFunc(handler),
	}
	log.Fatal(s.ListenAndServe())
}
