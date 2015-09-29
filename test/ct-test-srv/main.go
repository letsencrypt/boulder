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
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync/atomic"
)

type ctSubmissionRequest struct {
	Chain []string `json:"chain"`
}

type integrationSrv struct {
	submissions int64
}

func (is *integrationSrv) handler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/ct/v1/add-chain":
		if r.Method != "POST" {
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
		// id is a sha256 of a random EC key. Generate your own with:
		// openssl ecparam -name prime256v1 -genkey -outform der | openssl sha256 -binary | base64
		w.Write([]byte(`{
			"sct_version": 0,
			"id": "8fjM8cvLPOhzCFwI62IYJhjkOcvWFLx1dMJbs0uhxJU=",
			"timestamp": 1442400000,
			"extensions": "",
			"signature": "BAMARzBFAiBB5wKED8KqKhADT37n0y28fZIPiGbCfZRVKq0wNo0hrwIhAOIa2tPBF/rB1y30Y/ROh4LBmJ0mItAbTWy8XZKh7Wcp"
		}`))
		atomic.AddInt64(&is.submissions, 1)
	case "/submissions":
		if r.Method != "GET" {
			http.NotFound(w, r)
			return
		}

		submissions := atomic.LoadInt64(&is.submissions)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("%d", submissions)))
	default:
		http.NotFound(w, r)
		return
	}
}

func main() {
	is := integrationSrv{}
	s := &http.Server{
		Addr:    "localhost:4500",
		Handler: http.HandlerFunc(is.handler),
	}
	log.Fatal(s.ListenAndServe())
}
