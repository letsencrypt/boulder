// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package safebrowsing

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	pb "github.com/google/safebrowsing/internal/safebrowsing_proto"

	"github.com/golang/protobuf/proto"
)

const (
	findHashPath    = "/v4/fullHashes:find"
	fetchUpdatePath = "/v4/threatListUpdates:fetch"
)

// The api interface specifies wrappers around the Safe Browsing API.
type api interface {
	ListUpdate(req *pb.FetchThreatListUpdatesRequest) (*pb.FetchThreatListUpdatesResponse, error)
	HashLookup(req *pb.FindFullHashesRequest) (*pb.FindFullHashesResponse, error)
}

// netAPI is an api object that talks to the server over HTTP.
type netAPI struct {
	client http.Client
	url    *url.URL
}

// newNetAPI creates a new netAPI object pointed at the provided root URL.
// For every request, it will use the provided API key.
// If the protocol is not specified in root, then this defaults to using HTTPS.
func newNetAPI(root string, key string) (*netAPI, error) {
	if !strings.Contains(root, "://") {
		root = "https://" + root
	}
	u, err := url.Parse(root)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Set("key", key)
	q.Set("alt", "proto")
	u.RawQuery = q.Encode()
	return &netAPI{url: u}, nil
}

// doRequests performs a POST to requestPath. It uses the marshaled form of req
// as the request body payload, and automatically unmarshals the response body
// payload as resp.
func (a *netAPI) doRequest(requestPath string, req proto.Message, resp proto.Message) error {
	p, err := proto.Marshal(req)
	if err != nil {
		return err
	}

	u := *a.url // Make a copy of URL
	u.Path = requestPath
	httpReq, err := http.NewRequest("POST", u.String(), bytes.NewReader(p))
	httpReq.Header.Add("Content-Type", "application/x-protobuf")
	httpResp, err := a.client.Do(httpReq)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != 200 {
		return fmt.Errorf("safebrowsing: unexpected server response code: %d", httpResp.StatusCode)
	}
	body, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		return err
	}
	return proto.Unmarshal(body, resp)
}

// ListUpdate issues a FetchThreatListUpdates API call and returns the response.
func (a *netAPI) ListUpdate(req *pb.FetchThreatListUpdatesRequest) (*pb.FetchThreatListUpdatesResponse, error) {
	resp := new(pb.FetchThreatListUpdatesResponse)
	return resp, a.doRequest(fetchUpdatePath, req, resp)
}

// HashLookup issues a FindFullHashes API call and returns the response.
func (a *netAPI) HashLookup(req *pb.FindFullHashesRequest) (*pb.FindFullHashesResponse, error) {
	resp := new(pb.FindFullHashesResponse)
	return resp, a.doRequest(findHashPath, req, resp)
}
