// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package anvil

import (
	"encoding/json"
	"fmt"
	"github.com/bifurcation/gose"
	"io/ioutil"
	"net/http"
	"regexp"
)

type WebFrontEndImpl struct {
	RA RegistrationAuthority
	SA StorageGetter

	// URL configuration parameters
	baseURL   string
	authzBase string
	certBase  string
}

func NewWebFrontEndImpl() WebFrontEndImpl {
	return WebFrontEndImpl{}
}

// Method implementations

func verifyPOST(request *http.Request) ([]byte, jose.JsonWebKey, error) {
	zero := []byte{}
	zeroKey := jose.JsonWebKey{}

	// Read body
	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		return zero, zeroKey, err
	}

	// Parse as JWS
	var jws jose.JsonWebSignature
	err = json.Unmarshal(body, &jws)
	if err != nil {
		return zero, zeroKey, err
	}

	// Verify JWS
	// NOTE: It might seem insecure for the WFE to be trusted to verify
	// client requests, i.e., that the verification should be done at the
	// RA.  However the WFE is the RA's only view of the outside world
	// *anyway*, so it could always lie about what key was used by faking
	// the signature itself.
	err = jws.Verify()
	if err != nil {
		return zero, zeroKey, err
	}

	// TODO Return JWS body
	return []byte(jws.Payload), jws.Header.Key, nil
}

// The ID is always the last slash-separated token in the path
func parseIDFromPath(path string) string {
	re := regexp.MustCompile("^.*/")
	return re.ReplaceAllString(path, "")
}

// Problem objects represent problem documents, which are
// returned with HTTP error responses
// https://tools.ietf.org/html/draft-ietf-appsawg-http-problem-00
type problem struct {
	Type     string `json:"type,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
}

func sendError(response http.ResponseWriter, message string, code int) {
	problem := problem{Detail: message}
	problemDoc, err := json.Marshal(problem)
	if err != nil {
		return
	}
	http.Error(response, string(problemDoc), code)
}

func (wfe *WebFrontEndImpl) SetAuthzBase(base string) {
	wfe.authzBase = base
}

func (wfe *WebFrontEndImpl) SetCertBase(base string) {
	wfe.certBase = base
}

func (wfe *WebFrontEndImpl) NewAuthz(response http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		sendError(response, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, key, err := verifyPOST(request)
	if err != nil {
		sendError(response, "Unable to read body", http.StatusBadRequest)
		return
	}

	var init Authorization
	err = json.Unmarshal(body, &init)
	if err != nil {
		sendError(response, "Error unmarshaling JSON", http.StatusBadRequest)
		return
	}

	// TODO: Create new authz and return
	authz, err := wfe.RA.NewAuthorization(init, key)
	if err != nil {
		sendError(response,
			fmt.Sprintf("Error creating new authz: %+v", err),
			http.StatusInternalServerError)
		return
	}

	// Make a URL for this authz, then blow away the ID before serializing
	authzURL := wfe.authzBase + string(authz.ID)
	authz.ID = ""
	responseBody, err := json.Marshal(authz)
	if err != nil {
		sendError(response, "Error marshaling authz", http.StatusInternalServerError)
		return
	}

	response.Header().Add("Location", authzURL)
	response.WriteHeader(http.StatusCreated)
	response.Write(responseBody)
}

func (wfe *WebFrontEndImpl) NewCert(response http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		sendError(response, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, key, err := verifyPOST(request)
	if err != nil {
		sendError(response, "Unable to read body", http.StatusBadRequest)
		return
	}

	var init CertificateRequest
	err = json.Unmarshal(body, &init)
	if err != nil {
		sendError(response, "Error unmarshaling certificate request", http.StatusBadRequest)
		return
	}

	// Create new certificate and return
	cert, err := wfe.RA.NewCertificate(init, key)
	if err != nil {
		sendError(response,
			fmt.Sprintf("Error creating new cert: %+v", err),
			http.StatusBadRequest)
		return
	}

	// Make a URL for this authz
	certURL := wfe.certBase + string(cert.ID)

	// TODO: Content negotiation for cert format
	response.Header().Add("Location", certURL)
	response.WriteHeader(http.StatusCreated)
	response.Write(cert.DER)
}

func (wfe *WebFrontEndImpl) Authz(response http.ResponseWriter, request *http.Request) {
	// Requests to this handler should have a path that leads to a known authz
	id := parseIDFromPath(request.URL.Path)
	obj, err := wfe.SA.Get(id)
	if err != nil {
		sendError(response,
			fmt.Sprintf("Unable to find authorization: %+v", err),
			http.StatusNotFound)
		return
	}
	authz := obj.(Authorization)

	switch request.Method {
	default:
		sendError(response, "Method not allowed", http.StatusMethodNotAllowed)
		return

	case "POST":
		body, key, err := verifyPOST(request)
		if err != nil {
			sendError(response, "Unable to read body", http.StatusBadRequest)
			return
		}

		var initialAuthz Authorization
		err = json.Unmarshal(body, &initialAuthz)
		if err != nil {
			sendError(response, "Error unmarshaling authorization", http.StatusBadRequest)
			return
		}

		// Check that the signing key is the right key
		if !key.Equals(authz.Key) {
			fmt.Printf("req:   %+v\n", key)
			fmt.Printf("authz: %+v\n", authz.Key)
			sendError(response, "Signing key does not match key in authorization", http.StatusForbidden)
			return
		}

		// Ask the RA to update this authorization
		initialAuthz.ID = authz.ID
		updatedAuthz, err := wfe.RA.UpdateAuthorization(initialAuthz)
		if err != nil {
			sendError(response, "Unable to update authorization", http.StatusInternalServerError)
			return
		}

		jsonReply, err := json.Marshal(updatedAuthz)
		if err != nil {
			sendError(response, "Failed to marshal authz", http.StatusInternalServerError)
			return
		}
		response.WriteHeader(http.StatusAccepted)
		response.Write(jsonReply)

	case "GET":
		jsonReply, err := json.Marshal(authz)
		if err != nil {
			sendError(response, "Failed to marshal authz", http.StatusInternalServerError)
			return
		}
		response.WriteHeader(http.StatusOK)
		response.Write(jsonReply)
	}
}

func (wfe *WebFrontEndImpl) Cert(response http.ResponseWriter, request *http.Request) {
	switch request.Method {
	default:
		sendError(response, "Method not allowed", http.StatusMethodNotAllowed)
		return

	case "GET":
		id := parseIDFromPath(request.URL.Path)
		obj, err := wfe.SA.Get(id)
		if err != nil {
			sendError(response, "Not found", http.StatusNotFound)
			return
		}
		cert := obj.(Certificate)

		// TODO: Content negotiation
		// TODO: Link header
		jsonReply, err := json.Marshal(cert)
		if err != nil {
			sendError(response, "Failed to marshal cert", http.StatusInternalServerError)
			return
		}
		response.WriteHeader(http.StatusOK)
		response.Write(jsonReply)

	case "POST":
		// TODO: Handle revocation in POST
	}
}
