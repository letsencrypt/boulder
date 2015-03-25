// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package wfe

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/jose"
	blog "github.com/letsencrypt/boulder/log"
)

type WebFrontEndImpl struct {
	RA  core.RegistrationAuthority
	SA  core.StorageGetter
	log *blog.AuditLogger

	// URL configuration parameters
	NewReg    string
	RegBase   string
	NewAuthz  string
	AuthzBase string
	NewCert   string
	CertBase  string

	SubscriberAgreementURL string
}

func NewWebFrontEndImpl(logger *blog.AuditLogger) WebFrontEndImpl {
	logger.Notice("Web Front End Starting")
	return WebFrontEndImpl{log: logger}
}

// Method implementations

func verifyPOST(request *http.Request) ([]byte, jose.JsonWebKey, error) {
	zeroKey := jose.JsonWebKey{}

	// Read body
	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		return nil, zeroKey, err
	}

	// Parse as JWS
	var jws jose.JsonWebSignature
	if err = json.Unmarshal(body, &jws); err != nil {
		return nil, zeroKey, err
	}

	// Verify JWS
	// NOTE: It might seem insecure for the WFE to be trusted to verify
	// client requests, i.e., that the verification should be done at the
	// RA.  However the WFE is the RA's only view of the outside world
	// *anyway*, so it could always lie about what key was used by faking
	// the signature itself.
	if err = jws.Verify(); err != nil {
		return nil, zeroKey, err
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
	response.Header().Add("Content-Type", "application/problem+json")
	w.WriteHeader(code)
	fmt
}

func link(url, relation string) string {
	return fmt.Sprintf("<%s>;rel=\"%s\"", url, relation)
}

func (wfe *WebFrontEndImpl) NewRegistration(response http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		sendError(response, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, key, err := verifyPOST(request)
	if err != nil {
		sendError(response, fmt.Sprintf("Unable to read/verify body: %v", err), http.StatusBadRequest)
		return
	}

	var init core.Registration
	err = json.Unmarshal(body, &init)
	if err != nil {
		sendError(response, "Error unmarshaling JSON", http.StatusBadRequest)
		return
	}

	reg, err := wfe.RA.NewRegistration(init, key)
	if err != nil {
		sendError(response,
			fmt.Sprintf("Error creating new registration: %+v", err),
			http.StatusInternalServerError)
	}

	regURL := wfe.RegBase + string(reg.ID)
	reg.ID = ""
	responseBody, err := json.Marshal(reg)
	if err != nil {
		sendError(response, "Error marshaling authz", http.StatusInternalServerError)
		return
	}

	response.Header().Add("Location", regURL)
	response.Header().Add("Content-Type", "application/json")
	response.Header().Add("Link", link(wfe.NewAuthz, "next"))
	if len(wfe.SubscriberAgreementURL) > 0 {
		response.Header().Add("Link", link(wfe.SubscriberAgreementURL, "terms-of-service"))
	}

	response.WriteHeader(http.StatusCreated)
	response.Write(responseBody)
}

func (wfe *WebFrontEndImpl) NewAuthorization(response http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		sendError(response, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, key, err := verifyPOST(request)
	if err != nil {
		sendError(response, "Unable to read/verify body", http.StatusBadRequest)
		return
	}

	var init core.Authorization
	if err = json.Unmarshal(body, &init); err != nil {
		sendError(response, "Error unmarshaling JSON", http.StatusBadRequest)
		return
	}

	// Create new authz and return
	authz, err := wfe.RA.NewAuthorization(init, key)
	if err != nil {
		sendError(response,
			fmt.Sprintf("Error creating new authz: %+v", err),
			http.StatusInternalServerError)
		return
	}

	// Make a URL for this authz, then blow away the ID before serializing
	authzURL := wfe.AuthzBase + string(authz.ID)
	authz.ID = ""
	responseBody, err := json.Marshal(authz)
	if err != nil {
		sendError(response, "Error marshaling authz", http.StatusInternalServerError)
		return
	}

	response.Header().Add("Location", authzURL)
	response.Header().Add("Link", link(wfe.NewCert, "next"))
	response.Header().Add("Content-Type", "application/json")
	response.WriteHeader(http.StatusCreated)
	if _, err = response.Write(responseBody); err != nil {
		wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
	}
}

func (wfe *WebFrontEndImpl) NewCertificate(response http.ResponseWriter, request *http.Request) {

	if request.Method != "POST" {
		sendError(response, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, key, err := verifyPOST(request)
	if err != nil {
		sendError(response, "Unable to read/verify body", http.StatusBadRequest)
		return
	}

	var init core.CertificateRequest
	if err = json.Unmarshal(body, &init); err != nil {
		sendError(response, "Error unmarshaling certificate request", http.StatusBadRequest)
		return
	}

	wfe.log.Notice(fmt.Sprintf("Asked to create new certificate: %v %v", init, key))

	// Create new certificate and return
	cert, err := wfe.RA.NewCertificate(init, key)
	if err != nil {
		sendError(response,
			fmt.Sprintf("Error creating new cert: %+v", err),
			http.StatusBadRequest)
		return
	}

	// Make a URL for this authz
	certURL := wfe.CertBase + string(cert.ID)

	// TODO The spec says this should 201 over to /cert, not reply with the
	// certificate at this point... fix will need to land in boulder and client
	// simultaneously.
	// TODO The spec says a client should send an Accept: application/pkix-cert
	// header; either explicitly insist or tolerate

	response.Header().Add("Location", certURL)
	response.Header().Add("Content-Type", "application/pkix-cert")
	response.WriteHeader(http.StatusCreated)
	if _, err = response.Write(cert.DER); err != nil {
		wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
	}
}

func (wfe *WebFrontEndImpl) Challenge(authz core.Authorization, response http.ResponseWriter, request *http.Request) {
	// Check that the requested challenge exists within the authorization
	found := false
	var challengeIndex int
	for i, challenge := range authz.Challenges {
		tempURL := url.URL(challenge.URI)
		if tempURL.Path == request.URL.Path && tempURL.RawQuery == request.URL.RawQuery {
			found = true
			challengeIndex = i
			break
		}
	}

	if !found {
		sendError(response,
			fmt.Sprintf("Unable to find challenge"),
			http.StatusNotFound)
		return
	}

	switch request.Method {
	default:
		sendError(response, "Method not allowed", http.StatusMethodNotAllowed)
		return

	case "POST":
		body, key, err := verifyPOST(request)
		if err != nil {
			sendError(response, "Unable to read/verify body", http.StatusBadRequest)
			return
		}

		var challengeResponse core.Challenge
		if err = json.Unmarshal(body, &challengeResponse); err != nil {
			sendError(response, "Error unmarshaling authorization", http.StatusBadRequest)
			return
		}

		// Check that the signing key is the right key
		if !key.Equals(authz.Key) {
			sendError(response, "Signing key does not match key in authorization", http.StatusForbidden)
			return
		}

		// Ask the RA to update this authorization
		updatedAuthz, err := wfe.RA.UpdateAuthorization(authz, challengeIndex, challengeResponse)
		if err != nil {
			sendError(response, "Unable to update authorization", http.StatusInternalServerError)
			return
		}

		jsonReply, err := json.Marshal(updatedAuthz)
		if err != nil {
			sendError(response, "Failed to marshal authz", http.StatusInternalServerError)
			return
		}
		response.Header().Add("Content-Type", "application/json")
		response.WriteHeader(http.StatusAccepted)
		if _, err = response.Write(jsonReply); err != nil {
			wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
		}

	}
}

func (wfe *WebFrontEndImpl) Registration(response http.ResponseWriter, request *http.Request) {
	// Requests to this handler should have a path that leads to a known authz
	id := parseIDFromPath(request.URL.Path)
	reg, err := wfe.SA.GetRegistration(id)
	if err != nil {
		sendError(response,
			fmt.Sprintf("Unable to find registration: %+v", err),
			http.StatusNotFound)
		return
	}
	reg.ID = id

	switch request.Method {
	default:
		sendError(response, "Method not allowed", http.StatusMethodNotAllowed)
		return

	case "GET":
		jsonReply, err := json.Marshal(reg)
		if err != nil {
			sendError(response, "Failed to marshal authz", http.StatusInternalServerError)
			return
		}
		response.Header().Add("Content-Type", "application/json")
		response.WriteHeader(http.StatusOK)
		response.Write(jsonReply)

	case "POST":
		body, key, err := verifyPOST(request)
		if err != nil {
			sendError(response, "Unable to read/verify body", http.StatusBadRequest)
			return
		}

		var update core.Registration
		err = json.Unmarshal(body, &update)
		if err != nil {
			sendError(response, "Error unmarshaling registration", http.StatusBadRequest)
			return
		}

		// Check that the signing key is the right key
		if !key.Equals(reg.Key) {
			sendError(response, "Signing key does not match key in registration", http.StatusForbidden)
			return
		}

		// Ask the RA to update this authorization
		updatedReg, err := wfe.RA.UpdateRegistration(reg, update)
		if err != nil {
			fmt.Println(err)
			sendError(response, "Unable to update registration", http.StatusInternalServerError)
			return
		}

		jsonReply, err := json.Marshal(updatedReg)
		if err != nil {
			sendError(response, "Failed to marshal authz", http.StatusInternalServerError)
			return
		}
		response.Header().Add("Content-Type", "application/json")
		response.WriteHeader(http.StatusAccepted)
		response.Write(jsonReply)

	}
}

func (wfe *WebFrontEndImpl) Authorization(response http.ResponseWriter, request *http.Request) {
	// Requests to this handler should have a path that leads to a known authz
	id := parseIDFromPath(request.URL.Path)
	authz, err := wfe.SA.GetAuthorization(id)
	if err != nil {
		sendError(response,
			fmt.Sprintf("Unable to find authorization: %+v", err),
			http.StatusNotFound)
		return
	}

	// If there is a fragment, then this is actually a request to a challenge URI
	if len(request.URL.RawQuery) != 0 {
		wfe.Challenge(authz, response, request)
		return
	}

	switch request.Method {
	default:
		sendError(response, "Method not allowed", http.StatusMethodNotAllowed)
		return

	case "GET":
		jsonReply, err := json.Marshal(authz)
		if err != nil {
			sendError(response, "Failed to marshal authz", http.StatusInternalServerError)
			return
		}
		response.Header().Add("Content-Type", "application/json")
		response.WriteHeader(http.StatusOK)
		if _, err = response.Write(jsonReply); err != nil {
			wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
		}
	}
}

func (wfe *WebFrontEndImpl) Certificate(response http.ResponseWriter, request *http.Request) {
	switch request.Method {
	default:
		sendError(response, "Method not allowed", http.StatusMethodNotAllowed)
		return

	case "GET":
		id := parseIDFromPath(request.URL.Path)
		wfe.log.Notice(fmt.Sprintf("Requested certificate ID %s", id))

		cert, err := wfe.SA.GetCertificate(id)
		if err != nil {
			sendError(response, "Not found", http.StatusNotFound)
			return
		}

		// TODO: Content negotiation
		// TODO: Link header
		response.Header().Add("Content-Type", "application/pkix-cert")
		response.WriteHeader(http.StatusOK)
		if _, err = response.Write(cert); err != nil {
			wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
		}

	case "POST":
		// TODO: Handle revocation in POST
	}
}
