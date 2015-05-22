// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package wfe

import (
	"bytes"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/square/go-jose"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

// WebFrontEndImpl represents a Boulder web service and its resources
type WebFrontEndImpl struct {
	RA    core.RegistrationAuthority
	SA    core.StorageGetter
	Stats statsd.Statter
	log   *blog.AuditLogger

	// URL configuration parameters
	BaseURL        string
	NewReg         string
	NewRegPath     string
	RegBase        string
	RegPath        string
	NewAuthz       string
	NewAuthzPath   string
	AuthzBase      string
	AuthzPath      string
	NewCert        string
	NewCertPath    string
	CertBase       string
	CertPath       string
	RevokeCertPath string
	TermsPath      string
	IssuerPath     string

	// Issuer certificate (DER) for /acme/issuer-cert
	IssuerCert []byte

	// URL to the current subscriber agreement (should contain some version identifier)
	SubscriberAgreementURL string
}

// NewWebFrontEndImpl constructs a web service for Boulder
func NewWebFrontEndImpl() WebFrontEndImpl {
	logger := blog.GetAuditLogger()
	logger.Notice("Web Front End Starting")
	return WebFrontEndImpl{
		log:            logger,
		NewRegPath:     "/acme/new-reg",
		RegPath:        "/acme/reg/",
		NewAuthzPath:   "/acme/new-authz",
		AuthzPath:      "/acme/authz/",
		NewCertPath:    "/acme/new-cert",
		CertPath:       "/acme/cert/",
		RevokeCertPath: "/acme/revoke-cert/",
		TermsPath:      "/terms",
		IssuerPath:     "/acme/issuer-cert",
	}
}

func (wfe *WebFrontEndImpl) HandlePaths() {
	wfe.NewReg = wfe.BaseURL + wfe.NewRegPath
	wfe.RegBase = wfe.BaseURL + wfe.RegPath
	wfe.NewAuthz = wfe.BaseURL + wfe.NewAuthzPath
	wfe.AuthzBase = wfe.BaseURL + wfe.AuthzPath
	wfe.NewCert = wfe.BaseURL + wfe.NewCertPath
	wfe.CertBase = wfe.BaseURL + wfe.CertPath

	http.HandleFunc("/", wfe.Index)
	http.HandleFunc(wfe.NewRegPath, wfe.NewRegistration)
	http.HandleFunc(wfe.NewAuthzPath, wfe.NewAuthorization)
	http.HandleFunc(wfe.NewCertPath, wfe.NewCertificate)
	http.HandleFunc(wfe.RegPath, wfe.Registration)
	http.HandleFunc(wfe.AuthzPath, wfe.Authorization)
	http.HandleFunc(wfe.CertPath, wfe.Certificate)
	http.HandleFunc(wfe.RevokeCertPath, wfe.RevokeCertificate)
	http.HandleFunc(wfe.TermsPath, wfe.Terms)
	http.HandleFunc(wfe.IssuerPath, wfe.Issuer)
}

// Method implementations

func (wfe *WebFrontEndImpl) Index(response http.ResponseWriter, request *http.Request) {
	// http://golang.org/pkg/net/http/#example_ServeMux_Handle
	// The "/" pattern matches everything, so we need to check
	// that we're at the root here.
	if request.URL.Path != "/" {
		http.NotFound(response, request)
		return
	}

	tmpl := template.Must(template.New("body").Parse(`<html>
  <body>
    <a href="https://letsencrypt.org/">Let's Encrypt</a> Certificate Authority
    running <a href="https://github.com/letsencrypt/boulder">Boulder</a>,
    a reference <a href="https://letsencrypt.github.io/acme-spec/">ACME</a>
    server implementation. New registration is available at
    <a href="{{.NewReg}}">{{.NewReg}}</a>.
  </body>
</html>
`))
	tmpl.Execute(response, wfe)
	response.Header().Set("Content-Type", "text/html")
}

// The ID is always the last slash-separated token in the path
func parseIDFromPath(path string) string {
	re := regexp.MustCompile("^.*/")
	return re.ReplaceAllString(path, "")
}

// ProblemType objects represent problem documents, which are
// returned with HTTP error responses
// https://tools.ietf.org/html/draft-ietf-appsawg-http-problem-00
type ProblemType string

type problem struct {
	Type   ProblemType `json:"type,omitempty"`
	Detail string      `json:"detail,omitempty"`
}

const (
	MalformedProblem      = ProblemType("urn:acme:error:malformed")
	UnauthorizedProblem   = ProblemType("urn:acme:error:unauthorized")
	ServerInternalProblem = ProblemType("urn:acme:error:serverInternal")
)

func (wfe *WebFrontEndImpl) verifyPOST(request *http.Request, regCheck bool) ([]byte, *jose.JsonWebKey, core.Registration, error) {
	var reg core.Registration

	// Read body
	if request.Body == nil {
		return nil, nil, reg, errors.New("No body on POST")
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		return nil, nil, reg, err
	}

	// Parse as JWS
	parsedJws, err := jose.ParseSigned(string(body))
	if err != nil {
		wfe.log.Debug(fmt.Sprintf("Parse error reading JWS: %v", err))
		return nil, nil, reg, err
	}

	// Verify JWS
	// NOTE: It might seem insecure for the WFE to be trusted to verify
	// client requests, i.e., that the verification should be done at the
	// RA.  However the WFE is the RA's only view of the outside world
	// *anyway*, so it could always lie about what key was used by faking
	// the signature itself.
	if len(parsedJws.Signatures) > 1 {
		wfe.log.Debug(fmt.Sprintf("Too many signatures on POST"))
		return nil, nil, reg, errors.New("Too many signatures on POST")
	}
	if len(parsedJws.Signatures) == 0 {
		wfe.log.Debug(fmt.Sprintf("POST not signed: %v", parsedJws))
		return nil, nil, reg, errors.New("POST not signed")
	}
	// TODO: Look up key in registrations.
	// https://github.com/letsencrypt/boulder/issues/187
	key := parsedJws.Signatures[0].Header.JsonWebKey
	payload, err := parsedJws.Verify(key)
	if err != nil {
		wfe.log.Debug(string(body))
		wfe.log.Debug(fmt.Sprintf("JWS verification error: %v", err))
		return nil, nil, reg, err
	}

	if regCheck {
		// Check that the key is assosiated with an actual account
		reg, err = wfe.SA.GetRegistrationByKey(*key)
		if err != nil {
			return nil, nil, reg, err
		}
	}

	// TODO Return JWS body
	return []byte(payload), key, reg, nil
}

// Notify the client of an error condition and log it for audit purposes.
func (wfe *WebFrontEndImpl) sendError(response http.ResponseWriter, details string, debug interface{}, code int) {
	problem := problem{Detail: details}
	switch code {
	case http.StatusForbidden:
		problem.Type = UnauthorizedProblem
	case http.StatusMethodNotAllowed:
		fallthrough
	case http.StatusNotFound:
		fallthrough
	case http.StatusBadRequest:
		problem.Type = MalformedProblem
	case http.StatusInternalServerError:
		problem.Type = ServerInternalProblem
	}

	problemDoc, err := json.Marshal(problem)
	if err != nil {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		wfe.log.Audit(fmt.Sprintf("Could not marshal error message: %s - %+v", err.Error(), problem))
		problemDoc = []byte("{\"detail\": \"Problem marshalling error message.\"}")
	}

	switch problem.Type {
	case ServerInternalProblem:
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		wfe.log.Audit(fmt.Sprintf("Internal error - %s - %s", details, debug))
	case MalformedProblem:
		// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
		wfe.log.Audit(fmt.Sprintf("Improper HTTP request - %s - %s", details, debug))
	case UnauthorizedProblem:
		// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
		wfe.log.Audit(fmt.Sprintf("Unauthorized HTTP request - %s - %s", details, debug))
	}

	// Paraphrased from
	// https://golang.org/src/net/http/server.go#L1272
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(code)
	response.Write(problemDoc)
}

func link(url, relation string) string {
	return fmt.Sprintf("<%s>;rel=\"%s\"", url, relation)
}

func (wfe *WebFrontEndImpl) NewRegistration(response http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		wfe.sendError(response, "Method not allowed", "", http.StatusMethodNotAllowed)
		return
	}

	body, key, _, err := wfe.verifyPOST(request, false)
	if err != nil {
		wfe.sendError(response, "Unable to read/verify body", err, http.StatusBadRequest)
		return
	}

	var init, unmarshalled core.Registration
	err = json.Unmarshal(body, &unmarshalled)
	if err != nil {
		wfe.sendError(response, "Error unmarshaling JSON", err, http.StatusBadRequest)
		return
	}
	if len(unmarshalled.Agreement) > 0 && unmarshalled.Agreement != wfe.SubscriberAgreementURL {
		wfe.sendError(response, fmt.Sprintf("Provided agreement URL [%s] does not match current agreement URL [%s]", unmarshalled.Agreement, wfe.SubscriberAgreementURL), nil, http.StatusBadRequest)
		return
	}
	init.MergeUpdate(unmarshalled)

	reg, err := wfe.RA.NewRegistration(init, *key)
	if err != nil {
		wfe.sendError(response, "Error creating new registration", err, http.StatusInternalServerError)
		return
	}

	// Use an explicitly typed variable. Otherwise `go vet' incorrectly complains
	// that reg.ID is a string being passed to %d.
	var id int64 = reg.ID
	regURL := fmt.Sprintf("%s%d", wfe.RegBase, id)
	responseBody, err := json.Marshal(reg)
	if err != nil {
		wfe.sendError(response, "Error marshaling authz", err, http.StatusInternalServerError)
		return
	}

	response.Header().Add("Location", regURL)
	response.Header().Set("Content-Type", "application/json")
	response.Header().Add("Link", link(wfe.NewAuthz, "next"))
	if len(wfe.SubscriberAgreementURL) > 0 {
		response.Header().Add("Link", link(wfe.SubscriberAgreementURL, "terms-of-service"))
	}

	response.WriteHeader(http.StatusCreated)
	response.Write(responseBody)

	// incr reg stat
	wfe.Stats.Inc("Registrations", 1, 1.0)
}

func (wfe *WebFrontEndImpl) NewAuthorization(response http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		wfe.sendError(response, "Method not allowed", request.Method, http.StatusMethodNotAllowed)
		return
	}

	body, _, currReg, err := wfe.verifyPOST(request, true)
	if err != nil {
		if err == sql.ErrNoRows {
			wfe.sendError(response, "No registration exists matching provided key", err, http.StatusForbidden)
		} else {
			wfe.sendError(response, "Unable to read/verify body", err, http.StatusBadRequest)
		}
		return
	}
	if currReg.Agreement == "" {
		wfe.sendError(response, "Must agree to subscriber agreement before any further actions", nil, http.StatusForbidden)
		return
	}

	var init core.Authorization
	if err = json.Unmarshal(body, &init); err != nil {
		wfe.sendError(response, "Error unmarshaling JSON", err, http.StatusBadRequest)
		return
	}

	// Create new authz and return
	authz, err := wfe.RA.NewAuthorization(init, currReg.ID)
	if err != nil {
		wfe.sendError(response,
			"Error creating new authz", err,
			http.StatusInternalServerError)
		return
	}

	// Make a URL for this authz, then blow away the ID before serializing
	authzURL := wfe.AuthzBase + string(authz.ID)
	authz.ID = ""
	responseBody, err := json.Marshal(authz)
	if err != nil {
		wfe.sendError(response, "Error marshaling authz", err, http.StatusInternalServerError)
		return
	}

	response.Header().Add("Location", authzURL)
	response.Header().Add("Link", link(wfe.NewCert, "next"))
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusCreated)
	if _, err = response.Write(responseBody); err != nil {
		wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
	}
	// incr pending auth stat (?)
	wfe.Stats.Inc("PendingAuthorizations", 1, 1.0)
}

func (wfe *WebFrontEndImpl) RevokeCertificate(response http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		wfe.sendError(response, "Method not allowed", request.Method, http.StatusMethodNotAllowed)
		return
	}

	// We don't ask verifyPOST to verify there is a correponding registration,
	// because anyone with the right private key can revoke a certificate.
	body, requestKey, _, err := wfe.verifyPOST(request, false)
	if err != nil {
		wfe.sendError(response, "Unable to read/verify body", err, http.StatusBadRequest)
		return
	}

	type RevokeRequest struct {
		CertificateDER core.JsonBuffer `json:"certificate"`
	}
	var revokeRequest RevokeRequest
	if err = json.Unmarshal(body, &revokeRequest); err != nil {
		wfe.log.Debug(fmt.Sprintf("Couldn't unmarshal in revoke request %s", string(body)))
		wfe.sendError(response, "Unable to read/verify body", err, http.StatusBadRequest)
		return
	}
	providedCert, err := x509.ParseCertificate(revokeRequest.CertificateDER)
	if err != nil {
		wfe.log.Debug("Couldn't parse cert in revoke request.")
		wfe.sendError(response, "Unable to read/verify body", err, http.StatusBadRequest)
		return
	}

	serial := core.SerialToString(providedCert.SerialNumber)
	certDER, err := wfe.SA.GetCertificate(serial)
	if err != nil || !bytes.Equal(certDER, revokeRequest.CertificateDER) {
		wfe.sendError(response, "No such certificate", err, http.StatusNotFound)
		return
	}
	parsedCertificate, err := x509.ParseCertificate(certDER)
	if err != nil {
		wfe.sendError(response, "Invalid certificate", err, http.StatusInternalServerError)
		return
	}

	certStatus, err := wfe.SA.GetCertificateStatus(serial)
	if err != nil {
		wfe.sendError(response, "No such certificate", err, http.StatusNotFound)
		return
	}

	if certStatus.Status == core.OCSPStatusRevoked {
		wfe.sendError(response, "Certificate already revoked", "", http.StatusConflict)
		return
	}

	// TODO: Implement other methods of validating revocation, e.g. through
	// authorizations on account.
	if !core.KeyDigestEquals(requestKey, parsedCertificate.PublicKey) {
		wfe.log.Debug("Key mismatch for revoke")
		wfe.sendError(response,
			"Revocation request must be signed by private key of cert to be revoked",
			requestKey,
			http.StatusForbidden)
		return
	}

	err = wfe.RA.RevokeCertificate(*parsedCertificate)
	if err != nil {
		wfe.sendError(response,
			"Failed to revoke certificate",
			err,
			http.StatusInternalServerError)
	} else {
		wfe.log.Debug(fmt.Sprintf("Revoked %v", serial))
		// incr revoked cert stat
		wfe.Stats.Inc("RevokedCertificates", 1, 1.0)
		response.WriteHeader(http.StatusOK)
	}
}

func (wfe *WebFrontEndImpl) NewCertificate(response http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		wfe.sendError(response, "Method not allowed", request.Method, http.StatusMethodNotAllowed)
		return
	}

	body, key, reg, err := wfe.verifyPOST(request, true)
	if err != nil {
		if err == sql.ErrNoRows {
			wfe.sendError(response, "No registration exists matching provided key", err, http.StatusForbidden)
		} else {
			wfe.sendError(response, "Unable to read/verify body", err, http.StatusBadRequest)
		}
		return
	}
	if reg.Agreement == "" {
		wfe.sendError(response, "Must agree to subscriber agreement before any further actions", nil, http.StatusForbidden)
		return
	}

	var init core.CertificateRequest
	if err = json.Unmarshal(body, &init); err != nil {
		fmt.Println(err)
		wfe.sendError(response, "Error unmarshaling certificate request", err, http.StatusBadRequest)
		return
	}

	wfe.log.Notice(fmt.Sprintf("Client requested new certificate: %v %v %v",
		request.RemoteAddr, init, key))

	// Create new certificate and return
	// TODO IMPORTANT: The RA trusts the WFE to provide the correct key. If the
	// WFE is compromised, *and* the attacker knows the public key of an account
	// authorized for target site, they could cause issuance for that site by
	// lying to the RA. We should probably pass a copy of the whole rquest to the
	// RA for secondary validation.
	cert, err := wfe.RA.NewCertificate(init, reg.ID)
	if err != nil {
		wfe.sendError(response,
			"Error creating new cert", err,
			http.StatusBadRequest)
		return
	}

	// Make a URL for this certificate.
	// We use only the sequential part of the serial number, because it should
	// uniquely identify the certificate, and this makes it easy for anybody to
	// enumerate and mirror our certificates.
	serial := cert.ParsedCertificate.SerialNumber
	certURL := fmt.Sprintf("%s%016x", wfe.CertBase, serial.Rsh(serial, 64))

	// TODO The spec says a client should send an Accept: application/pkix-cert
	// header; either explicitly insist or tolerate
	response.Header().Add("Location", certURL)
	response.Header().Add("Link", link(wfe.BaseURL+wfe.IssuerPath, "up"))
	response.Header().Set("Content-Type", "application/pkix-cert")
	response.WriteHeader(http.StatusCreated)
	if _, err = response.Write(cert.DER); err != nil {
		wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
	}
	// incr cert stat
	wfe.Stats.Inc("Certificates", 1, 1.0)
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
		wfe.sendError(response, "Unable to find challenge", request.URL.RawQuery, http.StatusNotFound)
		return
	}

	switch request.Method {
	default:
		wfe.sendError(response, "Method not allowed", "", http.StatusMethodNotAllowed)
		return

	case "POST":
		body, _, currReg, err := wfe.verifyPOST(request, true)
		if err != nil {
			if err == sql.ErrNoRows {
				wfe.sendError(response, "No registration exists matching provided key", err, http.StatusForbidden)
			} else {
				wfe.sendError(response, "Unable to read/verify body", err, http.StatusBadRequest)
			}
			return
		}
		if currReg.Agreement == "" {
			wfe.sendError(response, "Must agree to subscriber agreement before any further actions", nil, http.StatusForbidden)
			return
		}

		var challengeResponse core.Challenge
		if err = json.Unmarshal(body, &challengeResponse); err != nil {
			wfe.sendError(response, "Error unmarshaling authorization", err, http.StatusBadRequest)
			return
		}

		// Check that the registration ID matching the key used matches
		// the registration ID on the authz object
		if currReg.ID != authz.RegistrationID {
			wfe.sendError(response, "User registration ID doesn't match registration ID in authorization",
				fmt.Sprintf("User: %v != Authorization: %v", currReg.ID, authz.RegistrationID),
				http.StatusForbidden)
			return
		}

		// Ask the RA to update this authorization
		updatedAuthz, err := wfe.RA.UpdateAuthorization(authz, challengeIndex, challengeResponse)
		if err != nil {
			wfe.sendError(response, "Unable to update authorization", err, http.StatusInternalServerError)
			return
		}

		challenge := updatedAuthz.Challenges[challengeIndex]
		// assumption: UpdateAuthorization does not modify order of challenges
		jsonReply, err := json.Marshal(challenge)
		if err != nil {
			wfe.sendError(response, "Failed to marshal authz", err, http.StatusInternalServerError)
			return
		}

		authzURL := wfe.AuthzBase + string(authz.ID)
		challengeURL := url.URL(challenge.URI)
		response.Header().Add("Location", challengeURL.String())
		response.Header().Set("Content-Type", "application/json")
		response.Header().Add("Link", link(authzURL, "up"))
		response.WriteHeader(http.StatusAccepted)
		if _, err = response.Write(jsonReply); err != nil {
			wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
		}

	}
}

func (wfe *WebFrontEndImpl) Registration(response http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		wfe.sendError(response, "Method not allowed", request.Method, http.StatusMethodNotAllowed)
		return
	}

	body, _, currReg, err := wfe.verifyPOST(request, true)
	if err != nil {
		if err == sql.ErrNoRows {
			wfe.sendError(response,
				"No registration exists matching provided key",
				err, http.StatusForbidden)
		} else {
			wfe.sendError(response,
				"Unable to read/verify body", err, http.StatusBadRequest)
		}
		return
	}

	// Requests to this handler should have a path that leads to a known
	// registration
	idStr := parseIDFromPath(request.URL.Path)
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		wfe.sendError(response, "Registration ID must be an integer", err, http.StatusBadRequest)
		return
	} else if id <= 0 {
		wfe.sendError(response, "Registration ID must be a positive non-zero integer", id, http.StatusBadRequest)
		return
	} else if id != currReg.ID {
		wfe.sendError(response, "Request signing key did not match registration key", "", http.StatusForbidden)
		return
	}

	var update core.Registration
	err = json.Unmarshal(body, &update)
	if err != nil {
		wfe.sendError(response, "Error unmarshaling registration", err, http.StatusBadRequest)
		return
	}

	if len(update.Agreement) > 0 && update.Agreement != wfe.SubscriberAgreementURL {
		wfe.sendError(response,
			fmt.Sprintf("Provided agreement URL [%s] does not match current agreement URL [%s]",
				update.Agreement, wfe.SubscriberAgreementURL), nil, http.StatusBadRequest)
		return
	}

	// MergeUpdate copies over only the fields that a client is allowed to modify.
	// Note: The RA will also use MergeUpdate to filter out non-updateable fields,
	// but we do it here too, so that/ input filtering happens as early in the
	// request processing as possible.
	currReg.MergeUpdate(update)
	// Ask the RA to update this authorization.
	updatedReg, err := wfe.RA.UpdateRegistration(currReg, currReg)
	if err != nil {
		wfe.sendError(response, "Unable to update registration", err, http.StatusInternalServerError)
		return
	}

	jsonReply, err := json.Marshal(updatedReg)
	if err != nil {
		wfe.sendError(response, "Failed to marshal authz", err, http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusAccepted)
	response.Write(jsonReply)
}

func (wfe *WebFrontEndImpl) Authorization(response http.ResponseWriter, request *http.Request) {
	// Requests to this handler should have a path that leads to a known authz
	id := parseIDFromPath(request.URL.Path)
	authz, err := wfe.SA.GetAuthorization(id)
	if err != nil {
		wfe.sendError(response,
			"Unable to find authorization", err,
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
		wfe.sendError(response, "Method not allowed", request.Method, http.StatusMethodNotAllowed)
		return

	case "GET":
		jsonReply, err := json.Marshal(authz)
		if err != nil {
			wfe.sendError(response, "Failed to marshal authz", err, http.StatusInternalServerError)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusOK)
		if _, err = response.Write(jsonReply); err != nil {
			wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
		}
	}
}

var allHex = regexp.MustCompile("^[0-9a-f]+$")

func (wfe *WebFrontEndImpl) Certificate(response http.ResponseWriter, request *http.Request) {
	path := request.URL.Path
	switch request.Method {
	default:
		wfe.sendError(response, "Method not allowed", request.Method, http.StatusMethodNotAllowed)
		return

	case "GET":
		// Certificate paths consist of the CertBase path, plus exactly sixteen hex
		// digits.
		if !strings.HasPrefix(path, wfe.CertPath) {
			wfe.sendError(response, "Not found", path, http.StatusNotFound)
			return
		}
		serial := path[len(wfe.CertPath):]
		if len(serial) != 16 || !allHex.Match([]byte(serial)) {
			wfe.sendError(response, "Not found", serial, http.StatusNotFound)
			return
		}
		wfe.log.Debug(fmt.Sprintf("Requested certificate ID %s", serial))

		cert, err := wfe.SA.GetCertificateByShortSerial(serial)
		if err != nil {
			wfe.sendError(response, "Not found", err, http.StatusNotFound)
			return
		}

		// TODO: Content negotiation
		response.Header().Set("Content-Type", "application/pkix-cert")
		response.Header().Add("Link", link(wfe.IssuerPath, "up"))
		response.WriteHeader(http.StatusOK)
		if _, err = response.Write(cert); err != nil {
			wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
		}
	}
}

func (wfe *WebFrontEndImpl) Terms(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "You agree to do the right thing")
}

func (wfe *WebFrontEndImpl) Issuer(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/pkix-cert")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(wfe.IssuerCert); err != nil {
		wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
	}
}
