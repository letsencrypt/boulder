// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package wfe

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/square/go-jose"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

type WebFrontEndImpl struct {
	RA    core.RegistrationAuthority
	SA    core.StorageGetter
	CA    core.CertificateAuthority
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
	TermsPath      string
	IssuerPath     string

	// Issuer certificate (DER) for /acme/issuer-cert
	IssuerCert []byte
}

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

func (wfe *WebFrontEndImpl) verifyPOST(request *http.Request) ([]byte, *jose.JsonWebKey, error) {
	// Read body
	if request.Body == nil {
		wfe.log.Debug("No body on POST")
		return nil, nil, errors.New("No body on POST")
	}

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		wfe.log.Debug(fmt.Sprintf("Error reading data from POST: %v", err))
		return nil, nil, err
	}

	// Parse as JWS
	parsedJws, err := jose.ParseSigned(string(body))
	if err != nil {
		wfe.log.Debug(fmt.Sprintf("Parse error reading JWS: %v", err))
		return nil, nil, err
	}

	// Verify JWS
	// NOTE: It might seem insecure for the WFE to be trusted to verify
	// client requests, i.e., that the verification should be done at the
	// RA.  However the WFE is the RA's only view of the outside world
	// *anyway*, so it could always lie about what key was used by faking
	// the signature itself.
	if len(parsedJws.Signatures) > 1 {
		wfe.log.Debug(fmt.Sprintf("Too many signatures on POST"))
		return nil, nil, errors.New("Too many signatures on POST")
	}
	if len(parsedJws.Signatures) == 0 {
		wfe.log.Debug(fmt.Sprintf("POST not signed: %v", parsedJws))
		return nil, nil, errors.New("POST not signed")
	}
	// TODO: Look up key in registrations.
	// https://github.com/letsencrypt/boulder/issues/187
	key := parsedJws.Signatures[0].Header.JsonWebKey
	payload, err := parsedJws.Verify(key)
	if err != nil {
		wfe.log.Debug(string(body))
		wfe.log.Debug(fmt.Sprintf("JWS verification error: %v", err))
		return nil, nil, err
	}

	return []byte(payload), key, nil
}

// The ID is always the last slash-separated token in the path
func parseIDFromPath(path string) string {
	re := regexp.MustCompile("^.*/")
	return re.ReplaceAllString(path, "")
}

// Problem objects represent problem documents, which are
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

func (wfe *WebFrontEndImpl) sendError(response http.ResponseWriter, message string, code int) {
	problem := problem{Detail: message}
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
		problemDoc = []byte("{\"detail\": \"Problem marshalling error message.\"}")
	}
	wfe.log.Debug("Sending error to client: " + string(problemDoc))
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
		wfe.sendError(response, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, key, err := wfe.verifyPOST(request)
	if err != nil {
		wfe.sendError(response, "Unable to read/verify body", http.StatusBadRequest)
		return
	}

	var init, unmarshalled core.Registration
	err = json.Unmarshal(body, &unmarshalled)
	if err != nil {
		wfe.sendError(response, "Error unmarshaling JSON", http.StatusBadRequest)
		return
	}
	init.MergeUpdate(unmarshalled)

	reg, err := wfe.RA.NewRegistration(init, *key)
	if err != nil {
		wfe.sendError(response,
			fmt.Sprintf("Error creating new registration: %+v", err),
			http.StatusInternalServerError)
		return
	}

	regURL := wfe.RegBase + string(reg.ID)
	reg.ID = ""
	responseBody, err := json.Marshal(reg)
	if err != nil {
		wfe.sendError(response, "Error marshaling authz", http.StatusInternalServerError)
		return
	}

	response.Header().Add("Location", regURL)
	response.Header().Set("Content-Type", "application/json")
	response.Header().Add("Link", link(wfe.NewAuthz, "next"))
	if len(wfe.TermsPath) > 0 {
		response.Header().Add("Link", link(wfe.BaseURL+wfe.TermsPath, "terms-of-service"))
	}

	response.WriteHeader(http.StatusCreated)
	response.Write(responseBody)

	// incr reg stat
	wfe.Stats.Inc("Registrations", 1, 1.0)
}

func (wfe *WebFrontEndImpl) NewAuthorization(response http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		wfe.sendError(response, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, key, err := wfe.verifyPOST(request)
	if err != nil {
		wfe.sendError(response, "Unable to read/verify body", http.StatusBadRequest)
		return
	}

	var init core.Authorization
	if err = json.Unmarshal(body, &init); err != nil {
		wfe.sendError(response, "Error unmarshaling JSON", http.StatusBadRequest)
		return
	}

	// Create new authz and return
	authz, err := wfe.RA.NewAuthorization(init, *key)
	if err != nil {
		wfe.sendError(response,
			fmt.Sprintf("Error creating new authz: %+v", err),
			http.StatusInternalServerError)
		return
	}

	// Make a URL for this authz, then blow away the ID before serializing
	authzURL := wfe.AuthzBase + string(authz.ID)
	authz.ID = ""
	responseBody, err := json.Marshal(authz)
	if err != nil {
		wfe.sendError(response, "Error marshaling authz", http.StatusInternalServerError)
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

func (wfe *WebFrontEndImpl) NewCertificate(response http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		wfe.sendError(response, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, key, err := wfe.verifyPOST(request)
	if err != nil {
		wfe.sendError(response, "Unable to read/verify body", http.StatusBadRequest)
		return
	}

	var init core.CertificateRequest
	if err = json.Unmarshal(body, &init); err != nil {
		fmt.Println(err)
		wfe.sendError(response, "Error unmarshaling certificate request", http.StatusBadRequest)
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
	cert, err := wfe.RA.NewCertificate(init, *key)
	if err != nil {
		wfe.sendError(response,
			fmt.Sprintf("Error creating new cert: %+v", err),
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
	response.Header().Add("Link", link(wfe.IssuerPath, "up"))
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
		wfe.sendError(response,
			fmt.Sprintf("Unable to find challenge"),
			http.StatusNotFound)
		return
	}

	switch request.Method {
	default:
		wfe.sendError(response, "Method not allowed", http.StatusMethodNotAllowed)
		return

	case "POST":
		body, key, err := wfe.verifyPOST(request)
		if err != nil {
			wfe.sendError(response, "Unable to read/verify body", http.StatusBadRequest)
			return
		}

		var challengeResponse core.Challenge
		if err = json.Unmarshal(body, &challengeResponse); err != nil {
			wfe.sendError(response, "Error unmarshaling authorization", http.StatusBadRequest)
			return
		}

		// Check that the signing key is the right key
		if !core.KeyDigestEquals(key, authz.Key) {
			wfe.sendError(response, "Signing key does not match key in authorization", http.StatusForbidden)
			return
		}

		// Ask the RA to update this authorization
		updatedAuthz, err := wfe.RA.UpdateAuthorization(authz, challengeIndex, challengeResponse)
		if err != nil {
			wfe.sendError(response, "Unable to update authorization", http.StatusInternalServerError)
			return
		}

		challenge := updatedAuthz.Challenges[challengeIndex]
		// assumption: UpdateAuthorization does not modify order of challenges
		jsonReply, err := json.Marshal(challenge)
		if err != nil {
			wfe.sendError(response, "Failed to marshal challenge", http.StatusInternalServerError)
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
	// Requests to this handler should have a path that leads to a known
	// registration
	id := parseIDFromPath(request.URL.Path)
	reg, err := wfe.SA.GetRegistration(id)
	if err != nil {
		wfe.sendError(response,
			fmt.Sprintf("Unable to find registration: %+v", err),
			http.StatusNotFound)
		return
	}
	reg.ID = id

	switch request.Method {
	default:
		wfe.sendError(response, "Method not allowed", http.StatusMethodNotAllowed)
		return

	case "GET":
		jsonReply, err := json.Marshal(reg)
		if err != nil {
			wfe.sendError(response, "Failed to marshal authz", http.StatusInternalServerError)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusOK)
		response.Write(jsonReply)

	case "POST":
		body, key, err := wfe.verifyPOST(request)
		if err != nil {
			wfe.sendError(response, "Unable to read/verify body", http.StatusBadRequest)
			return
		}

		// Check that the signing key is the right key
		if !core.KeyDigestEquals(key, reg.Key) {
			wfe.sendError(response, "Signing key does not match key in registration", http.StatusForbidden)
			return
		}

		var update core.Registration
		err = json.Unmarshal(body, &update)
		if err != nil {
			wfe.sendError(response, "Error unmarshaling registration", http.StatusBadRequest)
			return
		}

		// Ask the RA to update this authorization
		updatedReg, err := wfe.RA.UpdateRegistration(reg, update)
		if err != nil {
			wfe.sendError(response, "Unable to update registration", http.StatusInternalServerError)
			return
		}

		jsonReply, err := json.Marshal(updatedReg)
		if err != nil {
			wfe.sendError(response, "Failed to marshal authz", http.StatusInternalServerError)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusAccepted)
		response.Write(jsonReply)

	}
}

func (wfe *WebFrontEndImpl) Authorization(response http.ResponseWriter, request *http.Request) {
	// Requests to this handler should have a path that leads to a known authz
	id := parseIDFromPath(request.URL.Path)
	authz, err := wfe.SA.GetAuthorization(id)
	if err != nil {
		wfe.sendError(response,
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
		wfe.sendError(response, "Method not allowed", http.StatusMethodNotAllowed)
		return

	case "GET":
		jsonReply, err := json.Marshal(authz)
		if err != nil {
			wfe.sendError(response, "Failed to marshal authz", http.StatusInternalServerError)
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

func (wfe *WebFrontEndImpl) notFound(response http.ResponseWriter) {
	wfe.sendError(response, "Not found", http.StatusNotFound)
}

func (wfe *WebFrontEndImpl) Certificate(response http.ResponseWriter, request *http.Request) {
	path := request.URL.Path
	switch request.Method {
	default:
		wfe.sendError(response, "Method not allowed", http.StatusMethodNotAllowed)
		return

	case "GET":
		// Certificate paths consist of the CertBase path, plus exactly sixteen hex
		// digits.
		if !strings.HasPrefix(path, wfe.CertPath) {
			wfe.notFound(response)
			return
		}
		serial := path[len(wfe.CertPath):]
		if len(serial) != 16 || !allHex.Match([]byte(serial)) {
			wfe.notFound(response)
			return
		}
		wfe.log.Debug(fmt.Sprintf("Requested certificate ID %s", serial))

		cert, err := wfe.SA.GetCertificateByShortSerial(serial)
		if err != nil {
			wfe.log.Debug(fmt.Sprintf("Not found cert: %v", err))
			wfe.notFound(response)
			return
		}

		// TODO: Content negotiation
		response.Header().Set("Content-Type", "application/pkix-cert")
		response.Header().Add("Link", link(wfe.IssuerPath, "up"))
		response.WriteHeader(http.StatusOK)
		if _, err = response.Write(cert); err != nil {
			wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
		}

	case "POST":
		// TODO: Handle revocation in POST

		// incr revoked cert stat
		wfe.Stats.Inc("RevokedCertificates", 1, 1.0)
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
