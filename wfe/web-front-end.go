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
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

// Paths are the ACME-spec identified URL path-segments for various methods
const (
	DirectoryPath  = "/directory"
	NewRegPath     = "/acme/new-reg"
	RegPath        = "/acme/reg/"
	NewAuthzPath   = "/acme/new-authz"
	AuthzPath      = "/acme/authz/"
	NewCertPath    = "/acme/new-cert"
	CertPath       = "/acme/cert/"
	RevokeCertPath = "/acme/revoke-cert"
	TermsPath      = "/terms"
	IssuerPath     = "/acme/issuer-cert"
	BuildIDPath    = "/build"
)

type WebFrontEndImpl struct {
	RA    core.RegistrationAuthority
	SA    core.StorageGetter
	Stats statsd.Statter
	log   *blog.AuditLogger

	// URL configuration parameters
	BaseURL   string
	NewReg    string
	RegBase   string
	NewAuthz  string
	AuthzBase string
	NewCert   string
	CertBase  string

	// JSON encoded endpoint directory
	DirectoryJSON []byte

	// Issuer certificate (DER) for /acme/issuer-cert
	IssuerCert []byte

	// URL to the current subscriber agreement (should contain some version identifier)
	SubscriberAgreementURL string

	// Register of anti-replay nonces
	nonceService core.NonceService

	// Cache settings
	CertCacheDuration           time.Duration
	CertNoCacheExpirationWindow time.Duration
	IndexCacheDuration          time.Duration
	IssuerCacheDuration         time.Duration
}

func statusCodeFromError(err interface{}) int {
	// Populate these as needed.  We probably should trim the error list in util.go
	switch err.(type) {
	case core.MalformedRequestError:
		return http.StatusBadRequest
	case core.NotSupportedError:
		return http.StatusNotImplemented
	case core.SyntaxError:
		return http.StatusBadRequest
	case core.UnauthorizedError:
		return http.StatusForbidden
	case core.NotFoundError:
		return http.StatusNotFound
	case core.SignatureValidationError:
		return http.StatusPreconditionFailed
	case core.InternalServerError:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

type requestEvent struct {
	ID           string          `json:",omitempty"`
	RealIP       string          `json:",omitempty"`
	ForwardedFor string          `json:",omitempty"`
	Endpoint     string          `json:",omitempty"`
	Method       string          `json:",omitempty"`
	RequestTime  time.Time       `json:",omitempty"`
	ResponseTime time.Time       `json:",omitempty"`
	Error        string          `json:",omitempty"`
	Requester    int64           `json:",omitempty"`
	Contacts     []*core.AcmeURL `json:",omitempty"`

	Extra map[string]interface{} `json:",omitempty"`
}

// NewWebFrontEndImpl constructs a web service for Boulder
func NewWebFrontEndImpl() (WebFrontEndImpl, error) {
	logger := blog.GetAuditLogger()
	logger.Notice("Web Front End Starting")

	nonceService, err := core.NewNonceService()
	if err != nil {
		return WebFrontEndImpl{}, err
	}

	return WebFrontEndImpl{
		log:          logger,
		nonceService: nonceService,
	}, nil
}

// BodylessResponseWriter wraps http.ResponseWriter, discarding
// anything written to the body.
type BodylessResponseWriter struct {
	http.ResponseWriter
}

func (mrw BodylessResponseWriter) Write(buf []byte) (int, error) {
	return len(buf), nil
}

// HandleFunc registers a handler at the given path. It's
// http.HandleFunc(), but with a wrapper around the handler that
// provides some generic per-request functionality:
//
// * Set a Replay-Nonce header.
//
// * Respond http.StatusMethodNotAllowed for HTTP methods other than
//   those listed.
//
// * Never send a body in response to a HEAD request. (Anything
//   written by the handler will be discarded if the method is HEAD.)
func (wfe *WebFrontEndImpl) HandleFunc(mux *http.ServeMux, pattern string, h func(http.ResponseWriter, *http.Request), methods ...string) {
	methodsOK := make(map[string]bool)
	for _, m := range methods {
		methodsOK[m] = true
	}
	mux.HandleFunc(pattern, func(response http.ResponseWriter, request *http.Request) {
		// We do not propagate errors here, because (1) they should be
		// transient, and (2) they fail closed.
		nonce, err := wfe.nonceService.Nonce()
		if err == nil {
			response.Header().Set("Replay-Nonce", nonce)
		}
		response.Header().Set("Access-Control-Allow-Origin", "*")

		switch request.Method {
		case "HEAD":
			// We'll be sending an error anyway, but we
			// should still comply with HTTP spec by not
			// sending a body.
			response = BodylessResponseWriter{response}
		case "OPTIONS":
			// TODO, #469
		}

		if _, ok := methodsOK[request.Method]; !ok {
			logEvent := wfe.populateRequestEvent(request)
			defer wfe.logRequestDetails(&logEvent)
			logEvent.Error = "Method not allowed"
			response.Header().Set("Allow", strings.Join(methods, ", "))
			wfe.sendError(response, logEvent.Error, request.Method, http.StatusMethodNotAllowed)
			return
		}

		// Call the wrapped handler.
		h(response, request)
	})
}

// Handler returns an http.Handler that uses various functions for
// various ACME-specified paths.
func (wfe *WebFrontEndImpl) Handler() (http.Handler, error) {
	wfe.NewReg = wfe.BaseURL + NewRegPath
	wfe.RegBase = wfe.BaseURL + RegPath
	wfe.NewAuthz = wfe.BaseURL + NewAuthzPath
	wfe.AuthzBase = wfe.BaseURL + AuthzPath
	wfe.NewCert = wfe.BaseURL + NewCertPath
	wfe.CertBase = wfe.BaseURL + CertPath

	// Only generate directory once
	directory := map[string]string{
		"new-reg":     wfe.NewReg,
		"new-authz":   wfe.NewAuthz,
		"new-cert":    wfe.NewCert,
		"revoke-cert": wfe.BaseURL + RevokeCertPath,
	}
	directoryJSON, err := json.Marshal(directory)
	if err != nil {
		return nil, err
	}
	wfe.DirectoryJSON = directoryJSON

	m := http.NewServeMux()
	wfe.HandleFunc(m, "/", wfe.Index, "GET")
	wfe.HandleFunc(m, DirectoryPath, wfe.Directory, "GET")
	wfe.HandleFunc(m, NewRegPath, wfe.NewRegistration, "POST")
	wfe.HandleFunc(m, NewAuthzPath, wfe.NewAuthorization, "POST")
	wfe.HandleFunc(m, NewCertPath, wfe.NewCertificate, "POST")
	wfe.HandleFunc(m, RegPath, wfe.Registration, "POST")
	wfe.HandleFunc(m, AuthzPath, wfe.Authorization, "GET", "POST")
	wfe.HandleFunc(m, CertPath, wfe.Certificate, "GET")
	wfe.HandleFunc(m, RevokeCertPath, wfe.RevokeCertificate, "POST")
	wfe.HandleFunc(m, TermsPath, wfe.Terms, "GET")
	wfe.HandleFunc(m, IssuerPath, wfe.Issuer, "GET")
	wfe.HandleFunc(m, BuildIDPath, wfe.BuildID, "GET")
	return m, nil
}

// Method implementations

// Index serves a simple identification page. It is not part of the ACME spec.
func (wfe *WebFrontEndImpl) Index(response http.ResponseWriter, request *http.Request) {
	logEvent := wfe.populateRequestEvent(request)
	defer wfe.logRequestDetails(&logEvent)

	// http://golang.org/pkg/net/http/#example_ServeMux_Handle
	// The "/" pattern matches everything, so we need to check
	// that we're at the root here.
	if request.URL.Path != "/" {
		logEvent.Error = "Resource not found"
		http.NotFound(response, request)
		return
	}

	tmpl := template.Must(template.New("body").Parse(`<html>
  <body>
    This is an <a href="https://github.com/letsencrypt/acme-spec/">ACME</a>
    Certificate Authority running <a href="https://github.com/letsencrypt/boulder">Boulder</a>,
    New registration is available at <a href="{{.NewReg}}">{{.NewReg}}</a>.
  </body>
</html>
`))
	tmpl.Execute(response, wfe)
	response.Header().Set("Content-Type", "text/html")
	addCacheHeader(response, wfe.IndexCacheDuration.Seconds())
}

func addNoCacheHeader(w http.ResponseWriter) {
	w.Header().Add("Cache-Control", "public, max-age=0, no-cache")
}

func addCacheHeader(w http.ResponseWriter, age float64) {
	w.Header().Add("Cache-Control", fmt.Sprintf("public, max-age=%.f", age))
}

func (wfe *WebFrontEndImpl) Directory(response http.ResponseWriter, request *http.Request) {
	response.Write(wfe.DirectoryJSON)
}

// The ID is always the last slash-separated token in the path
func parseIDFromPath(path string) string {
	re := regexp.MustCompile("^.*/")
	return re.ReplaceAllString(path, "")
}

const (
	unknownKey   = "No registration exists matching provided key"
	malformedJWS = "Unable to read/verify body"
)

func (wfe *WebFrontEndImpl) verifyPOST(request *http.Request, regCheck bool, resource core.AcmeResource) ([]byte, *jose.JsonWebKey, core.Registration, error) {
	var err error
	var reg core.Registration

	// Read body
	if request.Body == nil {
		err = core.MalformedRequestError("No body on POST")
		wfe.log.Debug(err.Error())
		return nil, nil, reg, err
	}

	bodyBytes, err := ioutil.ReadAll(request.Body)
	if err != nil {
		err = core.InternalServerError(err.Error())
		wfe.log.Debug(err.Error())
		return nil, nil, reg, err
	}

	body := string(bodyBytes)
	// Parse as JWS
	parsedJws, err := jose.ParseSigned(body)
	if err != nil {
		puberr := core.SignatureValidationError("Parse error reading JWS")
		wfe.log.Debug(fmt.Sprintf("%v :: %v", puberr.Error(), err.Error()))
		return nil, nil, reg, puberr
	}

	// Verify JWS
	// NOTE: It might seem insecure for the WFE to be trusted to verify
	// client requests, i.e., that the verification should be done at the
	// RA.  However the WFE is the RA's only view of the outside world
	// *anyway*, so it could always lie about what key was used by faking
	// the signature itself.
	if len(parsedJws.Signatures) > 1 {
		err = core.SignatureValidationError("Too many signatures on POST")
		wfe.log.Debug(err.Error())
		return nil, nil, reg, err
	}
	if len(parsedJws.Signatures) == 0 {
		err = core.SignatureValidationError("POST JWS not signed")
		wfe.log.Debug(err.Error())
		return nil, nil, reg, err
	}
	key := parsedJws.Signatures[0].Header.JsonWebKey
	payload, header, err := parsedJws.Verify(key)
	if err != nil {
		puberr := core.SignatureValidationError("JWS verification error")
		wfe.log.Debug(string(body))
		wfe.log.Debug(fmt.Sprintf("%v :: %v", puberr.Error(), err.Error()))
		return nil, nil, reg, puberr
	}

	// Check that the request has a known anti-replay nonce
	// i.e., Nonce is in protected header and
	if err != nil || len(header.Nonce) == 0 {
		err = core.SignatureValidationError("JWS has no anti-replay nonce")
		wfe.log.Debug(err.Error())
		return nil, nil, reg, err
	} else if !wfe.nonceService.Valid(header.Nonce) {
		err = core.SignatureValidationError(fmt.Sprintf("JWS has invalid anti-replay nonce"))
		wfe.log.Debug(err.Error())
		return nil, nil, reg, err
	}

	reg, err = wfe.SA.GetRegistrationByKey(*key)
	if err != nil {
		// If we are requiring a valid registration, any failure to look up the
		// registration is an overall failure to verify.
		if regCheck {
			return nil, nil, reg, err
		}
		// Otherwise we just return an empty registration. The caller is expected
		// to use the returned key instead.
		reg = core.Registration{}
	}

	// Check that the "resource" field is present and has the correct value
	var parsedRequest struct {
		Resource string `json:"resource"`
	}
	err = json.Unmarshal([]byte(payload), &parsedRequest)
	if err != nil {
		puberr := core.SignatureValidationError("Request payload did not parse as JSON")
		wfe.log.Debug(fmt.Sprintf("%v :: %v", puberr.Error(), err.Error()))
		return nil, nil, reg, puberr
	}
	if parsedRequest.Resource == "" {
		err = core.MalformedRequestError("Request payload does not specify a resource")
		wfe.log.Debug(err.Error())
		return nil, nil, reg, err
	} else if resource != core.AcmeResource(parsedRequest.Resource) {
		err = core.MalformedRequestError(fmt.Sprintf("Request payload has invalid resource: %s != %s", parsedRequest.Resource, resource))
		wfe.log.Debug(err.Error())
		return nil, nil, reg, err
	}

	return []byte(payload), key, reg, nil
}

// Notify the client of an error condition and log it for audit purposes.
func (wfe *WebFrontEndImpl) sendError(response http.ResponseWriter, msg string, detail interface{}, code int) {
	problem := core.ProblemDetails{Detail: msg}
	switch code {
	case http.StatusPreconditionFailed:
		fallthrough
	case http.StatusForbidden:
		problem.Type = core.UnauthorizedProblem
	case http.StatusConflict:
		fallthrough
	case http.StatusMethodNotAllowed:
		fallthrough
	case http.StatusNotFound:
		fallthrough
	case http.StatusBadRequest:
		problem.Type = core.MalformedProblem
	default: // Either http.StatusInternalServerError or an unexpected code
		problem.Type = core.ServerInternalProblem
	}

	// Only audit log internal errors so users cannot purposefully cause
	// auditable events.
	if problem.Type == core.ServerInternalProblem {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		wfe.log.Audit(fmt.Sprintf("Internal error - %s - %s", msg, detail))
	} else if statusCodeFromError(detail) != http.StatusInternalServerError {
		// If not an internal error and problem is a custom error type
		problem.Detail += fmt.Sprintf(" :: %s", detail)
	}

	problemDoc, err := json.Marshal(problem)
	if err != nil {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		wfe.log.Audit(fmt.Sprintf("Could not marshal error message: %s - %+v", err, problem))
		problemDoc = []byte("{\"detail\": \"Problem marshalling error message.\"}")
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

// NewRegistration is used by clients to submit a new registration/account
func (wfe *WebFrontEndImpl) NewRegistration(response http.ResponseWriter, request *http.Request) {
	logEvent := wfe.populateRequestEvent(request)
	defer wfe.logRequestDetails(&logEvent)

	body, key, _, err := wfe.verifyPOST(request, false, core.ResourceNewReg)
	if err != nil {
		logEvent.Error = err.Error()
		wfe.sendError(response, malformedJWS, err, http.StatusBadRequest)
		return
	}

	if existingReg, err := wfe.SA.GetRegistrationByKey(*key); err == nil {
		logEvent.Error = "Registration key is already in use"
		response.Header().Set("Location", fmt.Sprintf("%s%d", wfe.RegBase, existingReg.ID))
		wfe.sendError(response, logEvent.Error, nil, http.StatusConflict)
		return
	}

	var init core.Registration
	err = json.Unmarshal(body, &init)
	if err != nil {
		logEvent.Error = err.Error()
		wfe.sendError(response, "Error unmarshaling JSON", err, http.StatusBadRequest)
		return
	}
	if len(init.Agreement) > 0 && init.Agreement != wfe.SubscriberAgreementURL {
		logEvent.Error = fmt.Sprintf("Provided agreement URL [%s] does not match current agreement URL [%s]", init.Agreement, wfe.SubscriberAgreementURL)
		wfe.sendError(response, logEvent.Error, nil, http.StatusBadRequest)
		return
	}
	init.Key = *key

	reg, err := wfe.RA.NewRegistration(init)
	if err != nil {
		logEvent.Error = err.Error()
		wfe.sendError(response, "Error creating new registration", err, statusCodeFromError(err))
		return
	}
	logEvent.Requester = reg.ID
	logEvent.Contacts = reg.Contact

	// Use an explicitly typed variable. Otherwise `go vet' incorrectly complains
	// that reg.ID is a string being passed to %d.
	var id int64 = reg.ID
	regURL := fmt.Sprintf("%s%d", wfe.RegBase, id)
	responseBody, err := json.Marshal(reg)
	if err != nil {
		logEvent.Error = err.Error()
		// StatusInternalServerError because we just created this registration, it should be OK.
		wfe.sendError(response, "Error marshaling registration", err, http.StatusInternalServerError)
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

// NewAuthorization is used by clients to submit a new ID Authorization
func (wfe *WebFrontEndImpl) NewAuthorization(response http.ResponseWriter, request *http.Request) {
	logEvent := wfe.populateRequestEvent(request)
	defer wfe.logRequestDetails(&logEvent)

	body, _, currReg, err := wfe.verifyPOST(request, true, core.ResourceNewAuthz)
	if err != nil {
		logEvent.Error = err.Error()
		respMsg := malformedJWS
		respCode := http.StatusBadRequest
		if err == sql.ErrNoRows {
			respMsg = unknownKey
			respCode = http.StatusForbidden
		}
		wfe.sendError(response, respMsg, err, respCode)
		return
	}
	logEvent.Requester = currReg.ID
	logEvent.Contacts = currReg.Contact
	// Any version of the agreement is acceptable here. Version match is enforced in
	// wfe.Registration when agreeing the first time. Agreement updates happen
	// by mailing subscribers and don't require a registration update.
	if currReg.Agreement == "" {
		logEvent.Error = "Must agree to subscriber agreement before any further actions"
		wfe.sendError(response, logEvent.Error, nil, http.StatusForbidden)
		return
	}

	var init core.Authorization
	if err = json.Unmarshal(body, &init); err != nil {
		logEvent.Error = err.Error()
		wfe.sendError(response, "Error unmarshaling JSON", err, http.StatusBadRequest)
		return
	}
	logEvent.Extra["Identifier"] = init.Identifier

	// Create new authz and return
	authz, err := wfe.RA.NewAuthorization(init, currReg.ID)
	if err != nil {
		logEvent.Error = err.Error()
		wfe.sendError(response, "Error creating new authz", err, statusCodeFromError(err))
		return
	}
	logEvent.Extra["AuthzID"] = authz.ID

	// Make a URL for this authz, then blow away the ID and RegID before serializing
	authzURL := wfe.AuthzBase + string(authz.ID)
	authz.ID = ""
	authz.RegistrationID = 0
	responseBody, err := json.Marshal(authz)
	if err != nil {
		logEvent.Error = err.Error()
		// StatusInternalServerError because we generated the authz, it should be OK
		wfe.sendError(response, "Error marshaling authz", err, http.StatusInternalServerError)
		return
	}

	response.Header().Add("Location", authzURL)
	response.Header().Add("Link", link(wfe.NewCert, "next"))
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusCreated)
	if _, err = response.Write(responseBody); err != nil {
		logEvent.Error = err.Error()
		wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
	}
	// incr pending auth stat (?)
	wfe.Stats.Inc("PendingAuthorizations", 1, 1.0)
}

// RevokeCertificate is used by clients to request the revocation of a cert.
func (wfe *WebFrontEndImpl) RevokeCertificate(response http.ResponseWriter, request *http.Request) {
	logEvent := wfe.populateRequestEvent(request)
	defer wfe.logRequestDetails(&logEvent)

	// We don't ask verifyPOST to verify there is a correponding registration,
	// because anyone with the right private key can revoke a certificate.
	body, requestKey, registration, err := wfe.verifyPOST(request, false, core.ResourceRevokeCert)
	if err != nil {
		logEvent.Error = err.Error()
		wfe.sendError(response, malformedJWS, err, http.StatusBadRequest)
		return
	}
	logEvent.Requester = registration.ID
	logEvent.Contacts = registration.Contact

	type RevokeRequest struct {
		CertificateDER core.JSONBuffer `json:"certificate"`
	}
	var revokeRequest RevokeRequest
	if err = json.Unmarshal(body, &revokeRequest); err != nil {
		logEvent.Error = err.Error()
		wfe.log.Debug(fmt.Sprintf("Couldn't unmarshal in revoke request %s", string(body)))
		wfe.sendError(response, "Unable to read/verify body", err, http.StatusBadRequest)
		return
	}
	providedCert, err := x509.ParseCertificate(revokeRequest.CertificateDER)
	if err != nil {
		logEvent.Error = err.Error()
		wfe.log.Debug("Couldn't parse cert in revoke request.")
		wfe.sendError(response, "Unable to read/verify body", err, http.StatusBadRequest)
		return
	}

	serial := core.SerialToString(providedCert.SerialNumber)
	logEvent.Extra["ProvidedCertificateSerial"] = serial
	cert, err := wfe.SA.GetCertificate(serial)
	if err != nil || !bytes.Equal(cert.DER, revokeRequest.CertificateDER) {
		wfe.sendError(response, "No such certificate", err, http.StatusNotFound)
		return
	}
	parsedCertificate, err := x509.ParseCertificate(cert.DER)
	if err != nil {
		logEvent.Error = err.Error()
		// InternalServerError because this is a failure to decode from our DB.
		wfe.sendError(response, "Invalid certificate", err, http.StatusInternalServerError)
		return
	}
	logEvent.Extra["RetrievedCertificateSerial"] = core.SerialToString(parsedCertificate.SerialNumber)
	logEvent.Extra["RetrievedCertificateDNSNames"] = parsedCertificate.DNSNames
	logEvent.Extra["RetrievedCertificateEmailAddresses"] = parsedCertificate.EmailAddresses
	logEvent.Extra["RetrievedCertificateIPAddresses"] = parsedCertificate.IPAddresses

	certStatus, err := wfe.SA.GetCertificateStatus(serial)
	if err != nil {
		logEvent.Error = err.Error()
		wfe.sendError(response, "Certificate status not yet available", err, http.StatusNotFound)
		return
	}
	logEvent.Extra["CertificateStatus"] = certStatus.Status

	if certStatus.Status == core.OCSPStatusRevoked {
		logEvent.Error = "Certificate already revoked"
		wfe.sendError(response, logEvent.Error, "", http.StatusConflict)
		return
	}

	// TODO: Implement method of revocation by authorizations on account.
	if !(core.KeyDigestEquals(requestKey, parsedCertificate.PublicKey) ||
		registration.ID == cert.RegistrationID) {
		logEvent.Error = "Revocation request must be signed by private key of cert to be revoked"
		wfe.log.Debug("Key mismatch for revoke")
		wfe.sendError(response,
			logEvent.Error,
			requestKey,
			http.StatusForbidden)
		return
	}

	err = wfe.RA.RevokeCertificate(*parsedCertificate)
	if err != nil {
		logEvent.Error = err.Error()
		wfe.sendError(response, "Failed to revoke certificate", err, statusCodeFromError(err))
	} else {
		wfe.log.Debug(fmt.Sprintf("Revoked %v", serial))
		// incr revoked cert stat
		wfe.Stats.Inc("RevokedCertificates", 1, 1.0)
		response.WriteHeader(http.StatusOK)
	}
}

func (wfe *WebFrontEndImpl) logCsr(remoteAddr string, cr core.CertificateRequest, registration core.Registration) {
	var csrLog = struct {
		RemoteAddr   string
		CsrBase64    []byte
		Registration core.Registration
	}{
		RemoteAddr:   remoteAddr,
		CsrBase64:    cr.Bytes,
		Registration: registration,
	}
	wfe.log.AuditObject("Certificate request", csrLog)
}

// NewCertificate is used by clients to request the issuance of a cert for an
// authorized identifier.
func (wfe *WebFrontEndImpl) NewCertificate(response http.ResponseWriter, request *http.Request) {
	logEvent := wfe.populateRequestEvent(request)
	defer wfe.logRequestDetails(&logEvent)

	body, _, reg, err := wfe.verifyPOST(request, true, core.ResourceNewCert)
	if err != nil {
		logEvent.Error = err.Error()
		respMsg := malformedJWS
		respCode := http.StatusBadRequest
		if err == sql.ErrNoRows {
			respMsg = unknownKey
			respCode = http.StatusForbidden
		}
		wfe.sendError(response, respMsg, err, respCode)
		return
	}
	logEvent.Requester = reg.ID
	logEvent.Contacts = reg.Contact
	// Any version of the agreement is acceptable here. Version match is enforced in
	// wfe.Registration when agreeing the first time. Agreement updates happen
	// by mailing subscribers and don't require a registration update.
	if reg.Agreement == "" {
		logEvent.Error = "Must agree to subscriber agreement before any further actions"
		wfe.sendError(response, logEvent.Error, nil, http.StatusForbidden)
		return
	}

	var init core.CertificateRequest
	if err = json.Unmarshal(body, &init); err != nil {
		logEvent.Error = err.Error()
		wfe.sendError(response, "Error unmarshaling certificate request", err, http.StatusBadRequest)
		return
	}
	wfe.logCsr(request.RemoteAddr, init, reg)
	logEvent.Extra["CSRDNSNames"] = init.CSR.DNSNames
	logEvent.Extra["CSREmailAddresses"] = init.CSR.EmailAddresses
	logEvent.Extra["CSRIPAddresses"] = init.CSR.IPAddresses

	// Create new certificate and return
	// TODO IMPORTANT: The RA trusts the WFE to provide the correct key. If the
	// WFE is compromised, *and* the attacker knows the public key of an account
	// authorized for target site, they could cause issuance for that site by
	// lying to the RA. We should probably pass a copy of the whole rquest to the
	// RA for secondary validation.
	cert, err := wfe.RA.NewCertificate(init, reg.ID)
	if err != nil {
		logEvent.Error = err.Error()
		wfe.sendError(response, "Error creating new cert", err, statusCodeFromError(err))
		return
	}

	// Make a URL for this certificate.
	// We use only the sequential part of the serial number, because it should
	// uniquely identify the certificate, and this makes it easy for anybody to
	// enumerate and mirror our certificates.
	parsedCertificate, err := x509.ParseCertificate([]byte(cert.DER))
	if err != nil {
		logEvent.Error = err.Error()
		wfe.sendError(response,
			"Error creating new cert", err,
			http.StatusBadRequest)
		return
	}
	serial := parsedCertificate.SerialNumber
	certURL := fmt.Sprintf("%s%016x", wfe.CertBase, serial.Rsh(serial, 64))

	// TODO Content negotiation
	response.Header().Add("Location", certURL)
	response.Header().Add("Link", link(wfe.BaseURL+IssuerPath, "up"))
	response.Header().Set("Content-Type", "application/pkix-cert")
	response.WriteHeader(http.StatusCreated)
	if _, err = response.Write(cert.DER); err != nil {
		logEvent.Error = err.Error()
		wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
	}
	// incr cert stat
	wfe.Stats.Inc("Certificates", 1, 1.0)
}

func (wfe *WebFrontEndImpl) challenge(authz core.Authorization, response http.ResponseWriter, request *http.Request, logEvent requestEvent) requestEvent {
	// Check that the requested challenge exists within the authorization
	found := false
	var challengeIndex int
	for i, challenge := range authz.Challenges {
		tempURL := challenge.URI
		if tempURL.Path == request.URL.Path && tempURL.RawQuery == request.URL.RawQuery {
			found = true
			challengeIndex = i
			break
		}
	}

	if !found {
		logEvent.Error = "Unable to find challenge"
		wfe.sendError(response, logEvent.Error, request.URL.RawQuery, http.StatusNotFound)
		return logEvent
	}

	switch request.Method {
	case "GET":
		challenge := authz.Challenges[challengeIndex]
		jsonReply, err := json.Marshal(challenge)
		if err != nil {
			logEvent.Error = err.Error()
			// InternalServerError because this is a failure to decode data passed in
			// by the caller, which got it from the DB.
			wfe.sendError(response, "Failed to marshal challenge", err, http.StatusInternalServerError)
			return logEvent
		}

		authzURL := wfe.AuthzBase + string(authz.ID)
		response.Header().Add("Location", challenge.URI.String())
		response.Header().Set("Content-Type", "application/json")
		response.Header().Add("Link", link(authzURL, "up"))
		response.WriteHeader(http.StatusAccepted)
		if _, err := response.Write(jsonReply); err != nil {
			wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
			logEvent.Error = err.Error()
			return logEvent
		}

	case "POST":
		body, _, currReg, err := wfe.verifyPOST(request, true, core.ResourceChallenge)
		if err != nil {
			logEvent.Error = err.Error()
			respMsg := malformedJWS
			respCode := http.StatusBadRequest
			if err == sql.ErrNoRows {
				respMsg = unknownKey
				respCode = http.StatusForbidden
			}
			wfe.sendError(response, respMsg, err, respCode)
			return logEvent
		}
		logEvent.Requester = currReg.ID
		logEvent.Contacts = currReg.Contact
		// Any version of the agreement is acceptable here. Version match is enforced in
		// wfe.Registration when agreeing the first time. Agreement updates happen
		// by mailing subscribers and don't require a registration update.
		if currReg.Agreement == "" {
			logEvent.Error = "Must agree to subscriber agreement before any further actions"
			wfe.sendError(response, logEvent.Error, nil, http.StatusForbidden)
			return logEvent
		}

		// Check that the registration ID matching the key used matches
		// the registration ID on the authz object
		if currReg.ID != authz.RegistrationID {
			logEvent.Error = fmt.Sprintf("User: %v != Authorization: %v", currReg.ID, authz.RegistrationID)
			wfe.sendError(response, "User registration ID doesn't match registration ID in authorization",
				logEvent.Error,
				http.StatusForbidden)
			return logEvent
		}

		var challengeResponse core.Challenge
		if err = json.Unmarshal(body, &challengeResponse); err != nil {
			logEvent.Error = err.Error()
			wfe.sendError(response, "Error unmarshaling challenge response", err, http.StatusBadRequest)
			return logEvent
		}

		// Ask the RA to update this authorization
		updatedAuthz, err := wfe.RA.UpdateAuthorization(authz, challengeIndex, challengeResponse)
		if err != nil {
			logEvent.Error = err.Error()
			wfe.sendError(response, "Unable to update authorization", err, statusCodeFromError(err))
			return logEvent
		}

		challenge := updatedAuthz.Challenges[challengeIndex]
		// assumption: UpdateAuthorization does not modify order of challenges
		jsonReply, err := json.Marshal(challenge)
		if err != nil {
			logEvent.Error = err.Error()
			// StatusInternalServerError because we made the challenges, they should be OK
			wfe.sendError(response, "Failed to marshal challenge", err, http.StatusInternalServerError)
			return logEvent
		}

		authzURL := wfe.AuthzBase + string(authz.ID)
		response.Header().Add("Location", challenge.URI.String())
		response.Header().Set("Content-Type", "application/json")
		response.Header().Add("Link", link(authzURL, "up"))
		response.WriteHeader(http.StatusAccepted)
		if _, err = response.Write(jsonReply); err != nil {
			logEvent.Error = err.Error()
			wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
			return logEvent
		}

	}
	return logEvent
}

// Registration is used by a client to submit an update to their registration.
func (wfe *WebFrontEndImpl) Registration(response http.ResponseWriter, request *http.Request) {
	logEvent := wfe.populateRequestEvent(request)
	defer wfe.logRequestDetails(&logEvent)

	body, _, currReg, err := wfe.verifyPOST(request, true, core.ResourceRegistration)
	if err != nil {
		logEvent.Error = err.Error()
		respMsg := malformedJWS
		respCode := http.StatusBadRequest
		if err == sql.ErrNoRows {
			respMsg = unknownKey
			respCode = http.StatusForbidden
		}
		wfe.sendError(response, respMsg, err, respCode)
		return
	}
	logEvent.Requester = currReg.ID
	logEvent.Contacts = currReg.Contact

	// Requests to this handler should have a path that leads to a known
	// registration
	idStr := parseIDFromPath(request.URL.Path)
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		logEvent.Error = err.Error()
		wfe.sendError(response, "Registration ID must be an integer", err, http.StatusBadRequest)
		return
	} else if id <= 0 {
		logEvent.Error = "Registration ID must be a positive non-zero integer"
		wfe.sendError(response, logEvent.Error, id, http.StatusBadRequest)
		return
	} else if id != currReg.ID {
		logEvent.Error = "Request signing key did not match registration key"
		wfe.sendError(response, logEvent.Error, "", http.StatusForbidden)
		return
	}

	var update core.Registration
	err = json.Unmarshal(body, &update)
	if err != nil {
		logEvent.Error = err.Error()
		wfe.sendError(response, "Error unmarshaling registration", err, http.StatusBadRequest)
		return
	}

	if len(update.Agreement) > 0 && update.Agreement != wfe.SubscriberAgreementURL {
		logEvent.Error = fmt.Sprintf("Provided agreement URL [%s] does not match current agreement URL [%s]", update.Agreement, wfe.SubscriberAgreementURL)
		wfe.sendError(response, logEvent.Error, nil, http.StatusBadRequest)
		return
	}

	// Registration objects contain a JWK object, which must be non-nil. We know
	// the key of the updated registration object is going to be the same as the
	// key of the current one, so we set it here. This ensures we can cleanly
	// serialize the update as JSON to send via AMQP to the RA.
	update.Key = currReg.Key

	// Ask the RA to update this authorization.
	updatedReg, err := wfe.RA.UpdateRegistration(currReg, update)
	if err != nil {
		logEvent.Error = err.Error()
		wfe.sendError(response, "Unable to update registration", err, statusCodeFromError(err))
		return
	}

	jsonReply, err := json.Marshal(updatedReg)
	if err != nil {
		logEvent.Error = err.Error()
		// StatusInternalServerError because we just generated the reg, it should be OK
		wfe.sendError(response, "Failed to marshal registration", err, http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Add("Link", link(wfe.NewAuthz, "next"))
	if len(wfe.SubscriberAgreementURL) > 0 {
		response.Header().Add("Link", link(wfe.SubscriberAgreementURL, "terms-of-service"))
	}
	response.WriteHeader(http.StatusAccepted)
	response.Write(jsonReply)
}

// Authorization is used by clients to submit an update to one of their
// authorizations.
func (wfe *WebFrontEndImpl) Authorization(response http.ResponseWriter, request *http.Request) {
	logEvent := wfe.populateRequestEvent(request)
	defer wfe.logRequestDetails(&logEvent)

	// Requests to this handler should have a path that leads to a known authz
	id := parseIDFromPath(request.URL.Path)
	authz, err := wfe.SA.GetAuthorization(id)
	if err != nil {
		wfe.sendError(response,
			"Unable to find authorization", err,
			http.StatusNotFound)
		return
	}
	logEvent.Extra["AuthorizationID"] = authz.ID
	logEvent.Extra["AuthorizationRegistrationID"] = authz.RegistrationID
	logEvent.Extra["AuthorizationIdentifier"] = authz.Identifier
	logEvent.Extra["AuthorizationStatus"] = authz.Status
	logEvent.Extra["AuthorizationExpires"] = authz.Expires

	// If there is a fragment, then this is actually a request to a challenge URI
	if len(request.URL.RawQuery) != 0 {
		logEvent = wfe.challenge(authz, response, request, logEvent)
		return
	}

	// Blank out ID and regID
	switch request.Method {
	case "GET":
		authz.ID = ""
		authz.RegistrationID = 0

		jsonReply, err := json.Marshal(authz)
		if err != nil {
			logEvent.Error = err.Error()
			// InternalServerError because this is a failure to decode from our DB.
			wfe.sendError(response, "Failed to marshal authz", err, http.StatusInternalServerError)
			return
		}
		response.Header().Add("Link", link(wfe.NewCert, "next"))
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusOK)
		if _, err = response.Write(jsonReply); err != nil {
			logEvent.Error = err.Error()
			wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
		}
	}
}

var allHex = regexp.MustCompile("^[0-9a-f]+$")

// Certificate is used by clients to request a copy of their current certificate, or to
// request a reissuance of the certificate.
func (wfe *WebFrontEndImpl) Certificate(response http.ResponseWriter, request *http.Request) {
	logEvent := wfe.populateRequestEvent(request)
	defer wfe.logRequestDetails(&logEvent)

	path := request.URL.Path
	// Certificate paths consist of the CertBase path, plus exactly sixteen hex
	// digits.
	if !strings.HasPrefix(path, CertPath) {
		logEvent.Error = "Certificate not found"
		wfe.sendError(response, logEvent.Error, path, http.StatusNotFound)
		addNoCacheHeader(response)
		return
	}
	serial := path[len(CertPath):]
	if len(serial) != 16 || !allHex.Match([]byte(serial)) {
		logEvent.Error = "Certificate not found"
		wfe.sendError(response, logEvent.Error, serial, http.StatusNotFound)
		addNoCacheHeader(response)
		return
	}
	wfe.log.Debug(fmt.Sprintf("Requested certificate ID %s", serial))
	logEvent.Extra["RequestedSerial"] = serial

	cert, err := wfe.SA.GetCertificateByShortSerial(serial)
	if err != nil {
		logEvent.Error = err.Error()
		if strings.HasPrefix(err.Error(), "gorp: multiple rows returned") {
			wfe.sendError(response, "Multiple certificates with same short serial", err, http.StatusConflict)
		} else {
			addNoCacheHeader(response)
			wfe.sendError(response, "Certificate not found", err, http.StatusNotFound)
		}
		return
	}

	addCacheHeader(response, wfe.CertCacheDuration.Seconds())

	// TODO Content negotiation
	response.Header().Set("Content-Type", "application/pkix-cert")
	response.Header().Add("Link", link(IssuerPath, "up"))
	response.WriteHeader(http.StatusOK)
	if _, err = response.Write(cert.DER); err != nil {
		logEvent.Error = err.Error()
		wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
	}
	return
}

// Terms is used by the client to obtain the current Terms of Service /
// Subscriber Agreement to which the subscriber must agree.
func (wfe *WebFrontEndImpl) Terms(response http.ResponseWriter, request *http.Request) {
	logEvent := wfe.populateRequestEvent(request)
	defer wfe.logRequestDetails(&logEvent)

	http.Redirect(response, request, wfe.SubscriberAgreementURL, http.StatusFound)
}

// Issuer obtains the issuer certificate used by this instance of Boulder.
func (wfe *WebFrontEndImpl) Issuer(response http.ResponseWriter, request *http.Request) {
	logEvent := wfe.populateRequestEvent(request)
	defer wfe.logRequestDetails(&logEvent)

	addCacheHeader(response, wfe.IssuerCacheDuration.Seconds())

	// TODO Content negotiation
	response.Header().Set("Content-Type", "application/pkix-cert")
	response.WriteHeader(http.StatusOK)
	if _, err := response.Write(wfe.IssuerCert); err != nil {
		logEvent.Error = err.Error()
		wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
	}
}

// BuildID tells the requestor what build we're running.
func (wfe *WebFrontEndImpl) BuildID(response http.ResponseWriter, request *http.Request) {
	logEvent := wfe.populateRequestEvent(request)
	defer wfe.logRequestDetails(&logEvent)

	response.Header().Set("Content-Type", "text/plain")
	response.WriteHeader(http.StatusOK)
	detailsString := fmt.Sprintf("Boulder=(%s %s)", core.GetBuildID(), core.GetBuildTime())
	if _, err := fmt.Fprintln(response, detailsString); err != nil {
		logEvent.Error = err.Error()
		wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
	}
}

func (wfe *WebFrontEndImpl) logRequestDetails(logEvent *requestEvent) {
	logEvent.ResponseTime = time.Now()
	var msg string
	if logEvent.Error != "" {
		msg = "Terminated request"
	} else {
		msg = "Successful request"
	}
	wfe.log.InfoObject(msg, logEvent)
}

func (wfe *WebFrontEndImpl) populateRequestEvent(request *http.Request) (logEvent requestEvent) {
	logEvent = requestEvent{
		ID:           core.NewToken(),
		RealIP:       request.Header.Get("X-Real-IP"),
		ForwardedFor: request.Header.Get("X-Forwarded-For"),
		Method:       request.Method,
		RequestTime:  time.Now(),
		Extra:        make(map[string]interface{}, 0),
	}
	if request.URL != nil {
		logEvent.Endpoint = request.URL.String()
	}
	return
}
