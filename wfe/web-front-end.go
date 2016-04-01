// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package wfe

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/square/go-jose"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/probs"
)

// Paths are the ACME-spec identified URL path-segments for various methods
const (
	DirectoryPath  = "/directory"
	NewRegPath     = "/acme/new-reg"
	RegPath        = "/acme/reg/"
	NewAuthzPath   = "/acme/new-authz"
	AuthzPath      = "/acme/authz/"
	ChallengePath  = "/acme/challenge/"
	NewCertPath    = "/acme/new-cert"
	CertPath       = "/acme/cert/"
	RevokeCertPath = "/acme/revoke-cert"
	TermsPath      = "/terms"
	IssuerPath     = "/acme/issuer-cert"
	BuildIDPath    = "/build"
)

// WebFrontEndImpl provides all the logic for Boulder's web-facing interface,
// i.e., ACME.  Its members configure the paths for various ACME functions,
// plus a few other data items used in ACME.  Its methods are primarily handlers
// for HTTPS requests for the various ACME functions.
type WebFrontEndImpl struct {
	RA    core.RegistrationAuthority
	SA    core.StorageGetter
	stats statsd.Statter
	log   *blog.AuditLogger
	clk   clock.Clock

	// URL configuration parameters
	BaseURL       string
	NewReg        string
	RegBase       string
	NewAuthz      string
	AuthzBase     string
	ChallengeBase string
	NewCert       string
	CertBase      string

	// JSON encoded endpoint directory
	DirectoryJSON []byte

	// Issuer certificate (DER) for /acme/issuer-cert
	IssuerCert []byte

	// URL to the current subscriber agreement (should contain some version identifier)
	SubscriberAgreementURL string

	// Register of anti-replay nonces
	nonceService *core.NonceService

	// Key policy.
	keyPolicy core.KeyPolicy

	// Cache settings
	CertCacheDuration           time.Duration
	CertNoCacheExpirationWindow time.Duration
	IndexCacheDuration          time.Duration
	IssuerCacheDuration         time.Duration

	// CORS settings
	AllowOrigins []string

	// Graceful shutdown settings
	ShutdownStopTimeout time.Duration
	ShutdownKillTimeout time.Duration
}

// NewWebFrontEndImpl constructs a web service for Boulder
func NewWebFrontEndImpl(stats statsd.Statter, clk clock.Clock, keyPolicy core.KeyPolicy) (WebFrontEndImpl, error) {
	logger := blog.GetAuditLogger()
	logger.Notice("Web Front End Starting")

	nonceService, err := core.NewNonceService()
	if err != nil {
		return WebFrontEndImpl{}, err
	}

	return WebFrontEndImpl{
		log:          logger,
		clk:          clk,
		nonceService: nonceService,
		stats:        stats,
		keyPolicy:    keyPolicy,
	}, nil
}

// HandleFunc registers a handler at the given path. It's
// http.HandleFunc(), but with a wrapper around the handler that
// provides some generic per-request functionality:
//
// * Set a Replay-Nonce header.
//
// * Respond to OPTIONS requests, including CORS preflight requests.
//
// * Respond http.StatusMethodNotAllowed for HTTP methods other than
// those listed.
//
// * Set CORS headers when responding to CORS "actual" requests.
//
// * Never send a body in response to a HEAD request. Anything
// written by the handler will be discarded if the method is HEAD.
// Also, all handlers that accept GET automatically accept HEAD.
func (wfe *WebFrontEndImpl) HandleFunc(mux *http.ServeMux, pattern string, h wfeHandlerFunc, methods ...string) {
	methodsMap := make(map[string]bool)
	for _, m := range methods {
		methodsMap[m] = true
	}
	if methodsMap["GET"] && !methodsMap["HEAD"] {
		// Allow HEAD for any resource that allows GET
		methods = append(methods, "HEAD")
		methodsMap["HEAD"] = true
	}
	methodsStr := strings.Join(methods, ", ")
	mux.Handle(pattern, &topHandler{
		log: wfe.log,
		clk: clock.Default(),
		wfe: wfeHandlerFunc(func(logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {
			// We do not propagate errors here, because (1) they should be
			// transient, and (2) they fail closed.
			nonce, err := wfe.nonceService.Nonce()
			if err == nil {
				response.Header().Set("Replay-Nonce", nonce)
				logEvent.ResponseNonce = nonce
			} else {
				logEvent.AddError("unable to make nonce: %s", err)
			}

			switch request.Method {
			case "HEAD":
				// Go's net/http (and httptest) servers will strip out the body
				// of responses for us. This keeps the Content-Length for HEAD
				// requests as the same as GET requests per the spec.
			case "OPTIONS":
				wfe.Options(response, request, methodsStr, methodsMap)
				return
			}

			if !methodsMap[request.Method] {
				response.Header().Set("Allow", methodsStr)
				wfe.sendError(response, logEvent, probs.MethodNotAllowed(), nil)
				return
			}

			wfe.setCORSHeaders(response, request, "")

			// Call the wrapped handler.
			h(logEvent, response, request)
		}),
	})
}

// Handler returns an http.Handler that uses various functions for
// various ACME-specified paths.
func (wfe *WebFrontEndImpl) Handler() (http.Handler, error) {
	wfe.NewReg = wfe.BaseURL + NewRegPath
	wfe.RegBase = wfe.BaseURL + RegPath
	wfe.NewAuthz = wfe.BaseURL + NewAuthzPath
	wfe.AuthzBase = wfe.BaseURL + AuthzPath
	wfe.ChallengeBase = wfe.BaseURL + ChallengePath
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
	wfe.HandleFunc(m, DirectoryPath, wfe.Directory, "GET")
	wfe.HandleFunc(m, NewRegPath, wfe.NewRegistration, "POST")
	wfe.HandleFunc(m, NewAuthzPath, wfe.NewAuthorization, "POST")
	wfe.HandleFunc(m, NewCertPath, wfe.NewCertificate, "POST")
	wfe.HandleFunc(m, RegPath, wfe.Registration, "POST")
	wfe.HandleFunc(m, AuthzPath, wfe.Authorization, "GET")
	wfe.HandleFunc(m, ChallengePath, wfe.Challenge, "GET", "POST")
	wfe.HandleFunc(m, CertPath, wfe.Certificate, "GET")
	wfe.HandleFunc(m, RevokeCertPath, wfe.RevokeCertificate, "POST")
	wfe.HandleFunc(m, TermsPath, wfe.Terms, "GET")
	wfe.HandleFunc(m, IssuerPath, wfe.Issuer, "GET")
	wfe.HandleFunc(m, BuildIDPath, wfe.BuildID, "GET")
	// We don't use our special HandleFunc for "/" because it matches everything,
	// meaning we can wind up returning 405 when we mean to return 404. See
	// https://github.com/letsencrypt/boulder/issues/717
	m.Handle("/", &topHandler{
		log: wfe.log,
		clk: clock.Default(),
		wfe: wfeHandlerFunc(wfe.Index),
	})
	return m, nil
}

// Method implementations

// Index serves a simple identification page. It is not part of the ACME spec.
func (wfe *WebFrontEndImpl) Index(logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {
	// http://golang.org/pkg/net/http/#example_ServeMux_Handle
	// The "/" pattern matches everything, so we need to check
	// that we're at the root here.
	if request.URL.Path != "/" {
		logEvent.AddError("Resource not found")
		http.NotFound(response, request)
		response.Header().Set("Content-Type", "application/problem+json")
		return
	}

	if request.Method != "GET" {
		logEvent.AddError("Bad method")
		response.Header().Set("Allow", "GET")
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	response.Header().Set("Content-Type", "text/html")
	response.Write([]byte(fmt.Sprintf(`<html>
		<body>
			This is an <a href="https://github.com/ietf-wg-acme/acme/">ACME</a>
			Certificate Authority running <a href="https://github.com/letsencrypt/boulder">Boulder</a>.
			JSON directory is available at <a href="%s">%s</a>.
		</body>
	</html>
	`, DirectoryPath, DirectoryPath)))
	addCacheHeader(response, wfe.IndexCacheDuration.Seconds())
}

func addNoCacheHeader(w http.ResponseWriter) {
	w.Header().Add("Cache-Control", "public, max-age=0, no-cache")
}

func addCacheHeader(w http.ResponseWriter, age float64) {
	w.Header().Add("Cache-Control", fmt.Sprintf("public, max-age=%.f", age))
}

// Directory is an HTTP request handler that simply provides the directory
// object stored in the WFE's DirectoryJSON member.
func (wfe *WebFrontEndImpl) Directory(logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	response.Write(wfe.DirectoryJSON)
}

// The ID is always the last slash-separated token in the path
func parseIDFromPath(path string) string {
	re := regexp.MustCompile("^.*/")
	return re.ReplaceAllString(path, "")
}

const (
	unknownKey = "No registration exists matching provided key"
)

// verifyPOST reads and parses the request body, looks up the Registration
// corresponding to its JWK, verifies the JWS signature, checks that the
// resource field is present and correct in the JWS protected header, and
// returns the JWS payload bytes, the key used to verify, and the corresponding
// Registration (or error).  If regCheck is false, verifyPOST will still try to
// look up a registration object, and will return it if found. However, if no
// registration object is found, verifyPOST will attempt to verify the JWS using
// the key in the JWS headers, and return the key plus a dummy registration if
// successful. If a caller passes regCheck = false, it should plan on validating
// the key itself.  verifyPOST also appends its errors to requestEvent.Errors so
// code calling it does not need to if they immediately return a response to the
// user.
func (wfe *WebFrontEndImpl) verifyPOST(logEvent *requestEvent, request *http.Request, regCheck bool, resource core.AcmeResource) ([]byte, *jose.JsonWebKey, core.Registration, *probs.ProblemDetails) {
	// TODO: We should return a pointer to a registration, which can be nil,
	// rather the a registration value with a sentinel value.
	// https://github.com/letsencrypt/boulder/issues/877
	reg := core.Registration{ID: 0}

	if _, ok := request.Header["Content-Length"]; !ok {
		wfe.stats.Inc("WFE.HTTP.ClientErrors.LengthRequiredError", 1, 1.0)
		logEvent.AddError("missing Content-Length header on POST")
		return nil, nil, reg, probs.ContentLengthRequired()
	}

	// Read body
	if request.Body == nil {
		wfe.stats.Inc("WFE.Errors.NoPOSTBody", 1, 1.0)
		logEvent.AddError("no body on POST")
		return nil, nil, reg, probs.Malformed("No body on POST")
	}

	bodyBytes, err := ioutil.ReadAll(request.Body)
	if err != nil {
		wfe.stats.Inc("WFE.Errors.UnableToReadRequestBody", 1, 1.0)
		logEvent.AddError("unable to read request body")
		return nil, nil, reg, probs.ServerInternal("unable to read request body")
	}

	body := string(bodyBytes)
	// Parse as JWS
	parsedJws, err := jose.ParseSigned(body)
	if err != nil {
		wfe.stats.Inc("WFE.Errors.UnableToParseJWS", 1, 1.0)
		logEvent.AddError("could not JSON parse body into JWS: %s", err)
		return nil, nil, reg, probs.Malformed("Parse error reading JWS")
	}

	// Verify JWS
	// NOTE: It might seem insecure for the WFE to be trusted to verify
	// client requests, i.e., that the verification should be done at the
	// RA.  However the WFE is the RA's only view of the outside world
	// *anyway*, so it could always lie about what key was used by faking
	// the signature itself.
	if len(parsedJws.Signatures) > 1 {
		wfe.stats.Inc("WFE.Errors.TooManyJWSSignaturesInPOST", 1, 1.0)
		logEvent.AddError("too many signatures in POST body: %d", len(parsedJws.Signatures))
		return nil, nil, reg, probs.Malformed("Too many signatures in POST body")
	}
	if len(parsedJws.Signatures) == 0 {
		wfe.stats.Inc("WFE.Errors.JWSNotSignedInPOST", 1, 1.0)
		logEvent.AddError("no signatures in POST body")
		return nil, nil, reg, probs.Malformed("POST JWS not signed")
	}

	submittedKey := parsedJws.Signatures[0].Header.JsonWebKey
	if submittedKey == nil {
		wfe.stats.Inc("WFE.Errors.NoJWKInJWSSignatureHeader", 1, 1.0)
		logEvent.AddError("no JWK in JWS signature header in POST body")
		return nil, nil, reg, probs.Malformed("No JWK in JWS header")
	}

	var key *jose.JsonWebKey
	reg, err = wfe.SA.GetRegistrationByKey(*submittedKey)
	// Special case: If no registration was found, but regCheck is false, use an
	// empty registration and the submitted key. The caller is expected to do some
	// validation on the returned key.
	if _, ok := err.(core.NoSuchRegistrationError); ok && !regCheck {
		// When looking up keys from the registrations DB, we can be confident they
		// are "good". But when we are verifying against any submitted key, we want
		// to check its quality before doing the verify.
		if err = wfe.keyPolicy.GoodKey(submittedKey.Key); err != nil {
			wfe.stats.Inc("WFE.Errors.JWKRejectedByGoodKey", 1, 1.0)
			logEvent.AddError("JWK in request was rejected by GoodKey: %s", err)
			return nil, nil, reg, probs.Malformed(err.Error())
		}
		key = submittedKey
	} else if err != nil {
		// For all other errors, or if regCheck is true, return error immediately.
		wfe.stats.Inc("WFE.Errors.UnableToGetRegistrationByKey", 1, 1.0)
		logEvent.AddError("unable to fetch registration by the given JWK: %s", err)
		if _, ok := err.(core.NoSuchRegistrationError); ok {
			return nil, nil, reg, probs.Unauthorized(unknownKey)
		}

		return nil, nil, reg, core.ProblemDetailsForError(err, "")
	} else {
		// If the lookup was successful, use that key.
		key = &reg.Key
		logEvent.Requester = reg.ID
		logEvent.Contacts = reg.Contact
	}

	if statName, err := checkAlgorithm(key, parsedJws); err != nil {
		wfe.stats.Inc(statName, 1, 1.0)
		return nil, nil, reg, probs.Malformed(err.Error())
	}

	payload, err := parsedJws.Verify(key)
	if err != nil {
		wfe.stats.Inc("WFE.Errors.JWSVerificationFailed", 1, 1.0)
		n := len(body)
		if n > 100 {
			n = 100
		}
		logEvent.AddError("verification of JWS with the JWK failed: %v; body: %s", err, body[:n])
		return nil, nil, reg, probs.Malformed("JWS verification error")
	}

	// Check that the request has a known anti-replay nonce
	nonce := parsedJws.Signatures[0].Header.Nonce
	logEvent.RequestNonce = nonce
	if len(nonce) == 0 {
		wfe.stats.Inc("WFE.Errors.JWSMissingNonce", 1, 1.0)
		logEvent.AddError("JWS is missing an anti-replay nonce")
		return nil, nil, reg, probs.BadNonce("JWS has no anti-replay nonce")
	} else if !wfe.nonceService.Valid(nonce) {
		wfe.stats.Inc("WFE.Errors.JWSInvalidNonce", 1, 1.0)
		logEvent.AddError("JWS has an invalid anti-replay nonce: %s", nonce)
		return nil, nil, reg, probs.BadNonce(fmt.Sprintf("JWS has invalid anti-replay nonce %v", nonce))
	}

	// Check that the "resource" field is present and has the correct value
	var parsedRequest struct {
		Resource string `json:"resource"`
	}
	err = json.Unmarshal([]byte(payload), &parsedRequest)
	if err != nil {
		wfe.stats.Inc("WFE.Errors.UnparsableJWSPayload", 1, 1.0)
		logEvent.AddError("unable to JSON parse resource from JWS payload: %s", err)
		return nil, nil, reg, probs.Malformed("Request payload did not parse as JSON")
	}
	if parsedRequest.Resource == "" {
		wfe.stats.Inc("WFE.Errors.NoResourceInJWSPayload", 1, 1.0)
		logEvent.AddError("JWS request payload does not specify a resource")
		return nil, nil, reg, probs.Malformed("Request payload does not specify a resource")
	} else if resource != core.AcmeResource(parsedRequest.Resource) {
		wfe.stats.Inc("WFE.Errors.MismatchedResourceInJWSPayload", 1, 1.0)
		logEvent.AddError("JWS request payload does not match resource")
		return nil, nil, reg, probs.Malformed("JWS resource payload does not match the HTTP resource: %s != %s", parsedRequest.Resource, resource)
	}

	return []byte(payload), key, reg, nil
}

// sendError sends an error response represented by the given ProblemDetails,
// and, if the ProblemDetails.Type is ServerInternalProblem, audit logs the
// internal ierr.
func (wfe *WebFrontEndImpl) sendError(response http.ResponseWriter, logEvent *requestEvent, prob *probs.ProblemDetails, ierr error) {
	code := probs.ProblemDetailsToStatusCode(prob)

	// Record details to the log event
	logEvent.AddError(fmt.Sprintf("%d :: %s :: %s", prob.HTTPStatus, prob.Type, prob.Detail))

	// Only audit log internal errors so users cannot purposefully cause
	// auditable events.
	if prob.Type == probs.ServerInternalProblem {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		wfe.log.AuditErr(fmt.Errorf("Internal error - %s - %s", prob.Detail, ierr))
	}

	problemDoc, err := json.Marshal(prob)
	if err != nil {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		wfe.log.AuditErr(fmt.Errorf("Could not marshal error message: %s - %+v", err, prob))
		problemDoc = []byte("{\"detail\": \"Problem marshalling error message.\"}")
	}

	// Paraphrased from
	// https://golang.org/src/net/http/server.go#L1272
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(code)
	response.Write(problemDoc)

	wfe.stats.Inc(fmt.Sprintf("WFE.HTTP.ErrorCodes.%d", code), 1, 1.0)
	problemSegments := strings.Split(string(prob.Type), ":")
	if len(problemSegments) > 0 {
		wfe.stats.Inc(fmt.Sprintf("WFE.HTTP.ProblemTypes.%s", problemSegments[len(problemSegments)-1]), 1, 1.0)
	}
}

func link(url, relation string) string {
	return fmt.Sprintf("<%s>;rel=\"%s\"", url, relation)
}

// NewRegistration is used by clients to submit a new registration/account
func (wfe *WebFrontEndImpl) NewRegistration(logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {

	body, key, _, prob := wfe.verifyPOST(logEvent, request, false, core.ResourceNewReg)
	if prob != nil {
		// verifyPOST handles its own setting of logEvent.Errors
		wfe.sendError(response, logEvent, prob, nil)
		return
	}

	if existingReg, err := wfe.SA.GetRegistrationByKey(*key); err == nil {
		response.Header().Set("Location", fmt.Sprintf("%s%d", wfe.RegBase, existingReg.ID))
		// TODO(#595): check for missing registration err
		wfe.sendError(response, logEvent, probs.Conflict("Registration key is already in use"), err)
		return
	}

	var init core.Registration
	err := json.Unmarshal(body, &init)
	if err != nil {
		wfe.sendError(response, logEvent, probs.Malformed("Error unmarshaling JSON"), err)
		return
	}
	if len(init.Agreement) > 0 && init.Agreement != wfe.SubscriberAgreementURL {
		msg := fmt.Sprintf("Provided agreement URL [%s] does not match current agreement URL [%s]", init.Agreement, wfe.SubscriberAgreementURL)
		wfe.sendError(response, logEvent, probs.Malformed(msg), nil)
		return
	}
	init.Key = *key
	init.InitialIP = net.ParseIP(request.Header.Get("X-Real-IP"))
	if init.InitialIP == nil {
		host, _, err := net.SplitHostPort(request.RemoteAddr)
		if err == nil {
			init.InitialIP = net.ParseIP(host)
		} else {
			logEvent.AddError("Couldn't parse RemoteAddr: %s", request.RemoteAddr)
			wfe.sendError(response, logEvent, probs.ServerInternal("couldn't parse the remote (that is, the client's) address"), nil)
			return
		}
	}

	reg, err := wfe.RA.NewRegistration(init)
	if err != nil {
		logEvent.AddError("unable to create new registration: %s", err)
		wfe.sendError(response, logEvent, core.ProblemDetailsForError(err, "Error creating new registration"), err)
		return
	}
	logEvent.Requester = reg.ID
	logEvent.Contacts = reg.Contact

	// Use an explicitly typed variable. Otherwise `go vet' incorrectly complains
	// that reg.ID is a string being passed to %d.
	regURL := fmt.Sprintf("%s%d", wfe.RegBase, reg.ID)
	responseBody, err := json.Marshal(reg)
	if err != nil {
		// ServerInternal because we just created this registration, and it
		// should be OK.
		logEvent.AddError("unable to marshal registration: %s", err)
		wfe.sendError(response, logEvent, probs.ServerInternal("Error marshaling registration"), err)
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
}

// NewAuthorization is used by clients to submit a new ID Authorization
func (wfe *WebFrontEndImpl) NewAuthorization(logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {
	body, _, currReg, prob := wfe.verifyPOST(logEvent, request, true, core.ResourceNewAuthz)
	if prob != nil {
		// verifyPOST handles its own setting of logEvent.Errors
		wfe.sendError(response, logEvent, prob, nil)
		return
	}
	// Any version of the agreement is acceptable here. Version match is enforced in
	// wfe.Registration when agreeing the first time. Agreement updates happen
	// by mailing subscribers and don't require a registration update.
	if currReg.Agreement == "" {
		wfe.sendError(response, logEvent, probs.Unauthorized("Must agree to subscriber agreement before any further actions"), nil)
		return
	}

	var init core.Authorization
	if err := json.Unmarshal(body, &init); err != nil {
		logEvent.AddError("unable to JSON unmarshal Authorization: %s", err)
		wfe.sendError(response, logEvent, probs.Malformed("Error unmarshaling JSON"), err)
		return
	}
	logEvent.Extra["Identifier"] = init.Identifier

	// Create new authz and return
	authz, err := wfe.RA.NewAuthorization(init, currReg.ID)
	if err != nil {
		logEvent.AddError("unable to create new authz: %s", err)
		wfe.sendError(response, logEvent, core.ProblemDetailsForError(err, "Error creating new authz"), err)
		return
	}
	logEvent.Extra["AuthzID"] = authz.ID

	// Make a URL for this authz, then blow away the ID and RegID before serializing
	authzURL := wfe.AuthzBase + string(authz.ID)
	wfe.prepAuthorizationForDisplay(&authz)
	responseBody, err := json.Marshal(authz)
	if err != nil {
		// ServerInternal because we generated the authz, it should be OK
		wfe.sendError(response, logEvent, probs.ServerInternal("Error marshaling authz"), err)
		return
	}

	response.Header().Add("Location", authzURL)
	response.Header().Add("Link", link(wfe.NewCert, "next"))
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusCreated)
	if _, err = response.Write(responseBody); err != nil {
		logEvent.AddError(err.Error())
		wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
	}
}

// RevokeCertificate is used by clients to request the revocation of a cert.
func (wfe *WebFrontEndImpl) RevokeCertificate(logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {

	// We don't ask verifyPOST to verify there is a corresponding registration,
	// because anyone with the right private key can revoke a certificate.
	body, requestKey, registration, prob := wfe.verifyPOST(logEvent, request, false, core.ResourceRevokeCert)
	if prob != nil {
		// verifyPOST handles its own setting of logEvent.Errors
		wfe.sendError(response, logEvent, prob, nil)
		return
	}

	type RevokeRequest struct {
		CertificateDER core.JSONBuffer `json:"certificate"`
	}
	var revokeRequest RevokeRequest
	if err := json.Unmarshal(body, &revokeRequest); err != nil {
		logEvent.AddError(fmt.Sprintf("Couldn't unmarshal in revoke request %s", string(body)))
		wfe.sendError(response, logEvent, probs.Malformed("Unable to JSON parse revoke request"), err)
		return
	}
	providedCert, err := x509.ParseCertificate(revokeRequest.CertificateDER)
	if err != nil {
		logEvent.AddError("unable to parse revoke certificate DER: %s", err)
		wfe.sendError(response, logEvent, probs.Malformed("Unable to parse certificate DER"), err)
		return
	}

	serial := core.SerialToString(providedCert.SerialNumber)
	logEvent.Extra["ProvidedCertificateSerial"] = serial
	cert, err := wfe.SA.GetCertificate(serial)
	// TODO(#991): handle db errors better
	if err != nil || !bytes.Equal(cert.DER, revokeRequest.CertificateDER) {
		wfe.sendError(response, logEvent, probs.NotFound("No such certificate"), err)
		return
	}
	parsedCertificate, err := x509.ParseCertificate(cert.DER)
	if err != nil {
		// InternalServerError because this is a failure to decode from our DB.
		wfe.sendError(response, logEvent, probs.ServerInternal("invalid parse of stored certificate"), err)
		return
	}
	logEvent.Extra["RetrievedCertificateSerial"] = core.SerialToString(parsedCertificate.SerialNumber)
	logEvent.Extra["RetrievedCertificateDNSNames"] = parsedCertificate.DNSNames
	logEvent.Extra["RetrievedCertificateEmailAddresses"] = parsedCertificate.EmailAddresses
	logEvent.Extra["RetrievedCertificateIPAddresses"] = parsedCertificate.IPAddresses

	certStatus, err := wfe.SA.GetCertificateStatus(serial)
	if err != nil {
		logEvent.AddError("unable to get certificate status: %s", err)
		// TODO(#991): handle db errors
		wfe.sendError(response, logEvent, probs.NotFound("Certificate status not yet available"), err)
		return
	}
	logEvent.Extra["CertificateStatus"] = certStatus.Status

	if certStatus.Status == core.OCSPStatusRevoked {
		logEvent.AddError("Certificate already revoked: %#v", serial)
		wfe.sendError(response, logEvent, probs.Conflict("Certificate already revoked"), nil)
		return
	}

	// TODO: Implement method of revocation by authorizations on account.
	if !(core.KeyDigestEquals(requestKey, parsedCertificate.PublicKey) ||
		registration.ID == cert.RegistrationID) {
		wfe.sendError(response, logEvent,
			probs.Unauthorized("Revocation request must be signed by private key of cert to be revoked, or by the account key of the account that issued it."),
			nil)
		return
	}

	// Use revocation code 0, meaning "unspecified"
	err = wfe.RA.RevokeCertificateWithReg(*parsedCertificate, 0, registration.ID)
	if err != nil {
		logEvent.AddError("failed to revoke certificate: %s", err)
		wfe.sendError(response, logEvent, core.ProblemDetailsForError(err, "Failed to revoke certificate"), err)
	} else {
		wfe.log.Debug(fmt.Sprintf("Revoked %v", serial))
		response.WriteHeader(http.StatusOK)
	}
}

func (wfe *WebFrontEndImpl) logCsr(request *http.Request, cr core.CertificateRequest, registration core.Registration) {
	var csrLog = struct {
		ClientAddr   string
		CsrBase64    []byte
		Registration core.Registration
	}{
		ClientAddr:   getClientAddr(request),
		CsrBase64:    cr.Bytes,
		Registration: registration,
	}
	wfe.log.AuditObject("Certificate request", csrLog)
}

// NewCertificate is used by clients to request the issuance of a cert for an
// authorized identifier.
func (wfe *WebFrontEndImpl) NewCertificate(logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {
	body, _, reg, prob := wfe.verifyPOST(logEvent, request, true, core.ResourceNewCert)
	if prob != nil {
		// verifyPOST handles its own setting of logEvent.Errors
		wfe.sendError(response, logEvent, prob, nil)
		return
	}
	// Any version of the agreement is acceptable here. Version match is enforced in
	// wfe.Registration when agreeing the first time. Agreement updates happen
	// by mailing subscribers and don't require a registration update.
	if reg.Agreement == "" {
		wfe.sendError(response, logEvent, probs.Unauthorized("Must agree to subscriber agreement before any further actions"), nil)
		return
	}

	var certificateRequest core.CertificateRequest
	if err := json.Unmarshal(body, &certificateRequest); err != nil {
		logEvent.AddError("unable to JSON unmarshal CertificateRequest: %s", err)
		wfe.sendError(response, logEvent, probs.Malformed("Error unmarshaling certificate request"), err)
		return
	}
	wfe.logCsr(request, certificateRequest, reg)
	// Check that the key in the CSR is good. This will also be checked in the CA
	// component, but we want to discard CSRs with bad keys as early as possible
	// because (a) it's an easy check and we can save unnecessary requests and
	// bytes on the wire, and (b) the CA logs all rejections as audit events, but
	// a bad key from the client is just a malformed request and doesn't need to
	// be audited.
	if err := wfe.keyPolicy.GoodKey(certificateRequest.CSR.PublicKey); err != nil {
		logEvent.AddError("CSR public key failed GoodKey: %s", err)
		wfe.sendError(response, logEvent, probs.Malformed("Invalid key in certificate request :: %s", err), err)
		return
	}
	logEvent.Extra["CSRDNSNames"] = certificateRequest.CSR.DNSNames
	logEvent.Extra["CSREmailAddresses"] = certificateRequest.CSR.EmailAddresses
	logEvent.Extra["CSRIPAddresses"] = certificateRequest.CSR.IPAddresses

	// Create new certificate and return
	// TODO IMPORTANT: The RA trusts the WFE to provide the correct key. If the
	// WFE is compromised, *and* the attacker knows the public key of an account
	// authorized for target site, they could cause issuance for that site by
	// lying to the RA. We should probably pass a copy of the whole rquest to the
	// RA for secondary validation.
	cert, err := wfe.RA.NewCertificate(certificateRequest, reg.ID)
	if err != nil {
		logEvent.AddError("unable to create new cert: %s", err)
		wfe.sendError(response, logEvent, core.ProblemDetailsForError(err, "Error creating new cert"), err)
		return
	}

	// Make a URL for this certificate.
	// We use only the sequential part of the serial number, because it should
	// uniquely identify the certificate, and this makes it easy for anybody to
	// enumerate and mirror our certificates.
	parsedCertificate, err := x509.ParseCertificate([]byte(cert.DER))
	if err != nil {
		logEvent.AddError("unable to parse certificate: %s", err)
		wfe.sendError(response, logEvent, probs.Malformed("Unable to parse certificate"), err)
		return
	}
	serial := parsedCertificate.SerialNumber
	certURL := wfe.CertBase + core.SerialToString(serial)

	// TODO Content negotiation
	response.Header().Add("Location", certURL)
	response.Header().Add("Link", link(wfe.BaseURL+IssuerPath, "up"))
	response.Header().Set("Content-Type", "application/pkix-cert")
	response.WriteHeader(http.StatusCreated)
	if _, err = response.Write(cert.DER); err != nil {
		logEvent.AddError(err.Error())
		wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
	}
}

// Challenge handles POST requests to challenge URLs.  Such requests are clients'
// responses to the server's challenges.
func (wfe *WebFrontEndImpl) Challenge(
	logEvent *requestEvent,
	response http.ResponseWriter,
	request *http.Request) {

	notFound := func() {
		wfe.sendError(response, logEvent, probs.NotFound("No such challenge"), nil)
	}

	// Challenge URIs are of the form /acme/challenge/<auth id>/<challenge id>.
	// Here we parse out the id components. TODO: Use a better tool to parse out
	// URL structure: https://github.com/letsencrypt/boulder/issues/437
	slug := strings.Split(request.URL.Path[len(ChallengePath):], "/")
	if len(slug) != 2 {
		notFound()
		return
	}
	authorizationID := slug[0]
	challengeID, err := strconv.ParseInt(slug[1], 10, 64)
	if err != nil {
		notFound()
		return
	}
	logEvent.Extra["AuthorizationID"] = authorizationID
	logEvent.Extra["ChallengeID"] = challengeID

	authz, err := wfe.SA.GetAuthorization(authorizationID)
	if err != nil {
		// TODO(#1198): handle db errors etc
		notFound()
		return
	}

	// After expiring, challenges are inaccessible
	if authz.Expires == nil || authz.Expires.Before(wfe.clk.Now()) {
		logEvent.AddError("Authorization %v expired in the past (%v)", authz.ID, *authz.Expires)
		wfe.sendError(response, logEvent, probs.NotFound("Expired authorization"), nil)
		return
	}

	// Check that the requested challenge exists within the authorization
	challengeIndex := authz.FindChallenge(challengeID)
	if challengeIndex == -1 {
		notFound()
		return
	}
	challenge := authz.Challenges[challengeIndex]

	logEvent.Extra["ChallengeType"] = challenge.Type
	logEvent.Extra["AuthorizationRegistrationID"] = authz.RegistrationID
	logEvent.Extra["AuthorizationIdentifier"] = authz.Identifier
	logEvent.Extra["AuthorizationStatus"] = authz.Status
	logEvent.Extra["AuthorizationExpires"] = authz.Expires

	switch request.Method {
	case "GET", "HEAD":
		wfe.getChallenge(response, request, authz, &challenge, logEvent)

	case "POST":
		wfe.postChallenge(response, request, authz, challengeIndex, logEvent)
	}
}

// prepChallengeForDisplay takes a core.Challenge and prepares it for display to
// the client by filling in its URI field and clearing its AccountKey and ID
// fields.
// TODO: Come up with a cleaner way to do this.
// https://github.com/letsencrypt/boulder/issues/761
func (wfe *WebFrontEndImpl) prepChallengeForDisplay(authz core.Authorization, challenge *core.Challenge) {
	challenge.URI = fmt.Sprintf("%s%s/%d", wfe.ChallengeBase, authz.ID, challenge.ID)
	challenge.AccountKey = nil
	// 0 is considered "empty" for the purpose of the JSON omitempty tag.
	challenge.ID = 0
}

// prepAuthorizationForDisplay takes a core.Authorization and prepares it for
// display to the client by clearing its ID and RegistrationID fields, and
// preparing all its challenges.
func (wfe *WebFrontEndImpl) prepAuthorizationForDisplay(authz *core.Authorization) {
	for i := range authz.Challenges {
		wfe.prepChallengeForDisplay(*authz, &authz.Challenges[i])
	}
	authz.ID = ""
	authz.RegistrationID = 0
}

func (wfe *WebFrontEndImpl) getChallenge(
	response http.ResponseWriter,
	request *http.Request,
	authz core.Authorization,
	challenge *core.Challenge,
	logEvent *requestEvent) {

	wfe.prepChallengeForDisplay(authz, challenge)

	jsonReply, err := json.Marshal(challenge)
	if err != nil {
		// InternalServerError because this is a failure to decode data passed in
		// by the caller, which got it from the DB.
		logEvent.AddError("unable to marshal challenge: %s", err)
		wfe.sendError(response, logEvent, probs.ServerInternal("Failed to marshal challenge"), err)
		return
	}

	authzURL := wfe.AuthzBase + string(authz.ID)
	response.Header().Add("Location", challenge.URI)
	response.Header().Set("Content-Type", "application/json")
	response.Header().Add("Link", link(authzURL, "up"))
	response.WriteHeader(http.StatusAccepted)
	if _, err := response.Write(jsonReply); err != nil {
		wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
		logEvent.AddError(err.Error())
		return
	}
}

func (wfe *WebFrontEndImpl) postChallenge(
	response http.ResponseWriter,
	request *http.Request,
	authz core.Authorization,
	challengeIndex int,
	logEvent *requestEvent) {
	body, _, currReg, prob := wfe.verifyPOST(logEvent, request, true, core.ResourceChallenge)
	if prob != nil {
		// verifyPOST handles its own setting of logEvent.Errors
		wfe.sendError(response, logEvent, prob, nil)
		return
	}
	// Any version of the agreement is acceptable here. Version match is enforced in
	// wfe.Registration when agreeing the first time. Agreement updates happen
	// by mailing subscribers and don't require a registration update.
	if currReg.Agreement == "" {
		wfe.sendError(response, logEvent, probs.Unauthorized("Registration didn't agree to subscriber agreement before any further actions"), nil)
		return
	}

	// Check that the registration ID matching the key used matches
	// the registration ID on the authz object
	if currReg.ID != authz.RegistrationID {
		logEvent.AddError("User registration id: %d != Authorization registration id: %v", currReg.ID, authz.RegistrationID)
		wfe.sendError(response,
			logEvent,
			probs.Unauthorized("User registration ID doesn't match registration ID in authorization"),
			nil,
		)
		return
	}

	var challengeUpdate core.Challenge
	if err := json.Unmarshal(body, &challengeUpdate); err != nil {
		logEvent.AddError("error JSON unmarshalling challenge response: %s", err)
		wfe.sendError(response, logEvent, probs.Malformed("Error unmarshaling challenge response"), err)
		return
	}

	// Ask the RA to update this authorization
	updatedAuthorization, err := wfe.RA.UpdateAuthorization(authz, challengeIndex, challengeUpdate)
	if err != nil {
		logEvent.AddError("unable to update challenge: %s", err)
		wfe.sendError(response, logEvent, core.ProblemDetailsForError(err, "Unable to update challenge"), err)
		return
	}

	// assumption: UpdateAuthorization does not modify order of challenges
	challenge := updatedAuthorization.Challenges[challengeIndex]
	wfe.prepChallengeForDisplay(authz, &challenge)
	jsonReply, err := json.Marshal(challenge)
	if err != nil {
		// ServerInternal because we made the challenges, they should be OK
		logEvent.AddError("failed to marshal challenge: %s", err)
		wfe.sendError(response, logEvent, probs.ServerInternal("Failed to marshal challenge"), err)
		return
	}

	authzURL := wfe.AuthzBase + string(authz.ID)
	response.Header().Add("Location", challenge.URI)
	response.Header().Set("Content-Type", "application/json")
	response.Header().Add("Link", link(authzURL, "up"))
	response.WriteHeader(http.StatusAccepted)
	if _, err = response.Write(jsonReply); err != nil {
		logEvent.AddError(err.Error())
		wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
		return
	}
}

// Registration is used by a client to submit an update to their registration.
func (wfe *WebFrontEndImpl) Registration(logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {

	body, _, currReg, prob := wfe.verifyPOST(logEvent, request, true, core.ResourceRegistration)
	if prob != nil {
		// verifyPOST handles its own setting of logEvent.Errors
		wfe.sendError(response, logEvent, prob, nil)
		return
	}

	// Requests to this handler should have a path that leads to a known
	// registration
	idStr := parseIDFromPath(request.URL.Path)
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		logEvent.AddError("registration ID must be an integer, was %#v", idStr)
		wfe.sendError(response, logEvent, probs.Malformed("Registration ID must be an integer"), err)
		return
	} else if id <= 0 {
		msg := fmt.Sprintf("Registration ID must be a positive non-zero integer, was %d", id)
		logEvent.AddError(msg)
		wfe.sendError(response, logEvent, probs.Malformed(msg), nil)
		return
	} else if id != currReg.ID {
		logEvent.AddError("Request signing key did not match registration key: %d != %d", id, currReg.ID)
		wfe.sendError(response, logEvent, probs.Unauthorized("Request signing key did not match registration key"), nil)
		return
	}

	var update core.Registration
	err = json.Unmarshal(body, &update)
	if err != nil {
		logEvent.AddError("unable to JSON parse registration: %s", err)
		wfe.sendError(response, logEvent, probs.Malformed("Error unmarshaling registration"), err)
		return
	}

	if len(update.Agreement) > 0 && update.Agreement != wfe.SubscriberAgreementURL {
		msg := fmt.Sprintf("Provided agreement URL [%s] does not match current agreement URL [%s]", update.Agreement, wfe.SubscriberAgreementURL)
		logEvent.AddError(msg)
		wfe.sendError(response, logEvent, probs.Malformed(msg), nil)
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
		logEvent.AddError("unable to update registration: %s", err)
		wfe.sendError(response, logEvent, core.ProblemDetailsForError(err, "Unable to update registration"), err)
		return
	}

	jsonReply, err := json.Marshal(updatedReg)
	if err != nil {
		// ServerInternal because we just generated the reg, it should be OK
		logEvent.AddError("unable to marshal updated registration: %s", err)
		wfe.sendError(response, logEvent, probs.ServerInternal("Failed to marshal registration"), err)
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
func (wfe *WebFrontEndImpl) Authorization(logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {
	// Requests to this handler should have a path that leads to a known authz
	id := parseIDFromPath(request.URL.Path)
	authz, err := wfe.SA.GetAuthorization(id)
	if err != nil {
		logEvent.AddError("No such authorization at id %s", id)
		// TODO(#1199): handle db errors
		wfe.sendError(response, logEvent, probs.NotFound("Unable to find authorization"), err)
		return
	}
	logEvent.Extra["AuthorizationID"] = authz.ID
	logEvent.Extra["AuthorizationRegistrationID"] = authz.RegistrationID
	logEvent.Extra["AuthorizationIdentifier"] = authz.Identifier
	logEvent.Extra["AuthorizationStatus"] = authz.Status
	logEvent.Extra["AuthorizationExpires"] = authz.Expires

	// After expiring, authorizations are inaccessible
	if authz.Expires == nil || authz.Expires.Before(wfe.clk.Now()) {
		msg := fmt.Sprintf("Authorization %v expired in the past (%v)", authz.ID, *authz.Expires)
		logEvent.AddError(msg)
		wfe.sendError(response, logEvent, probs.NotFound("Expired authorization"), nil)
		return
	}

	wfe.prepAuthorizationForDisplay(&authz)

	jsonReply, err := json.Marshal(authz)
	if err != nil {
		// InternalServerError because this is a failure to decode from our DB.
		logEvent.AddError("Failed to JSON marshal authz: %s", err)
		wfe.sendError(response, logEvent, probs.ServerInternal("Failed to JSON marshal authz"), err)
		return
	}
	response.Header().Add("Link", link(wfe.NewCert, "next"))
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	if _, err = response.Write(jsonReply); err != nil {
		logEvent.AddError(err.Error())
		wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
	}
}

var allHex = regexp.MustCompile("^[0-9a-f]+$")

// Certificate is used by clients to request a copy of their current certificate, or to
// request a reissuance of the certificate.
func (wfe *WebFrontEndImpl) Certificate(logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {

	path := request.URL.Path
	// Certificate paths consist of the CertBase path, plus exactly sixteen hex
	// digits.
	if !strings.HasPrefix(path, CertPath) {
		logEvent.AddError("this request path should not have gotten to Certificate: %#v is not a prefix of %#v", path, CertPath)
		wfe.sendError(response, logEvent, probs.NotFound("Certificate not found"), nil)
		addNoCacheHeader(response)
		return
	}
	serial := path[len(CertPath):]
	if !core.ValidSerial(serial) {
		logEvent.AddError("certificate serial provided was not valid: %s", serial)
		wfe.sendError(response, logEvent, probs.NotFound("Certificate not found"), nil)
		addNoCacheHeader(response)
		return
	}
	logEvent.Extra["RequestedSerial"] = serial

	cert, err := wfe.SA.GetCertificate(serial)
	// TODO(#991): handle db errors
	if err != nil {
		logEvent.AddError("unable to get certificate by serial id %#v: %s", serial, err)
		if strings.HasPrefix(err.Error(), "gorp: multiple rows returned") {
			wfe.sendError(response, logEvent, probs.Conflict("Multiple certificates with same short serial"), err)
		} else {
			addNoCacheHeader(response)
			wfe.sendError(response, logEvent, probs.NotFound("Certificate not found"), err)
		}
		return
	}

	addCacheHeader(response, wfe.CertCacheDuration.Seconds())

	// TODO Content negotiation
	response.Header().Set("Content-Type", "application/pkix-cert")
	response.Header().Add("Link", link(IssuerPath, "up"))
	response.WriteHeader(http.StatusOK)
	if _, err = response.Write(cert.DER); err != nil {
		logEvent.AddError(err.Error())
		wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
	}
	return
}

// Terms is used by the client to obtain the current Terms of Service /
// Subscriber Agreement to which the subscriber must agree.
func (wfe *WebFrontEndImpl) Terms(logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {
	http.Redirect(response, request, wfe.SubscriberAgreementURL, http.StatusFound)
}

// Issuer obtains the issuer certificate used by this instance of Boulder.
func (wfe *WebFrontEndImpl) Issuer(logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {
	addCacheHeader(response, wfe.IssuerCacheDuration.Seconds())

	// TODO Content negotiation
	response.Header().Set("Content-Type", "application/pkix-cert")
	response.WriteHeader(http.StatusOK)
	if _, err := response.Write(wfe.IssuerCert); err != nil {
		logEvent.AddError("unable to write issuer certificate response: %s", err)
		wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
	}
}

// BuildID tells the requestor what build we're running.
func (wfe *WebFrontEndImpl) BuildID(logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "text/plain")
	response.WriteHeader(http.StatusOK)
	detailsString := fmt.Sprintf("Boulder=(%s %s)", core.GetBuildID(), core.GetBuildTime())
	if _, err := fmt.Fprintln(response, detailsString); err != nil {
		logEvent.AddError("unable to print build information: %s", err)
		wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
	}
}

// Options responds to an HTTP OPTIONS request.
func (wfe *WebFrontEndImpl) Options(response http.ResponseWriter, request *http.Request, methodsStr string, methodsMap map[string]bool) {
	// Every OPTIONS request gets an Allow header with a list of supported methods.
	response.Header().Set("Allow", methodsStr)

	// CORS preflight requests get additional headers. See
	// http://www.w3.org/TR/cors/#resource-preflight-requests
	reqMethod := request.Header.Get("Access-Control-Request-Method")
	if reqMethod == "" {
		reqMethod = "GET"
	}
	if methodsMap[reqMethod] {
		wfe.setCORSHeaders(response, request, methodsStr)
	}
}

// setCORSHeaders() tells the client that CORS is acceptable for this
// request. If allowMethods == "" the request is assumed to be a CORS
// actual request and no Access-Control-Allow-Methods header will be
// sent.
func (wfe *WebFrontEndImpl) setCORSHeaders(response http.ResponseWriter, request *http.Request, allowMethods string) {
	reqOrigin := request.Header.Get("Origin")
	if reqOrigin == "" {
		// This is not a CORS request.
		return
	}

	// Allow CORS if the current origin (or "*") is listed as an
	// allowed origin in config. Otherwise, disallow by returning
	// without setting any CORS headers.
	allow := false
	for _, ao := range wfe.AllowOrigins {
		if ao == "*" {
			response.Header().Set("Access-Control-Allow-Origin", "*")
			allow = true
			break
		} else if ao == reqOrigin {
			response.Header().Set("Vary", "Origin")
			response.Header().Set("Access-Control-Allow-Origin", ao)
			allow = true
			break
		}
	}
	if !allow {
		return
	}

	if allowMethods != "" {
		// For an OPTIONS request: allow all methods handled at this URL.
		response.Header().Set("Access-Control-Allow-Methods", allowMethods)
	}
	response.Header().Set("Access-Control-Expose-Headers", "Link, Replay-Nonce")
	response.Header().Set("Access-Control-Max-Age", "86400")
}
