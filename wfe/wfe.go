package wfe

import (
	"bytes"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jmhodges/clock"
	"golang.org/x/net/context"
	jose "gopkg.in/square/go-jose.v1"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/metrics/measured_http"
	"github.com/letsencrypt/boulder/nonce"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/revocation"
)

// Paths are the ACME-spec identified URL path-segments for various methods.
// NOTE: In metrics/measured_http we make the assumption that these are all
// lowercase plus hyphens. If you violate that assumption you should update
// measured_http.
const (
	directoryPath  = "/directory"
	newRegPath     = "/acme/new-reg"
	regPath        = "/acme/reg/"
	newAuthzPath   = "/acme/new-authz"
	authzPath      = "/acme/authz/"
	challengePath  = "/acme/challenge/"
	newCertPath    = "/acme/new-cert"
	certPath       = "/acme/cert/"
	revokeCertPath = "/acme/revoke-cert"
	termsPath      = "/terms"
	issuerPath     = "/acme/issuer-cert"
	buildIDPath    = "/build"
	rolloverPath   = "/acme/key-change"
)

// WebFrontEndImpl provides all the logic for Boulder's web-facing interface,
// i.e., ACME.  Its members configure the paths for various ACME functions,
// plus a few other data items used in ACME.  Its methods are primarily handlers
// for HTTPS requests for the various ACME functions.
type WebFrontEndImpl struct {
	RA    core.RegistrationAuthority
	SA    core.StorageGetter
	stats metrics.Scope
	log   blog.Logger
	clk   clock.Clock

	// URL configuration parameters
	BaseURL string

	// Issuer certificate (DER) for /acme/issuer-cert
	IssuerCert []byte

	// URL to the current subscriber agreement (should contain some version identifier)
	SubscriberAgreementURL string

	// Register of anti-replay nonces
	nonceService *nonce.NonceService

	// Key policy.
	keyPolicy goodkey.KeyPolicy

	// Cache settings
	CertCacheDuration           time.Duration
	CertNoCacheExpirationWindow time.Duration
	IndexCacheDuration          time.Duration
	IssuerCacheDuration         time.Duration

	// CORS settings
	AllowOrigins []string

	// Maximum duration of a request
	RequestTimeout time.Duration

	AcceptRevocationReason bool
	AllowAuthzDeactivation bool
}

// signatureValidationError indicates that the user's signature could not
// be verified, either through adversarial activity, or misconfiguration of
// the user client.
type signatureValidationError string

func (e signatureValidationError) Error() string { return string(e) }

// NewWebFrontEndImpl constructs a web service for Boulder
func NewWebFrontEndImpl(
	stats metrics.Scope,
	clk clock.Clock,
	keyPolicy goodkey.KeyPolicy,
	logger blog.Logger,
) (WebFrontEndImpl, error) {
	nonceService, err := nonce.NewNonceService(stats)
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
// * Set a no cache header
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
	handler := http.StripPrefix(pattern, &topHandler{
		log: wfe.log,
		clk: clock.Default(),
		wfe: wfeHandlerFunc(func(ctx context.Context, logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {
			// We do not propagate errors here, because (1) they should be
			// transient, and (2) they fail closed.
			nonce, err := wfe.nonceService.Nonce()
			if err == nil {
				response.Header().Set("Replay-Nonce", nonce)
				logEvent.ResponseNonce = nonce
			} else {
				logEvent.AddError("unable to make nonce: %s", err)
			}

			logEvent.Endpoint = pattern
			if request.URL != nil {
				logEvent.Endpoint = path.Join(logEvent.Endpoint, request.URL.Path)
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

			// No cache header is set for all requests, succeed or fail.
			addNoCacheHeader(response)

			if !methodsMap[request.Method] {
				response.Header().Set("Allow", methodsStr)
				wfe.sendError(response, logEvent, probs.MethodNotAllowed(), nil)
				return
			}

			wfe.setCORSHeaders(response, request, "")

			timeout := wfe.RequestTimeout
			if timeout == 0 {
				timeout = 5 * time.Minute
			}
			ctx, cancel := context.WithTimeout(ctx, timeout)
			// TODO(riking): add request context using WithValue

			// Call the wrapped handler.
			h(ctx, logEvent, response, request)
			cancel()
		}),
	})
	mux.Handle(pattern, handler)
}

func marshalIndent(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

func (wfe *WebFrontEndImpl) writeJsonResponse(response http.ResponseWriter, logEvent *requestEvent, status int, v interface{}) error {
	jsonReply, err := marshalIndent(v)
	if err != nil {
		return err // All callers are responsible for handling this error
	}

	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_, err = response.Write(jsonReply)
	if err != nil {
		// Don't worry about returning this error because the caller will
		// never handle it.
		wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
		logEvent.AddError(fmt.Sprintf("failed to write response: %s", err))
	}
	return nil
}

func (wfe *WebFrontEndImpl) relativeEndpoint(request *http.Request, endpoint string) string {
	var result string
	proto := "http"
	host := request.Host

	// If the request was received via TLS, use `https://` for the protocol
	if request.TLS != nil {
		proto = "https"
	}

	// Allow upstream proxies  to specify the forwarded protocol. Allow this value
	// to override our own guess.
	if specifiedProto := request.Header.Get("X-Forwarded-Proto"); specifiedProto != "" {
		proto = specifiedProto
	}

	// Default to "localhost" when no request.Host is provided. Otherwise requests
	// with an empty `Host` produce results like `http:///acme/new-authz`
	if request.Host == "" {
		host = "localhost"
	}

	if wfe.BaseURL != "" {
		result = fmt.Sprintf("%s%s", wfe.BaseURL, endpoint)
	} else {
		resultUrl := url.URL{Scheme: proto, Host: host, Path: endpoint}
		result = resultUrl.String()
	}

	return result
}

const randomDirKeyExplanationLink = "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417"

func (wfe *WebFrontEndImpl) relativeDirectory(request *http.Request, directory map[string]interface{}) ([]byte, error) {
	// Create an empty map sized equal to the provided directory to store the
	// relative-ized result
	relativeDir := make(map[string]interface{}, len(directory))

	// Copy each entry of the provided directory into the new relative map. If
	// `wfe.BaseURL` != "", use the old behaviour and prefix each endpoint with
	// the `BaseURL`. Otherwise, prefix each endpoint using the request protocol
	// & host.
	for k, v := range directory {
		if features.Enabled(features.RandomDirectoryEntry) && v == randomDirKeyExplanationLink {
			relativeDir[k] = v
			continue
		}
		switch v := v.(type) {
		case string:
			// Only relative-ize top level string values, e.g. not the "meta" element
			relativeDir[k] = wfe.relativeEndpoint(request, v)
		default:
			// If it isn't a string, put it into the results unmodified
			relativeDir[k] = v
		}
	}

	directoryJSON, err := marshalIndent(relativeDir)
	// This should never happen since we are just marshalling known strings
	if err != nil {
		return nil, err
	}

	return directoryJSON, nil
}

// Handler returns an http.Handler that uses various functions for
// various ACME-specified paths.
func (wfe *WebFrontEndImpl) Handler() http.Handler {
	m := http.NewServeMux()
	wfe.HandleFunc(m, directoryPath, wfe.Directory, "GET")
	wfe.HandleFunc(m, newRegPath, wfe.NewRegistration, "POST")
	wfe.HandleFunc(m, newAuthzPath, wfe.NewAuthorization, "POST")
	wfe.HandleFunc(m, newCertPath, wfe.NewCertificate, "POST")
	wfe.HandleFunc(m, regPath, wfe.Registration, "POST")
	wfe.HandleFunc(m, authzPath, wfe.Authorization, "GET", "POST")
	wfe.HandleFunc(m, challengePath, wfe.Challenge, "GET", "POST")
	wfe.HandleFunc(m, certPath, wfe.Certificate, "GET")
	wfe.HandleFunc(m, revokeCertPath, wfe.RevokeCertificate, "POST")
	wfe.HandleFunc(m, termsPath, wfe.Terms, "GET")
	wfe.HandleFunc(m, issuerPath, wfe.Issuer, "GET")
	wfe.HandleFunc(m, buildIDPath, wfe.BuildID, "GET")
	if features.Enabled(features.AllowKeyRollover) {
		wfe.HandleFunc(m, rolloverPath, wfe.KeyRollover, "POST")
	}
	// We don't use our special HandleFunc for "/" because it matches everything,
	// meaning we can wind up returning 405 when we mean to return 404. See
	// https://github.com/letsencrypt/boulder/issues/717
	m.Handle("/", &topHandler{
		log: wfe.log,
		clk: clock.Default(),
		wfe: wfeHandlerFunc(wfe.Index),
	})
	return measured_http.New(m, wfe.clk)
}

// Method implementations

// Index serves a simple identification page. It is not part of the ACME spec.
func (wfe *WebFrontEndImpl) Index(ctx context.Context, logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {
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

	addNoCacheHeader(response)
	response.Header().Set("Content-Type", "text/html")
	response.Write([]byte(fmt.Sprintf(`<html>
		<body>
			This is an <a href="https://github.com/ietf-wg-acme/acme/">ACME</a>
			Certificate Authority running <a href="https://github.com/letsencrypt/boulder">Boulder</a>.
			JSON directory is available at <a href="%s">%s</a>.
		</body>
	</html>
	`, directoryPath, directoryPath)))
}

func addNoCacheHeader(w http.ResponseWriter) {
	w.Header().Add("Cache-Control", "public, max-age=0, no-cache")
}

func addRequesterHeader(w http.ResponseWriter, requester int64) {
	if requester > 0 {
		w.Header().Set("Boulder-Requester", fmt.Sprintf("%d", requester))
	}
}

// Directory is an HTTP request handler that provides the directory
// object stored in the WFE's DirectoryEndpoints member with paths prefixed
// using the `request.Host` of the HTTP request.
func (wfe *WebFrontEndImpl) Directory(ctx context.Context, logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {
	directoryEndpoints := map[string]interface{}{
		"new-reg":     newRegPath,
		"new-authz":   newAuthzPath,
		"new-cert":    newCertPath,
		"revoke-cert": revokeCertPath,
	}

	// Versions of Certbot pre-0.6.0 (named LetsEncryptPythonClient at the time) break when they
	// encounter a directory containing elements they don't expect so we gate
	// adding new directory fields for clients matching this UA.
	clientDirChangeIntolerant := strings.HasPrefix(request.UserAgent(), "LetsEncryptPythonClient")
	if features.Enabled(features.AllowKeyRollover) && !clientDirChangeIntolerant {
		directoryEndpoints["key-change"] = rolloverPath
	}
	if features.Enabled(features.RandomDirectoryEntry) && !clientDirChangeIntolerant {
		// Add a random key to the directory in order to make sure that clients don't hardcode an
		// expected set of keys. This ensures that we can properly extend the directory when we
		// need to add a new endpoint or meta element.
		directoryEndpoints[core.RandomString(8)] = randomDirKeyExplanationLink
	}
	if features.Enabled(features.DirectoryMeta) && !clientDirChangeIntolerant {
		// ACME since draft-02 describes an optional "meta" directory entry. The
		// meta entry may optionally contain a "terms-of-service" URI for the
		// current ToS.
		directoryEndpoints["meta"] = map[string]string{
			"terms-of-service": wfe.SubscriberAgreementURL,
		}
	}

	response.Header().Set("Content-Type", "application/json")

	relDir, err := wfe.relativeDirectory(request, directoryEndpoints)
	if err != nil {
		marshalProb := probs.ServerInternal("unable to marshal JSON directory")
		wfe.sendError(response, logEvent, marshalProb, nil)
		return
	}

	response.Write(relDir)
}

const (
	unknownKey = "No registration exists matching provided key"
)

func (wfe *WebFrontEndImpl) extractJWSKey(body string) (*jose.JsonWebKey, *jose.JsonWebSignature, error) {
	parsedJws, err := jose.ParseSigned(body)
	if err != nil {
		wfe.stats.Inc("Errors.UnableToParseJWS", 1)
		return nil, nil, errors.New("Parse error reading JWS")
	}

	if len(parsedJws.Signatures) > 1 {
		wfe.stats.Inc("Errors.TooManyJWSSignaturesInPOST", 1)
		return nil, nil, errors.New("Too many signatures in POST body")
	}
	if len(parsedJws.Signatures) == 0 {
		wfe.stats.Inc("Errors.JWSNotSignedInPOST", 1)
		return nil, nil, errors.New("POST JWS not signed")
	}

	key := parsedJws.Signatures[0].Header.JsonWebKey
	if key == nil {
		wfe.stats.Inc("Errors.NoJWKInJWSSignatureHeader", 1)
		return nil, nil, errors.New("No JWK in JWS header")
	}

	if !key.Valid() {
		wfe.stats.Inc("Errors.InvalidJWK", 1)
		return nil, nil, errors.New("Invalid JWK in JWS header")
	}

	return key, parsedJws, nil
}

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
func (wfe *WebFrontEndImpl) verifyPOST(ctx context.Context, logEvent *requestEvent, request *http.Request, regCheck bool, resource core.AcmeResource) ([]byte, *jose.JsonWebKey, core.Registration, *probs.ProblemDetails) {
	// TODO: We should return a pointer to a registration, which can be nil,
	// rather the a registration value with a sentinel value.
	// https://github.com/letsencrypt/boulder/issues/877
	reg := core.Registration{ID: 0}

	if _, ok := request.Header["Content-Length"]; !ok {
		wfe.stats.Inc("HTTP.ClientErrors.LengthRequiredError", 1)
		logEvent.AddError("missing Content-Length header on POST")
		return nil, nil, reg, probs.ContentLengthRequired()
	}

	// Read body
	if request.Body == nil {
		wfe.stats.Inc("Errors.NoPOSTBody", 1)
		logEvent.AddError("no body on POST")
		return nil, nil, reg, probs.Malformed("No body on POST")
	}

	bodyBytes, err := ioutil.ReadAll(request.Body)
	if err != nil {
		wfe.stats.Inc("Errors.UnableToReadRequestBody", 1)
		logEvent.AddError("unable to read request body")
		return nil, nil, reg, probs.ServerInternal("unable to read request body")
	}

	body := string(bodyBytes)

	// Verify JWS
	// NOTE: It might seem insecure for the WFE to be trusted to verify
	// client requests, i.e., that the verification should be done at the
	// RA.  However the WFE is the RA's only view of the outside world
	// *anyway*, so it could always lie about what key was used by faking
	// the signature itself.
	submittedKey, parsedJws, err := wfe.extractJWSKey(body)
	if err != nil {
		logEvent.AddError(err.Error())
		return nil, nil, reg, probs.Malformed(err.Error())
	}

	var key *jose.JsonWebKey
	reg, err = wfe.SA.GetRegistrationByKey(ctx, submittedKey)
	// Special case: If no registration was found, but regCheck is false, use an
	// empty registration and the submitted key. The caller is expected to do some
	// validation on the returned key.
	if berrors.Is(err, berrors.NotFound) && !regCheck {
		// When looking up keys from the registrations DB, we can be confident they
		// are "good". But when we are verifying against any submitted key, we want
		// to check its quality before doing the verify.
		if err = wfe.keyPolicy.GoodKey(submittedKey.Key); err != nil {
			wfe.stats.Inc("Errors.JWKRejectedByGoodKey", 1)
			logEvent.AddError("JWK in request was rejected by GoodKey: %s", err)
			return nil, nil, reg, probs.Malformed(err.Error())
		}
		key = submittedKey
	} else if err != nil {
		// For all other errors, or if regCheck is true, return error immediately.
		wfe.stats.Inc("Errors.UnableToGetRegistrationByKey", 1)
		logEvent.AddError("unable to fetch registration by the given JWK: %s", err)
		if berrors.Is(err, berrors.NotFound) {
			return nil, nil, reg, probs.Unauthorized(unknownKey)
		}

		return nil, nil, reg, probs.ServerInternal("Failed to get registration by key")
	} else {
		// If the lookup was successful, use that key.
		key = reg.Key
		logEvent.Requester = reg.ID
		logEvent.Contacts = reg.Contact
	}

	// Only check for validity if we are actually checking the registration
	if regCheck && features.Enabled(features.AllowAccountDeactivation) && reg.Status != core.StatusValid {
		return nil, nil, reg, probs.Unauthorized(fmt.Sprintf("Registration is not valid, has status '%s'", reg.Status))
	}

	if statName, err := checkAlgorithm(key, parsedJws); err != nil {
		wfe.stats.Inc(statName, 1)
		return nil, nil, reg, probs.Malformed(err.Error())
	}

	payload, err := parsedJws.Verify(key)
	if err != nil {
		wfe.stats.Inc("Errors.JWSVerificationFailed", 1)
		n := len(body)
		if n > 100 {
			n = 100
		}
		logEvent.AddError("verification of JWS with the JWK failed: %v; body: %s", err, body[:n])
		return nil, nil, reg, probs.Malformed("JWS verification error")
	}
	logEvent.Payload = string(payload)

	// Check that the request has a known anti-replay nonce
	nonce := parsedJws.Signatures[0].Header.Nonce
	logEvent.RequestNonce = nonce
	if len(nonce) == 0 {
		wfe.stats.Inc("Errors.JWSMissingNonce", 1)
		logEvent.AddError("JWS is missing an anti-replay nonce")
		return nil, nil, reg, probs.BadNonce("JWS has no anti-replay nonce")
	} else if !wfe.nonceService.Valid(nonce) {
		wfe.stats.Inc("Errors.JWSInvalidNonce", 1)
		logEvent.AddError("JWS has an invalid anti-replay nonce: %s", nonce)
		return nil, nil, reg, probs.BadNonce(fmt.Sprintf("JWS has invalid anti-replay nonce %v", nonce))
	}

	// Check that the "resource" field is present and has the correct value
	var parsedRequest struct {
		Resource string `json:"resource"`
	}
	err = json.Unmarshal([]byte(payload), &parsedRequest)
	if err != nil {
		wfe.stats.Inc("Errors.UnparseableJWSPayload", 1)
		logEvent.AddError("unable to JSON parse resource from JWS payload: %s", err)
		return nil, nil, reg, probs.Malformed("Request payload did not parse as JSON")
	}
	if parsedRequest.Resource == "" {
		wfe.stats.Inc("Errors.NoResourceInJWSPayload", 1)
		logEvent.AddError("JWS request payload does not specify a resource")
		return nil, nil, reg, probs.Malformed("Request payload does not specify a resource")
	} else if resource != core.AcmeResource(parsedRequest.Resource) {
		wfe.stats.Inc("Errors.MismatchedResourceInJWSPayload", 1)
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
		if ierr != nil {
			wfe.log.AuditErr(fmt.Sprintf("Internal error - %s - %s", prob.Detail, ierr))
		} else {
			wfe.log.AuditErr(fmt.Sprintf("Internal error - %s", prob.Detail))
		}
	}

	problemDoc, err := marshalIndent(prob)
	if err != nil {
		wfe.log.AuditErr(fmt.Sprintf("Could not marshal error message: %s - %+v", err, prob))
		problemDoc = []byte("{\"detail\": \"Problem marshalling error message.\"}")
	}

	// Paraphrased from
	// https://golang.org/src/net/http/server.go#L1272
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(code)
	response.Write(problemDoc)

	problemSegments := strings.Split(string(prob.Type), ":")
	if len(problemSegments) > 0 {
		wfe.stats.Inc(fmt.Sprintf("HTTP.ProblemTypes.%s", problemSegments[len(problemSegments)-1]), 1)
	}
}

func link(url, relation string) string {
	return fmt.Sprintf("<%s>;rel=\"%s\"", url, relation)
}

// NewRegistration is used by clients to submit a new registration/account
func (wfe *WebFrontEndImpl) NewRegistration(ctx context.Context, logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {

	body, key, _, prob := wfe.verifyPOST(ctx, logEvent, request, false, core.ResourceNewReg)
	addRequesterHeader(response, logEvent.Requester)
	if prob != nil {
		// verifyPOST handles its own setting of logEvent.Errors
		wfe.sendError(response, logEvent, prob, nil)
		return
	}

	if existingReg, err := wfe.SA.GetRegistrationByKey(ctx, key); err == nil {
		response.Header().Set("Location", wfe.relativeEndpoint(request, fmt.Sprintf("%s%d", regPath, existingReg.ID)))
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
	init.Key = key
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

	reg, err := wfe.RA.NewRegistration(ctx, init)
	if err != nil {
		logEvent.AddError("unable to create new registration: %s", err)
		wfe.sendError(response, logEvent, problemDetailsForError(err, "Error creating new registration"), err)
		return
	}
	logEvent.Requester = reg.ID
	addRequesterHeader(response, reg.ID)
	logEvent.Contacts = reg.Contact

	// Use an explicitly typed variable. Otherwise `go vet' incorrectly complains
	// that reg.ID is a string being passed to %d.
	regURL := wfe.relativeEndpoint(request, fmt.Sprintf("%s%d", regPath, reg.ID))

	response.Header().Add("Location", regURL)
	response.Header().Add("Link", link(wfe.relativeEndpoint(request, newAuthzPath), "next"))
	if len(wfe.SubscriberAgreementURL) > 0 {
		response.Header().Add("Link", link(wfe.SubscriberAgreementURL, "terms-of-service"))
	}

	err = wfe.writeJsonResponse(response, logEvent, http.StatusCreated, reg)
	if err != nil {
		// ServerInternal because we just created this registration, and it
		// should be OK.
		logEvent.AddError("unable to marshal registration: %s", err)
		wfe.sendError(response, logEvent, probs.ServerInternal("Error marshaling registration"), err)
		return
	}
}

// NewAuthorization is used by clients to submit a new ID Authorization
func (wfe *WebFrontEndImpl) NewAuthorization(ctx context.Context, logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {
	body, _, currReg, prob := wfe.verifyPOST(ctx, logEvent, request, true, core.ResourceNewAuthz)
	addRequesterHeader(response, logEvent.Requester)
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
	authz, err := wfe.RA.NewAuthorization(ctx, init, currReg.ID)
	if err != nil {
		logEvent.AddError("unable to create new authz: %s", err)
		wfe.sendError(response, logEvent, problemDetailsForError(err, "Error creating new authz"), err)
		return
	}
	logEvent.Extra["AuthzID"] = authz.ID

	// Make a URL for this authz, then blow away the ID and RegID before serializing
	authzURL := wfe.relativeEndpoint(request, authzPath+string(authz.ID))
	wfe.prepAuthorizationForDisplay(request, &authz)

	response.Header().Add("Location", authzURL)
	response.Header().Add("Link", link(wfe.relativeEndpoint(request, newCertPath), "next"))

	err = wfe.writeJsonResponse(response, logEvent, http.StatusCreated, authz)
	if err != nil {
		// ServerInternal because we generated the authz, it should be OK
		wfe.sendError(response, logEvent, probs.ServerInternal("Error marshaling authz"), err)
		return
	}
}

func (wfe *WebFrontEndImpl) regHoldsAuthorizations(ctx context.Context, regID int64, names []string) (bool, error) {
	authz, err := wfe.SA.GetValidAuthorizations(ctx, regID, names, wfe.clk.Now())
	if err != nil {
		return false, err
	}
	if len(names) != len(authz) {
		return false, nil
	}
	missingNames := false
	for _, name := range names {
		if _, present := authz[name]; !present {
			missingNames = true
		}
	}
	return !missingNames, nil
}

// RevokeCertificate is used by clients to request the revocation of a cert.
func (wfe *WebFrontEndImpl) RevokeCertificate(ctx context.Context, logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {
	// We don't ask verifyPOST to verify there is a corresponding registration,
	// because anyone with the right private key can revoke a certificate.
	body, requestKey, registration, prob := wfe.verifyPOST(ctx, logEvent, request, false, core.ResourceRevokeCert)
	addRequesterHeader(response, logEvent.Requester)
	if prob != nil {
		// verifyPOST handles its own setting of logEvent.Errors
		wfe.sendError(response, logEvent, prob, nil)
		return
	}

	type RevokeRequest struct {
		CertificateDER core.JSONBuffer    `json:"certificate"`
		Reason         *revocation.Reason `json:"reason"`
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
	cert, err := wfe.SA.GetCertificate(ctx, serial)
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

	certStatus, err := wfe.SA.GetCertificateStatus(ctx, serial)
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

	if !(core.KeyDigestEquals(requestKey, parsedCertificate.PublicKey) || registration.ID == cert.RegistrationID) {
		valid, err := wfe.regHoldsAuthorizations(ctx, registration.ID, parsedCertificate.DNSNames)
		if err != nil {
			logEvent.AddError("regHoldsAuthorizations failed: %s", err)
			wfe.sendError(response, logEvent, probs.ServerInternal("Failed to retrieve authorizations for names in certificate"), err)
			return
		}
		if !valid {
			wfe.sendError(response, logEvent,
				probs.Unauthorized("Revocation request must be signed by private key of cert to be revoked, by the "+
					"account key of the account that issued it, or by the account key of an account that holds valid "+
					"authorizations for all names in the certificate."),
				nil)
			return
		}
	}

	reason := revocation.Reason(0)
	if revokeRequest.Reason != nil && wfe.AcceptRevocationReason {
		if _, present := revocation.UserAllowedReasons[*revokeRequest.Reason]; !present {
			logEvent.AddError("unsupported revocation reason code provided")
			wfe.sendError(response, logEvent, probs.Malformed("unsupported revocation reason code provided"), nil)
			return
		}
		reason = *revokeRequest.Reason
	}

	err = wfe.RA.RevokeCertificateWithReg(ctx, *parsedCertificate, reason, registration.ID)
	if err != nil {
		logEvent.AddError("failed to revoke certificate: %s", err)
		wfe.sendError(response, logEvent, problemDetailsForError(err, "Failed to revoke certificate"), err)
	} else {
		wfe.log.Debug(fmt.Sprintf("Revoked %v", serial))
		response.WriteHeader(http.StatusOK)
	}
}

func (wfe *WebFrontEndImpl) logCsr(request *http.Request, cr core.CertificateRequest, registration core.Registration) {
	var csrLog = struct {
		ClientAddr   string
		CSR          string
		Registration core.Registration
	}{
		ClientAddr:   getClientAddr(request),
		CSR:          hex.EncodeToString(cr.Bytes),
		Registration: registration,
	}
	wfe.log.AuditObject("Certificate request", csrLog)
}

// NewCertificate is used by clients to request the issuance of a cert for an
// authorized identifier.
func (wfe *WebFrontEndImpl) NewCertificate(ctx context.Context, logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {
	body, _, reg, prob := wfe.verifyPOST(ctx, logEvent, request, true, core.ResourceNewCert)
	addRequesterHeader(response, logEvent.Requester)
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

	var rawCSR core.RawCertificateRequest
	err := json.Unmarshal(body, &rawCSR)
	if err != nil {
		logEvent.AddError("unable to JSON unmarshal CertificateRequest: %s", err)
		wfe.sendError(response, logEvent, probs.Malformed("Error unmarshaling certificate request"), err)
		return
	}
	// Assuming a properly formatted CSR there should be two four byte SEQUENCE
	// declarations then a two byte integer declaration which defines the version
	// of the CSR. If those two bytes (at offset 8 and 9) and equal to 2 and 0
	// then the CSR was generated by a pre-1.0.2 version of OpenSSL with a client
	// which didn't explicitly set the version causing the integer to be malformed
	// and encoding/asn1 will refuse to parse it. If this is the case exit early
	// with a more useful error message.
	if len(rawCSR.CSR) >= 10 && rawCSR.CSR[8] == 2 && rawCSR.CSR[9] == 0 {
		logEvent.AddError("Pre-1.0.2 OpenSSL malformed CSR")
		wfe.sendError(
			response,
			logEvent,
			probs.Malformed("CSR generated using a pre-1.0.2 OpenSSL with a client that doesn't properly specify the CSR version. See https://community.letsencrypt.org/t/openssl-bug-information/19591"),
			nil,
		)
		return
	}

	certificateRequest := core.CertificateRequest{Bytes: rawCSR.CSR}
	certificateRequest.CSR, err = x509.ParseCertificateRequest(rawCSR.CSR)
	if err != nil {
		logEvent.AddError("unable to parse certificate request: %s", err)
		wfe.sendError(response, logEvent, probs.Malformed("Error parsing certificate request: %s", err), err)
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
	// lying to the RA. We should probably pass a copy of the whole request to the
	// RA for secondary validation.
	cert, err := wfe.RA.NewCertificate(ctx, certificateRequest, reg.ID)
	if err != nil {
		logEvent.AddError("unable to create new cert: %s", err)
		wfe.sendError(response, logEvent, problemDetailsForError(err, "Error creating new cert"), err)
		return
	}

	// Make a URL for this certificate.
	// We use only the sequential part of the serial number, because it should
	// uniquely identify the certificate, and this makes it easy for anybody to
	// enumerate and mirror our certificates.
	parsedCertificate, err := x509.ParseCertificate([]byte(cert.DER))
	if err != nil {
		logEvent.AddError("unable to parse certificate: %s", err)
		wfe.sendError(response, logEvent, probs.ServerInternal("Unable to parse certificate"), err)
		return
	}
	serial := parsedCertificate.SerialNumber
	certURL := wfe.relativeEndpoint(request, certPath+core.SerialToString(serial))

	// TODO Content negotiation
	response.Header().Add("Location", certURL)
	if features.Enabled(features.UseAIAIssuerURL) {
		if err = wfe.addIssuingCertificateURLs(response, parsedCertificate.IssuingCertificateURL); err != nil {
			logEvent.AddError("unable to parse IssuingCertificateURL: %s", err)
			wfe.sendError(response, logEvent, probs.ServerInternal("unable to parse IssuingCertificateURL"), err)
			return
		}
	} else {
		relativeIssuerPath := wfe.relativeEndpoint(request, issuerPath)
		response.Header().Add("Link", link(relativeIssuerPath, "up"))
	}
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
	ctx context.Context,
	logEvent *requestEvent,
	response http.ResponseWriter,
	request *http.Request) {

	notFound := func() {
		wfe.sendError(response, logEvent, probs.NotFound("No such challenge"), nil)
	}

	// Challenge URIs are of the form /acme/challenge/<auth id>/<challenge id>.
	// Here we parse out the id components.
	slug := strings.Split(request.URL.Path, "/")
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

	authz, err := wfe.SA.GetAuthorization(ctx, authorizationID)
	if err != nil {
		if err == sql.ErrNoRows {
			notFound()
		} else {
			wfe.sendError(response, logEvent, probs.ServerInternal("Problem getting authorization"), err)
		}
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
		wfe.getChallenge(ctx, response, request, authz, &challenge, logEvent)

	case "POST":
		wfe.postChallenge(ctx, response, request, authz, challengeIndex, logEvent)
	}
}

// prepChallengeForDisplay takes a core.Challenge and prepares it for display to
// the client by filling in its URI field and clearing its ID field.
// TODO: Come up with a cleaner way to do this.
// https://github.com/letsencrypt/boulder/issues/761
func (wfe *WebFrontEndImpl) prepChallengeForDisplay(request *http.Request, authz core.Authorization, challenge *core.Challenge) {
	challenge.URI = wfe.relativeEndpoint(request, fmt.Sprintf("%s%s/%d", challengePath, authz.ID, challenge.ID))
	// 0 is considered "empty" for the purpose of the JSON omitempty tag.
	challenge.ID = 0
}

// prepAuthorizationForDisplay takes a core.Authorization and prepares it for
// display to the client by clearing its ID and RegistrationID fields, and
// preparing all its challenges.
func (wfe *WebFrontEndImpl) prepAuthorizationForDisplay(request *http.Request, authz *core.Authorization) {
	for i := range authz.Challenges {
		wfe.prepChallengeForDisplay(request, *authz, &authz.Challenges[i])
	}
	authz.ID = ""
	authz.RegistrationID = 0
}

func (wfe *WebFrontEndImpl) getChallenge(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	authz core.Authorization,
	challenge *core.Challenge,
	logEvent *requestEvent) {

	wfe.prepChallengeForDisplay(request, authz, challenge)

	authzURL := wfe.relativeEndpoint(request, authzPath+string(authz.ID))
	response.Header().Add("Location", challenge.URI)
	response.Header().Add("Link", link(authzURL, "up"))

	err := wfe.writeJsonResponse(response, logEvent, http.StatusAccepted, challenge)
	if err != nil {
		// InternalServerError because this is a failure to decode data passed in
		// by the caller, which got it from the DB.
		logEvent.AddError("unable to marshal challenge: %s", err)
		wfe.sendError(response, logEvent, probs.ServerInternal("Failed to marshal challenge"), err)
		return
	}
}

func (wfe *WebFrontEndImpl) postChallenge(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	authz core.Authorization,
	challengeIndex int,
	logEvent *requestEvent) {
	body, _, currReg, prob := wfe.verifyPOST(ctx, logEvent, request, true, core.ResourceChallenge)
	addRequesterHeader(response, logEvent.Requester)
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
		logEvent.AddError("error JSON unmarshaling challenge response: %s", err)
		wfe.sendError(response, logEvent, probs.Malformed("Error unmarshaling challenge response"), err)
		return
	}

	// Ask the RA to update this authorization
	updatedAuthorization, err := wfe.RA.UpdateAuthorization(ctx, authz, challengeIndex, challengeUpdate)
	if err != nil {
		logEvent.AddError("unable to update challenge: %s", err)
		wfe.sendError(response, logEvent, problemDetailsForError(err, "Unable to update challenge"), err)
		return
	}

	// assumption: UpdateAuthorization does not modify order of challenges
	challenge := updatedAuthorization.Challenges[challengeIndex]
	wfe.prepChallengeForDisplay(request, authz, &challenge)

	authzURL := wfe.relativeEndpoint(request, authzPath+string(authz.ID))
	response.Header().Add("Location", challenge.URI)
	response.Header().Add("Link", link(authzURL, "up"))

	err = wfe.writeJsonResponse(response, logEvent, http.StatusAccepted, challenge)
	if err != nil {
		// ServerInternal because we made the challenges, they should be OK
		logEvent.AddError("failed to marshal challenge: %s", err)
		wfe.sendError(response, logEvent, probs.ServerInternal("Failed to marshal challenge"), err)
		return
	}
}

// Registration is used by a client to submit an update to their registration.
func (wfe *WebFrontEndImpl) Registration(ctx context.Context, logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {

	body, _, currReg, prob := wfe.verifyPOST(ctx, logEvent, request, true, core.ResourceRegistration)
	addRequesterHeader(response, logEvent.Requester)
	if prob != nil {
		// verifyPOST handles its own setting of logEvent.Errors
		wfe.sendError(response, logEvent, prob, nil)
		return
	}

	// Requests to this handler should have a path that leads to a known
	// registration
	idStr := request.URL.Path
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

	// People *will* POST their full registrations to this endpoint, including
	// the 'valid' status, to avoid always failing out when that happens only
	// attempt to deactivate if the provided status is different from their current
	// status.
	//
	// If a user tries to send both a deactivation request and an update to their
	// contacts or subscriber agreement URL the deactivation will take place and
	// return before an update would be performed.
	if features.Enabled(features.AllowAccountDeactivation) && (update.Status != "" && update.Status != currReg.Status) {
		if update.Status != core.StatusDeactivated {
			wfe.sendError(response, logEvent, probs.Malformed("Invalid value provided for status field"), nil)
			return
		}
		wfe.deactivateRegistration(ctx, currReg, response, request, logEvent)
		return
	}

	// If a user POSTs their registration object including a previously valid
	// agreement URL but that URL has since changed we will fail out here
	// since the update agreement URL doesn't match the current URL. To fix that we
	// only fail if the sent URL doesn't match the currently valid agreement URL
	// and it doesn't match the URL currently stored in the registration
	// in the database. The RA understands the user isn't actually trying to
	// update the agreement but since we do an early check here in order to prevent
	// extraneous requests to the RA we have to add this bypass.
	if len(update.Agreement) > 0 && update.Agreement != currReg.Agreement &&
		update.Agreement != wfe.SubscriberAgreementURL {
		msg := fmt.Sprintf("Provided agreement URL [%s] does not match current agreement URL [%s]", update.Agreement, wfe.SubscriberAgreementURL)
		logEvent.AddError(msg)
		wfe.sendError(response, logEvent, probs.Malformed(msg), nil)
		return
	}

	// Registration objects contain a JWK object which are merged in UpdateRegistration
	// if it is different from the existing registration key. Since this isn't how you
	// update the key we just copy the existing one into the update object here. This
	// ensures the key isn't changed and that we can cleanly serialize the update as
	// JSON to send via RPC to the RA.
	update.Key = currReg.Key

	updatedReg, err := wfe.RA.UpdateRegistration(ctx, currReg, update)
	if err != nil {
		logEvent.AddError("unable to update registration: %s", err)
		wfe.sendError(response, logEvent, problemDetailsForError(err, "Unable to update registration"), err)
		return
	}

	response.Header().Add("Link", link(wfe.relativeEndpoint(request, newAuthzPath), "next"))
	if len(wfe.SubscriberAgreementURL) > 0 {
		response.Header().Add("Link", link(wfe.SubscriberAgreementURL, "terms-of-service"))
	}

	err = wfe.writeJsonResponse(response, logEvent, http.StatusAccepted, updatedReg)
	if err != nil {
		// ServerInternal because we just generated the reg, it should be OK
		logEvent.AddError("unable to marshal updated registration: %s", err)
		wfe.sendError(response, logEvent, probs.ServerInternal("Failed to marshal registration"), err)
		return
	}
}

func (wfe *WebFrontEndImpl) deactivateAuthorization(ctx context.Context, authz *core.Authorization, logEvent *requestEvent, response http.ResponseWriter, request *http.Request) bool {
	body, _, reg, prob := wfe.verifyPOST(ctx, logEvent, request, true, core.ResourceAuthz)
	addRequesterHeader(response, logEvent.Requester)
	if prob != nil {
		wfe.sendError(response, logEvent, prob, nil)
		return false
	}
	if reg.ID != authz.RegistrationID {
		logEvent.AddError("registration ID doesn't match ID for authorization")
		wfe.sendError(response, logEvent, probs.Unauthorized("Registration ID doesn't match ID for authorization"), nil)
		return false
	}
	var req struct {
		Status core.AcmeStatus
	}
	err := json.Unmarshal(body, &req)
	if err != nil {
		wfe.sendError(response, logEvent, probs.Malformed("Error unmarshaling JSON"), err)
		return false
	}
	if req.Status != core.StatusDeactivated {
		logEvent.AddError("invalid status value")
		wfe.sendError(response, logEvent, probs.Malformed("Invalid status value"), err)
		return false
	}
	err = wfe.RA.DeactivateAuthorization(ctx, *authz)
	if err != nil {
		logEvent.AddError("unable to deactivate authorization", err)
		wfe.sendError(response, logEvent, problemDetailsForError(err, "Error deactivating authorization"), err)
		return false
	}
	// Since the authorization passed to DeactivateAuthorization isn't
	// mutated locally by the function we must manually set the status
	// here before displaying the authorization to the user
	authz.Status = core.StatusDeactivated
	return true
}

// Authorization is used by clients to submit an update to one of their
// authorizations.
func (wfe *WebFrontEndImpl) Authorization(ctx context.Context, logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {
	// Requests to this handler should have a path that leads to a known authz
	id := request.URL.Path
	authz, err := wfe.SA.GetAuthorization(ctx, id)
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

	if wfe.AllowAuthzDeactivation && request.Method == "POST" {
		// If the deactivation fails return early as errors and return codes
		// have already been set. Otherwise continue so that the user gets
		// sent the deactivated authorization.
		if !wfe.deactivateAuthorization(ctx, &authz, logEvent, response, request) {
			return
		}
	}

	wfe.prepAuthorizationForDisplay(request, &authz)

	response.Header().Add("Link", link(wfe.relativeEndpoint(request, newCertPath), "next"))

	err = wfe.writeJsonResponse(response, logEvent, http.StatusOK, authz)
	if err != nil {
		// InternalServerError because this is a failure to decode from our DB.
		logEvent.AddError("Failed to JSON marshal authz: %s", err)
		wfe.sendError(response, logEvent, probs.ServerInternal("Failed to JSON marshal authz"), err)
		return
	}
}

var allHex = regexp.MustCompile("^[0-9a-f]+$")

// Certificate is used by clients to request a copy of their current certificate, or to
// request a reissuance of the certificate.
func (wfe *WebFrontEndImpl) Certificate(ctx context.Context, logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {

	serial := request.URL.Path
	// Certificate paths consist of the CertBase path, plus exactly sixteen hex
	// digits.
	if !core.ValidSerial(serial) {
		logEvent.AddError("certificate serial provided was not valid: %s", serial)
		wfe.sendError(response, logEvent, probs.NotFound("Certificate not found"), nil)
		return
	}
	logEvent.Extra["RequestedSerial"] = serial

	cert, err := wfe.SA.GetCertificate(ctx, serial)
	// TODO(#991): handle db errors
	if err != nil {
		logEvent.AddError("unable to get certificate by serial id %#v: %s", serial, err)
		if strings.HasPrefix(err.Error(), "gorp: multiple rows returned") {
			wfe.sendError(response, logEvent, probs.Conflict("Multiple certificates with same short serial"), err)
		} else {
			wfe.sendError(response, logEvent, probs.NotFound("Certificate not found"), err)
		}
		return
	}

	// TODO Content negotiation
	response.Header().Set("Content-Type", "application/pkix-cert")
	if features.Enabled(features.UseAIAIssuerURL) {
		parsedCertificate, err := x509.ParseCertificate([]byte(cert.DER))
		if err != nil {
			logEvent.AddError("unable to parse certificate: %s", err)
			wfe.sendError(response, logEvent, probs.ServerInternal("Unable to parse certificate"), err)
			return
		}
		if err = wfe.addIssuingCertificateURLs(response, parsedCertificate.IssuingCertificateURL); err != nil {
			logEvent.AddError("unable to parse IssuingCertificateURL: %s", err)
			wfe.sendError(response, logEvent, probs.ServerInternal("unable to parse IssuingCertificateURL"), err)
			return
		}
	} else {
		relativeIssuerPath := wfe.relativeEndpoint(request, issuerPath)
		response.Header().Add("Link", link(relativeIssuerPath, "up"))
	}
	response.WriteHeader(http.StatusOK)
	if _, err = response.Write(cert.DER); err != nil {
		logEvent.AddError(err.Error())
		wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
	}
	return
}

// Terms is used by the client to obtain the current Terms of Service /
// Subscriber Agreement to which the subscriber must agree.
func (wfe *WebFrontEndImpl) Terms(ctx context.Context, logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {
	http.Redirect(response, request, wfe.SubscriberAgreementURL, http.StatusFound)
}

// Issuer obtains the issuer certificate used by this instance of Boulder.
func (wfe *WebFrontEndImpl) Issuer(ctx context.Context, logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {
	// TODO Content negotiation
	response.Header().Set("Content-Type", "application/pkix-cert")
	response.WriteHeader(http.StatusOK)
	if _, err := response.Write(wfe.IssuerCert); err != nil {
		logEvent.AddError("unable to write issuer certificate response: %s", err)
		wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
	}
}

// BuildID tells the requestor what build we're running.
func (wfe *WebFrontEndImpl) BuildID(ctx context.Context, logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {
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

// KeyRollover allows a user to change their signing key
func (wfe *WebFrontEndImpl) KeyRollover(ctx context.Context, logEvent *requestEvent, response http.ResponseWriter, request *http.Request) {
	body, _, reg, prob := wfe.verifyPOST(ctx, logEvent, request, true, core.ResourceKeyChange)
	addRequesterHeader(response, logEvent.Requester)
	if prob != nil {
		wfe.sendError(response, logEvent, prob, nil)
		return
	}

	// Parse as JWS
	newKey, parsedJWS, err := wfe.extractJWSKey(string(body))
	if err != nil {
		logEvent.AddError(err.Error())
		wfe.sendError(response, logEvent, probs.Malformed(err.Error()), err)
		return
	}
	payload, err := parsedJWS.Verify(newKey)
	if err != nil {
		logEvent.AddError("verification of the inner JWS with the inner JWK failed: %v", err)
		wfe.sendError(response, logEvent, probs.Malformed("JWS verification error"), err)
		return
	}
	var rolloverRequest struct {
		NewKey  jose.JsonWebKey
		Account string
	}
	err = json.Unmarshal(payload, &rolloverRequest)
	if err != nil {
		logEvent.AddError("unable to JSON parse resource from JWS payload: %s", err)
		wfe.sendError(response, logEvent, probs.Malformed("Request payload did not parse as JSON"), nil)
		return
	}

	if wfe.relativeEndpoint(request, fmt.Sprintf("%s%d", regPath, reg.ID)) != rolloverRequest.Account {
		logEvent.AddError("incorrect account URL provided")
		wfe.sendError(response, logEvent, probs.Malformed("Incorrect account URL provided in payload"), nil)
		return
	}

	keysEqual, err := core.PublicKeysEqual(rolloverRequest.NewKey.Key, newKey.Key)
	if err != nil {
		logEvent.AddError("unable to marshal new key: %s", err)
		wfe.sendError(response, logEvent, probs.Malformed("Unable to marshal new JWK"), nil)
		return
	}
	if !keysEqual {
		logEvent.AddError("new key in inner payload doesn't match key used to sign inner JWS")
		wfe.sendError(response, logEvent, probs.Malformed("New JWK in inner payload doesn't match key used to sign inner JWS"), nil)
		return
	}

	// Update registration key
	updatedReg, err := wfe.RA.UpdateRegistration(ctx, reg, core.Registration{Key: newKey})
	if err != nil {
		logEvent.AddError("unable to update registration: %s", err)
		wfe.sendError(response, logEvent, problemDetailsForError(err, "Unable to update registration"), err)
		return
	}

	jsonReply, err := marshalIndent(updatedReg)
	if err != nil {
		logEvent.AddError("unable to marshal updated registration: %s", err)
		wfe.sendError(response, logEvent, probs.ServerInternal("Failed to marshal registration"), err)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	response.Write(jsonReply)
}

func (wfe *WebFrontEndImpl) deactivateRegistration(ctx context.Context, reg core.Registration, response http.ResponseWriter, request *http.Request, logEvent *requestEvent) {
	err := wfe.RA.DeactivateRegistration(ctx, reg)
	if err != nil {
		logEvent.AddError("unable to deactivate registration", err)
		wfe.sendError(response, logEvent, problemDetailsForError(err, "Error deactivating registration"), err)
		return
	}
	reg.Status = core.StatusDeactivated

	err = wfe.writeJsonResponse(response, logEvent, http.StatusOK, reg)
	if err != nil {
		// ServerInternal because registration is from DB and should be fine
		logEvent.AddError("unable to marshal updated registration: %s", err)
		wfe.sendError(response, logEvent, probs.ServerInternal("Failed to marshal registration"), err)
		return
	}
}

// addIssuingCertificateURLs() adds Issuing Certificate URLs (AIA) from a
// X.509 certificate to the HTTP response. If the IssuingCertificateURL
// in a certificate is not https://, it will be upgraded to https://
func (wfe *WebFrontEndImpl) addIssuingCertificateURLs(response http.ResponseWriter, issuingCertificateURL []string) error {
	for _, rawURL := range issuingCertificateURL {
		parsedURI, err := url.ParseRequestURI(rawURL)
		if err != nil {
			return err
		}
		parsedURI.Scheme = "https"
		response.Header().Add("Link", link(parsedURI.String(), "up"))
	}
	return nil
}
