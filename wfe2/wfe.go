package wfe2

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	jose "gopkg.in/square/go-jose.v2"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/context"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/goodkey"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/metrics/measured_http"
	"github.com/letsencrypt/boulder/nonce"
	"github.com/letsencrypt/boulder/probs"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/revocation"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/web"
)

// Paths are the ACME-spec identified URL path-segments for various methods.
// NOTE: In metrics/measured_http we make the assumption that these are all
// lowercase plus hyphens. If you violate that assumption you should update
// measured_http.
const (
	directoryPath  = "/directory"
	newAcctPath    = "/acme/new-acct"
	acctPath       = "/acme/acct/"
	authzPath      = "/acme/authz/"
	challengePath  = "/acme/challenge/"
	certPath       = "/acme/cert/"
	revokeCertPath = "/acme/revoke-cert"
	termsPath      = "/terms"
	issuerPath     = "/acme/issuer-cert"
	buildIDPath    = "/build"
	rolloverPath   = "/acme/key-change"
	newOrderPath   = "/acme/new-order"
	orderPath      = "/acme/order/"
)

// WebFrontEndImpl provides all the logic for Boulder's web-facing interface,
// i.e., ACME.  Its members configure the paths for various ACME functions,
// plus a few other data items used in ACME.  Its methods are primarily handlers
// for HTTPS requests for the various ACME functions.
type WebFrontEndImpl struct {
	RA    core.RegistrationAuthority
	SA    core.StorageGetter
	log   blog.Logger
	clk   clock.Clock
	stats wfe2Stats

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
		keyPolicy:    keyPolicy,
		stats:        initStats(stats),
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
func (wfe *WebFrontEndImpl) HandleFunc(mux *http.ServeMux, pattern string, h web.WFEHandlerFunc, methods ...string) {
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
	handler := http.StripPrefix(pattern, &web.TopHandler{
		Log: wfe.log,
		Clk: clock.Default(),
		WFE: web.WFEHandlerFunc(func(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
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

func (wfe *WebFrontEndImpl) writeJsonResponse(response http.ResponseWriter, logEvent *web.RequestEvent, status int, v interface{}) error {
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

// requestProto returns "http" for HTTP requests and "https" for HTTPS
// requests. It supports the use of "X-Forwarded-Proto" to override the protocol.
func requestProto(request *http.Request) string {
	proto := "http"

	// If the request was received via TLS, use `https://` for the protocol
	if request.TLS != nil {
		proto = "https"
	}

	// Allow upstream proxies  to specify the forwarded protocol. Allow this value
	// to override our own guess.
	if specifiedProto := request.Header.Get("X-Forwarded-Proto"); specifiedProto != "" {
		proto = specifiedProto
	}

	return proto
}

func (wfe *WebFrontEndImpl) relativeEndpoint(request *http.Request, endpoint string) string {
	var result string
	host := request.Host
	proto := requestProto(request)

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
		if v == randomDirKeyExplanationLink {
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
	wfe.HandleFunc(m, newAcctPath, wfe.NewAccount, "POST")
	wfe.HandleFunc(m, acctPath, wfe.Account, "POST")
	wfe.HandleFunc(m, authzPath, wfe.Authorization, "GET", "POST")
	wfe.HandleFunc(m, challengePath, wfe.Challenge, "GET", "POST")
	wfe.HandleFunc(m, certPath, wfe.Certificate, "GET")
	wfe.HandleFunc(m, revokeCertPath, wfe.RevokeCertificate, "POST")
	wfe.HandleFunc(m, termsPath, wfe.Terms, "GET")
	wfe.HandleFunc(m, issuerPath, wfe.Issuer, "GET")
	wfe.HandleFunc(m, buildIDPath, wfe.BuildID, "GET")
	wfe.HandleFunc(m, rolloverPath, wfe.KeyRollover, "POST")
	wfe.HandleFunc(m, newOrderPath, wfe.NewOrder, "POST")
	wfe.HandleFunc(m, orderPath, wfe.Order, "GET")
	// We don't use our special HandleFunc for "/" because it matches everything,
	// meaning we can wind up returning 405 when we mean to return 404. See
	// https://github.com/letsencrypt/boulder/issues/717
	m.Handle("/", &web.TopHandler{
		Log: wfe.log,
		Clk: clock.Default(),
		WFE: web.WFEHandlerFunc(wfe.Index),
	})
	return measured_http.New(m, wfe.clk)
}

// Method implementations

// Index serves a simple identification page. It is not part of the ACME spec.
func (wfe *WebFrontEndImpl) Index(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
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
		wfe.sendError(response, logEvent, probs.MethodNotAllowed(), nil)
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
func (wfe *WebFrontEndImpl) Directory(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
	directoryEndpoints := map[string]interface{}{
		"new-account": newAcctPath,
		"revoke-cert": revokeCertPath,
	}

	directoryEndpoints["key-change"] = rolloverPath

	// Add a random key to the directory in order to make sure that clients don't hardcode an
	// expected set of keys. This ensures that we can properly extend the directory when we
	// need to add a new endpoint or meta element.
	directoryEndpoints[core.RandomString(8)] = randomDirKeyExplanationLink

	// ACME since draft-02 describes an optional "meta" directory entry. The
	// meta entry may optionally contain a "terms-of-service" URI for the
	// current ToS.
	directoryEndpoints["meta"] = map[string]string{
		"terms-of-service": wfe.SubscriberAgreementURL,
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

// sendError sends an error response represented by the given ProblemDetails,
// and, if the ProblemDetails.Type is ServerInternalProblem, audit logs the
// internal ierr. The rendered Problem will have its Type prefixed with the ACME
// v2 error namespace.
func (wfe *WebFrontEndImpl) sendError(response http.ResponseWriter, logEvent *web.RequestEvent, prob *probs.ProblemDetails, ierr error) {
	// Determine the HTTP status code to use for this problem
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

	// Increment a stat for this problem type
	wfe.stats.httpErrorCount.With(prometheus.Labels{"type": string(prob.Type)}).Inc()

	// Prefix the problem type with the ACME V2 error namespace and marshal to JSON
	prob.Type = probs.V2ErrorNS + prob.Type
	problemDoc, err := marshalIndent(prob)
	if err != nil {
		wfe.log.AuditErr(fmt.Sprintf("Could not marshal error message: %s - %+v", err, prob))
		problemDoc = []byte("{\"detail\": \"Problem marshalling error message.\"}")
	}

	// Write the JSON problem response
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(code)
	response.Write(problemDoc)
}

func link(url, relation string) string {
	return fmt.Sprintf("<%s>;rel=\"%s\"", url, relation)
}

// NewAccount is used by clients to submit a new account
func (wfe *WebFrontEndImpl) NewAccount(
	ctx context.Context,
	logEvent *web.RequestEvent,
	response http.ResponseWriter,
	request *http.Request) {

	// NewAccount uses `validSelfAuthenticatedPOST` instead of
	// `validPOSTforAccount` because there is no account to authenticate against
	// until after it is created!
	body, key, prob := wfe.validSelfAuthenticatedPOST(request, logEvent)
	if prob != nil {
		// validSelfAuthenticatedPOST handles its own setting of logEvent.Errors
		wfe.sendError(response, logEvent, prob, nil)
		return
	}

	if existingAcct, err := wfe.SA.GetRegistrationByKey(ctx, key); err == nil {
		response.Header().Set("Location",
			wfe.relativeEndpoint(request, fmt.Sprintf("%s%d", acctPath, existingAcct.ID)))
		// TODO(#595): check for missing account err
		wfe.sendError(response, logEvent, probs.Conflict("Account key is already in use"), err)
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

	acct, err := wfe.RA.NewRegistration(ctx, init)
	if err != nil {
		logEvent.AddError("unable to create new account: %s", err)
		wfe.sendError(response, logEvent,
			web.ProblemDetailsForError(err, "Error creating new account"), err)
		return
	}
	logEvent.Requester = acct.ID
	addRequesterHeader(response, acct.ID)
	logEvent.Contacts = acct.Contact

	acctURL := wfe.relativeEndpoint(request, fmt.Sprintf("%s%d", acctPath, acct.ID))

	response.Header().Add("Location", acctURL)
	if len(wfe.SubscriberAgreementURL) > 0 {
		response.Header().Add("Link", link(wfe.SubscriberAgreementURL, "terms-of-service"))
	}

	err = wfe.writeJsonResponse(response, logEvent, http.StatusCreated, acct)
	if err != nil {
		// ServerInternal because we just created this account, and it
		// should be OK.
		logEvent.AddError("unable to marshal account: %s", err)
		wfe.sendError(response, logEvent, probs.ServerInternal("Error marshaling account"), err)
		return
	}
}

func (wfe *WebFrontEndImpl) acctHoldsAuthorizations(ctx context.Context, acctID int64, names []string) (bool, error) {
	authz, err := wfe.SA.GetValidAuthorizations(ctx, acctID, names, wfe.clk.Now())
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

// authorizedToRevokeCert is a callback function that can be used to validate if
// a given requester is authorized to revoke the certificate parsed out of the
// revocation request from the inner JWS. If the requester is not authorized to
// revoke the certificate a problem is returned. It is expected to be a closure
// containing additional state (an account ID or key) that will be used to make
// the decision.
type authorizedToRevokeCert func(*x509.Certificate) *probs.ProblemDetails

// processRevocation accepts the payload for a revocation request along with
// an account ID and a callback used to decide if the requester is authorized to
// revoke a given certificate. If the request can not  be authenticated or the
// requester is not authorized to revoke the certificate requested a problem is
// returned. Otherwise the certificate is marked revoked through the SA.
func (wfe *WebFrontEndImpl) processRevocation(
	ctx context.Context,
	jwsBody []byte,
	acctID int64,
	authorizedToRevoke authorizedToRevokeCert,
	request *http.Request,
	logEvent *web.RequestEvent) *probs.ProblemDetails {
	// Read the revoke request from the JWS payload
	var revokeRequest struct {
		CertificateDER core.JSONBuffer    `json:"certificate"`
		Reason         *revocation.Reason `json:"reason"`
	}
	if err := json.Unmarshal(jwsBody, &revokeRequest); err != nil {
		return probs.Malformed("Unable to JSON parse revoke request")
	}

	// Parse the provided certificate
	providedCert, err := x509.ParseCertificate(revokeRequest.CertificateDER)
	if err != nil {
		return probs.Malformed("Unable to parse certificate DER")
	}

	// Compute and record the serial number of the provided certificate
	serial := core.SerialToString(providedCert.SerialNumber)
	logEvent.Extra["ProvidedCertificateSerial"] = serial

	// Lookup the certificate by the serial. If the certificate wasn't found, or
	// it wasn't a byte-for-byte match to the certificate requested for
	// revocation, return an error
	cert, err := wfe.SA.GetCertificate(ctx, serial)
	if err != nil || !bytes.Equal(cert.DER, revokeRequest.CertificateDER) {
		return probs.NotFound("No such certificate")
	}

	// Parse the certificate into memory
	parsedCertificate, err := x509.ParseCertificate(cert.DER)
	if err != nil {
		// InternalServerError because cert.DER came from our own DB.
		return probs.ServerInternal("invalid parse of stored certificate")
	}
	logEvent.Extra["RetrievedCertificateSerial"] = core.SerialToString(parsedCertificate.SerialNumber)
	logEvent.Extra["RetrievedCertificateDNSNames"] = parsedCertificate.DNSNames

	// Check the certificate status for the provided certificate to see if it is
	// already revoked
	certStatus, err := wfe.SA.GetCertificateStatus(ctx, serial)
	if err != nil {
		return probs.NotFound("Certificate status not yet available")
	}
	logEvent.Extra["CertificateStatus"] = certStatus.Status

	if certStatus.Status == core.OCSPStatusRevoked {
		return probs.Conflict("Certificate already revoked")
	}

	// Validate that the requester is authenticated to revoke the given certificate
	prob := authorizedToRevoke(parsedCertificate)
	if prob != nil {
		return prob
	}

	// Verify the revocation reason supplied is allowed
	reason := revocation.Reason(0)
	if revokeRequest.Reason != nil && wfe.AcceptRevocationReason {
		if _, present := revocation.UserAllowedReasons[*revokeRequest.Reason]; !present {
			return probs.Malformed("unsupported revocation reason code provided")
		}
		reason = *revokeRequest.Reason
	}

	// Revoke the certificate. AcctID may be 0 if there is no associated account
	// (e.g. it was a self-authenticated JWS using the certificate public key)
	if err := wfe.RA.RevokeCertificateWithReg(ctx, *parsedCertificate, reason, acctID); err != nil {
		return web.ProblemDetailsForError(err, "Failed to revoke certificate")
	}

	wfe.log.Debug(fmt.Sprintf("Revoked %v", serial))
	return nil
}

// revokeCertByKeyID processes an outer JWS as a revocation request that is
// authenticated by a KeyID and the associated account.
func (wfe *WebFrontEndImpl) revokeCertByKeyID(
	ctx context.Context,
	outerJWS *jose.JSONWebSignature,
	request *http.Request,
	logEvent *web.RequestEvent) *probs.ProblemDetails {
	// For Key ID revocations we authenticate the outer JWS by using
	// `validJWSForAccount` similar to other WFE endpoints
	jwsBody, _, acct, prob := wfe.validJWSForAccount(outerJWS, request, ctx, logEvent)
	if prob != nil {
		return prob
	}
	// For Key ID revocations we decide if an account is able to revoke a specific
	// certificate by checking that the account has valid authorizations for all
	// of the names in the certificate
	authorizedToRevoke := func(parsedCertificate *x509.Certificate) *probs.ProblemDetails {
		valid, err := wfe.acctHoldsAuthorizations(ctx, acct.ID, parsedCertificate.DNSNames)
		if err != nil {
			return probs.ServerInternal("Failed to retrieve authorizations for names in certificate")
		}
		if !valid {
			return probs.Unauthorized(
				"The key ID specified in the revocation request does not hold valid authorizations for all names in the certificate to be revoked")
		}
		return nil
	}
	return wfe.processRevocation(ctx, jwsBody, acct.ID, authorizedToRevoke, request, logEvent)
}

// revokeCertByJWK processes an outer JWS as a revocation request that is
// authenticated by an embedded JWK. E.g. in the case where someone is
// requesting a revocation by using the keypair associated with the certificate
// to be revoked
func (wfe *WebFrontEndImpl) revokeCertByJWK(
	ctx context.Context,
	outerJWS *jose.JSONWebSignature,
	request *http.Request,
	logEvent *web.RequestEvent) *probs.ProblemDetails {
	// We maintain the requestKey as a var that is closed-over by the
	// `authorizedToRevoke` function to use
	var requestKey *jose.JSONWebKey
	// For embedded JWK revocations we authenticate the outer JWS by using
	// `validSelfAuthenticatedJWS` similar to new-reg and key rollover.
	// We do *not* use `validSelfAuthenticatedPOST` here because we've already
	// read the HTTP request body in `parseJWSRequest` and it is now empty.
	jwsBody, jwk, prob := wfe.validSelfAuthenticatedJWS(outerJWS, request, logEvent)
	if prob != nil {
		return prob
	}
	requestKey = jwk
	// For embedded JWK revocations we decide if a requester is able to revoke a specific
	// certificate by checking that to-be-revoked certificate has the same public
	// key as the JWK that was used to authenticate the request
	authorizedToRevoke := func(parsedCertificate *x509.Certificate) *probs.ProblemDetails {
		if !core.KeyDigestEquals(requestKey, parsedCertificate.PublicKey) {
			return probs.Unauthorized(
				"JWK embedded in revocation request must be the same public key as the cert to be revoked")
		}
		return nil
	}
	// We use `0` as the account ID provided to `processRevocation` because this
	// is a self-authenticated request.
	return wfe.processRevocation(ctx, jwsBody, 0, authorizedToRevoke, request, logEvent)
}

// RevokeCertificate is used by clients to request the revocation of a cert. The
// revocation request is handled uniquely based on the method of authentication
// used.
func (wfe *WebFrontEndImpl) RevokeCertificate(
	ctx context.Context,
	logEvent *web.RequestEvent,
	response http.ResponseWriter,
	request *http.Request) {

	// The ACME specification handles the verification of revocation requests
	// differently from other endpoints. For this reason we do *not* immediately
	// call `wfe.validPOSTForAccount` like all of the other endpoints.
	// For this endpoint we need to accept a JWS with an embedded JWK, or a JWS
	// with an embedded key ID, handling each case differently in terms of which
	// certificates are authorized to be revoked by the requester

	// Parse the JWS from the HTTP Request
	jws, prob := wfe.parseJWSRequest(request)
	if prob != nil {
		wfe.sendError(response, logEvent, prob, nil)
		return
	}

	// Figure out which type of authentication this JWS uses
	authType, prob := checkJWSAuthType(jws)
	if prob != nil {
		wfe.sendError(response, logEvent, prob, nil)
		return
	}

	// Handle the revocation request according to how it is authenticated, or if
	// the authentication type is unknown, error immediately
	if authType == embeddedKeyID {
		prob = wfe.revokeCertByKeyID(ctx, jws, request, logEvent)
		addRequesterHeader(response, logEvent.Requester)
	} else if authType == embeddedJWK {
		prob = wfe.revokeCertByJWK(ctx, jws, request, logEvent)
	} else {
		prob = probs.Malformed("Malformed JWS, no KeyID or embedded JWK")
	}
	if prob != nil {
		wfe.sendError(response, logEvent, prob, nil)
		return
	}
	response.WriteHeader(http.StatusOK)
}

func (wfe *WebFrontEndImpl) logCsr(request *http.Request, cr core.CertificateRequest, account core.Registration) {
	var csrLog = struct {
		ClientAddr   string
		CSR          string
		Registration core.Registration
	}{
		ClientAddr:   web.GetClientAddr(request),
		CSR:          hex.EncodeToString(cr.Bytes),
		Registration: account,
	}
	wfe.log.AuditObject("Certificate request", csrLog)
}

// Challenge handles POST requests to challenge URLs.  Such requests are clients'
// responses to the server's challenges.
func (wfe *WebFrontEndImpl) Challenge(
	ctx context.Context,
	logEvent *web.RequestEvent,
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
		if berrors.Is(err, berrors.NotFound) {
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
func (wfe *WebFrontEndImpl) prepChallengeForDisplay(request *http.Request, authz core.Authorization, challenge *core.Challenge) {
	// Update the challenge URI to be relative to the HTTP request Host
	challenge.URI = wfe.relativeEndpoint(request, fmt.Sprintf("%s%s/%d", challengePath, authz.ID, challenge.ID))
	// Ensure the challenge ID isn't written. 0 is considered "empty" for the purpose of the JSON omitempty tag.
	challenge.ID = 0

	// Historically the Type field of a problem was always prefixed with a static
	// error namespace. To support the V2 API and migrating to the correct IETF
	// namespace we now prefix the Type with the correct namespace at runtime when
	// we write the problem JSON to the user. We skip this process if the
	// challenge error type has already been prefixed with the V1ErrorNS.
	if challenge.Error != nil && !strings.HasPrefix(string(challenge.Error.Type), probs.V1ErrorNS) {
		challenge.Error.Type = probs.V2ErrorNS + challenge.Error.Type
	}
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
	logEvent *web.RequestEvent) {

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
	logEvent *web.RequestEvent) {
	body, _, currAcct, prob := wfe.validPOSTForAccount(request, ctx, logEvent)
	addRequesterHeader(response, logEvent.Requester)
	if prob != nil {
		// validPOSTForAccount handles its own setting of logEvent.Errors
		wfe.sendError(response, logEvent, prob, nil)
		return
	}
	// Any version of the agreement is acceptable here. Version match is enforced in
	// wfe.Account when agreeing the first time. Agreement updates happen
	// by mailing subscribers and don't require an account update.
	if currAcct.Agreement == "" {
		wfe.sendError(response, logEvent,
			probs.Unauthorized("Account must agree to subscriber agreement before any further actions"), nil)
		return
	}

	// Check that the account ID matching the key used matches
	// the account ID on the authz object
	if currAcct.ID != authz.RegistrationID {
		logEvent.AddError("User account id: %d != Authorization account id: %v", currAcct.ID, authz.RegistrationID)
		wfe.sendError(response,
			logEvent,
			probs.Unauthorized("User account ID doesn't match account ID in authorization"),
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
		wfe.sendError(response, logEvent, web.ProblemDetailsForError(err, "Unable to update challenge"), err)
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

// Account is used by a client to submit an update to their account.
func (wfe *WebFrontEndImpl) Account(
	ctx context.Context,
	logEvent *web.RequestEvent,
	response http.ResponseWriter,
	request *http.Request) {
	body, _, currAcct, prob := wfe.validPOSTForAccount(request, ctx, logEvent)
	addRequesterHeader(response, logEvent.Requester)
	if prob != nil {
		// validPOSTForAccount handles its own setting of logEvent.Errors
		wfe.sendError(response, logEvent, prob, nil)
		return
	}

	// Requests to this handler should have a path that leads to a known
	// account
	idStr := request.URL.Path
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		logEvent.AddError("account ID must be an integer, was %#v", idStr)
		wfe.sendError(response, logEvent, probs.Malformed("Account ID must be an integer"), err)
		return
	} else if id <= 0 {
		msg := fmt.Sprintf("Account ID must be a positive non-zero integer, was %d", id)
		logEvent.AddError(msg)
		wfe.sendError(response, logEvent, probs.Malformed(msg), nil)
		return
	} else if id != currAcct.ID {
		logEvent.AddError("Request signing key did not match account key: %d != %d", id, currAcct.ID)
		wfe.sendError(response, logEvent,
			probs.Unauthorized("Request signing key did not match account key"), nil)
		return
	}

	var update core.Registration
	err = json.Unmarshal(body, &update)
	if err != nil {
		logEvent.AddError("unable to JSON parse account: %s", err)
		wfe.sendError(response, logEvent, probs.Malformed("Error unmarshaling account"), err)
		return
	}

	// People *will* POST their full accounts to this endpoint, including
	// the 'valid' status, to avoid always failing out when that happens only
	// attempt to deactivate if the provided status is different from their current
	// status.
	//
	// If a user tries to send both a deactivation request and an update to their
	// contacts or subscriber agreement URL the deactivation will take place and
	// return before an update would be performed.
	if update.Status != "" && update.Status != currAcct.Status {
		if update.Status != core.StatusDeactivated {
			wfe.sendError(response, logEvent, probs.Malformed("Invalid value provided for status field"), nil)
			return
		}
		wfe.deactivateAccount(ctx, *currAcct, response, request, logEvent)
		return
	}

	// If a user POSTs their account object including a previously valid
	// agreement URL but that URL has since changed we will fail out here
	// since the update agreement URL doesn't match the current URL. To fix that we
	// only fail if the sent URL doesn't match the currently valid agreement URL
	// and it doesn't match the URL currently stored in the account
	// in the database. The RA understands the user isn't actually trying to
	// update the agreement but since we do an early check here in order to prevent
	// extraneous requests to the RA we have to add this bypass.
	if len(update.Agreement) > 0 && update.Agreement != currAcct.Agreement &&
		update.Agreement != wfe.SubscriberAgreementURL {
		msg := fmt.Sprintf("Provided agreement URL [%s] does not match current agreement URL [%s]",
			update.Agreement, wfe.SubscriberAgreementURL)
		logEvent.AddError(msg)
		wfe.sendError(response, logEvent, probs.Malformed(msg), nil)
		return
	}

	// Account objects contain a JWK object which are merged in UpdateRegistration
	// if it is different from the existing account key. Since this isn't how you
	// update the key we just copy the existing one into the update object here. This
	// ensures the key isn't changed and that we can cleanly serialize the update as
	// JSON to send via RPC to the RA.
	update.Key = currAcct.Key

	updatedAcct, err := wfe.RA.UpdateRegistration(ctx, *currAcct, update)
	if err != nil {
		logEvent.AddError("unable to update account: %s", err)
		wfe.sendError(response, logEvent,
			web.ProblemDetailsForError(err, "Unable to update account"), err)
		return
	}

	if len(wfe.SubscriberAgreementURL) > 0 {
		response.Header().Add("Link", link(wfe.SubscriberAgreementURL, "terms-of-service"))
	}

	err = wfe.writeJsonResponse(response, logEvent, http.StatusAccepted, updatedAcct)
	if err != nil {
		// ServerInternal because we just generated the account, it should be OK
		logEvent.AddError("unable to marshal updated account: %s", err)
		wfe.sendError(response, logEvent,
			probs.ServerInternal("Failed to marshal account"), err)
		return
	}
}

func (wfe *WebFrontEndImpl) deactivateAuthorization(
	ctx context.Context,
	authz *core.Authorization,
	logEvent *web.RequestEvent,
	response http.ResponseWriter,
	request *http.Request) bool {
	body, _, acct, prob := wfe.validPOSTForAccount(request, ctx, logEvent)
	addRequesterHeader(response, logEvent.Requester)
	if prob != nil {
		wfe.sendError(response, logEvent, prob, nil)
		return false
	}
	if acct.ID != authz.RegistrationID {
		logEvent.AddError("account ID doesn't match ID for authorization")
		wfe.sendError(response, logEvent,
			probs.Unauthorized("Account ID doesn't match ID for authorization"), nil)
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
		wfe.sendError(response, logEvent, web.ProblemDetailsForError(err, "Error deactivating authorization"), err)
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
func (wfe *WebFrontEndImpl) Authorization(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
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
func (wfe *WebFrontEndImpl) Certificate(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {

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

	response.WriteHeader(http.StatusOK)
	if _, err = response.Write(cert.DER); err != nil {
		logEvent.AddError(err.Error())
		wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
	}
	return
}

// Terms is used by the client to obtain the current Terms of Service /
// Subscriber Agreement to which the subscriber must agree.
func (wfe *WebFrontEndImpl) Terms(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
	http.Redirect(response, request, wfe.SubscriberAgreementURL, http.StatusFound)
}

// Issuer obtains the issuer certificate used by this instance of Boulder.
func (wfe *WebFrontEndImpl) Issuer(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
	// TODO Content negotiation
	response.Header().Set("Content-Type", "application/pkix-cert")
	response.WriteHeader(http.StatusOK)
	if _, err := response.Write(wfe.IssuerCert); err != nil {
		logEvent.AddError("unable to write issuer certificate response: %s", err)
		wfe.log.Warning(fmt.Sprintf("Could not write response: %s", err))
	}
}

// BuildID tells the requestor what build we're running.
func (wfe *WebFrontEndImpl) BuildID(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
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
func (wfe *WebFrontEndImpl) KeyRollover(
	ctx context.Context,
	logEvent *web.RequestEvent,
	response http.ResponseWriter,
	request *http.Request) {
	// Validate the outer JWS on the key rollover in standard fashion using
	// validPOSTForAccount
	outerBody, outerJWS, acct, prob := wfe.validPOSTForAccount(request, ctx, logEvent)
	addRequesterHeader(response, logEvent.Requester)
	if prob != nil {
		wfe.sendError(response, logEvent, prob, nil)
		return
	}

	// Parse the inner JWS from the validated outer JWS body
	innerJWS, prob := wfe.parseJWS(outerBody)
	if prob != nil {
		wfe.sendError(response, logEvent, prob, nil)
		return
	}

	// Validate the inner JWS as a key rollover request for the outer JWS
	rolloverRequest, prob := wfe.validKeyRollover(outerJWS, innerJWS, logEvent)
	if prob != nil {
		wfe.sendError(response, logEvent, prob, nil)
		return
	}
	newKey := rolloverRequest.NewKey

	// Check that the rollover request's account URL matches the account URL used
	// to validate the outer JWS
	header := outerJWS.Signatures[0].Header
	if rolloverRequest.Account != header.KeyID {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "KeyRolloverMismatchedAccount"}).Inc()
		wfe.sendError(response, logEvent, probs.Malformed(
			fmt.Sprintf("Inner key rollover request specified Account %q, but outer JWS has Key ID %q",
				rolloverRequest.Account, header.KeyID)), nil)
		return
	}

	// Check that the new key isn't the same as the old key. This would fail as
	// part of the subsequent `wfe.SA.GetRegistrationByKey` check since the new key
	// will find the old account if its equal to the old account key. We
	// check new key against old key explicitly to save an RPC round trip and a DB
	// query for this easy rejection case
	keysEqual, err := core.PublicKeysEqual(newKey.Key, acct.Key.Key)
	if err != nil {
		// This should not happen - both the old and new key have been validated by now
		wfe.sendError(response, logEvent, probs.ServerInternal("Unable to compare new and old keys"), nil)
		return
	}
	if keysEqual {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "KeyRolloverUnchangedKey"}).Inc()
		wfe.sendError(response, logEvent, probs.Malformed(
			"New key specified by rollover request is the same as the old key"), nil)
		return
	}

	// Check that the new key isn't already being used for an existing account
	if existingAcct, err := wfe.SA.GetRegistrationByKey(ctx, &newKey); err != nil {
		response.Header().Set("Location",
			wfe.relativeEndpoint(request, fmt.Sprintf("%s%d", acctPath, existingAcct.ID)))
		wfe.sendError(response, logEvent,
			probs.Conflict("New key is already in use for a different account"), err)
		return
	}

	// Update the account key to the new key
	updatedAcct, err := wfe.RA.UpdateRegistration(ctx, *acct, core.Registration{Key: &newKey})
	if err != nil {
		wfe.sendError(response, logEvent,
			web.ProblemDetailsForError(err, "Unable to update account with new key"), err)
		return
	}

	err = wfe.writeJsonResponse(response, logEvent, http.StatusOK, updatedAcct)
	if err != nil {
		logEvent.AddError("failed to marshal updated account: %q", err)
		wfe.sendError(response, logEvent, probs.ServerInternal("Failed to marshal updated account"), err)
	}
}

func (wfe *WebFrontEndImpl) deactivateAccount(
	ctx context.Context,
	acct core.Registration,
	response http.ResponseWriter,
	request *http.Request,
	logEvent *web.RequestEvent) {
	err := wfe.RA.DeactivateRegistration(ctx, acct)
	if err != nil {
		logEvent.AddError("unable to deactivate account", err)
		wfe.sendError(response, logEvent,
			web.ProblemDetailsForError(err, "Error deactivating account"), err)
		return
	}
	acct.Status = core.StatusDeactivated

	err = wfe.writeJsonResponse(response, logEvent, http.StatusOK, acct)
	if err != nil {
		// ServerInternal because account is from DB and should be fine
		logEvent.AddError("unable to marshal updated account: %s", err)
		wfe.sendError(response, logEvent,
			probs.ServerInternal("Failed to marshal account"), err)
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

type orderJSON struct {
	Status         core.AcmeStatus
	Expires        time.Time
	CSR            core.JSONBuffer
	Authorizations []string
	Certificate    string `json:",omitempty"`
	Error          string `json:",omitempty"`
}

// NewOrder is used by clients to create a new order object from a CSR
func (wfe *WebFrontEndImpl) NewOrder(
	ctx context.Context,
	logEvent *web.RequestEvent,
	response http.ResponseWriter,
	request *http.Request) {
	body, _, acct, prob := wfe.validPOSTForAccount(request, ctx, logEvent)
	addRequesterHeader(response, logEvent.Requester)
	if prob != nil {
		// validPOSTForAccount handles its own setting of logEvent.Errors
		wfe.sendError(response, logEvent, prob, nil)
		return
	}

	var rawCSR core.RawCertificateRequest
	// The optional fields NotAfter and NotBefore are ignored if present
	// in the request
	err := json.Unmarshal(body, &rawCSR)
	if err != nil {
		logEvent.AddError("unable to JSON unmarshal order request: %s", err)
		wfe.sendError(response, logEvent, probs.Malformed("Error unmarshaling order request"), err)
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

	// Check for a malformed CSR early to avoid unnecessary RPCs
	_, err = x509.ParseCertificateRequest(rawCSR.CSR)
	if err != nil {
		logEvent.AddError("unable to parse CSR: %s", err)
		wfe.sendError(response, logEvent, probs.Malformed("Error parsing certificate request: %s", err), err)
		return
	}

	order, err := wfe.RA.NewOrder(ctx, &rapb.NewOrderRequest{
		RegistrationID: &acct.ID,
		Csr:            rawCSR.CSR,
	})
	if err != nil {
		logEvent.AddError("unable to create order: %s", err)
		wfe.sendError(response, logEvent, web.ProblemDetailsForError(err, "Error creating new order"), err)
		return
	}

	respObj := orderJSON{
		Status:         core.AcmeStatus(*order.Status),
		Expires:        time.Unix(0, *order.Expires).UTC(),
		CSR:            core.JSONBuffer(order.Csr),
		Authorizations: make([]string, len(order.Authorizations)),
	}
	for i, authzID := range order.Authorizations {
		respObj.Authorizations[i] = wfe.relativeEndpoint(request, fmt.Sprintf("%s%s", authzPath, authzID))
	}

	response.Header().Set("Location", wfe.relativeEndpoint(request, fmt.Sprintf("%s%d/%d", orderPath, acct.ID, *order.Id)))

	err = wfe.writeJsonResponse(response, logEvent, http.StatusCreated, respObj)
	if err != nil {
		wfe.sendError(response, logEvent, probs.ServerInternal("Error marshaling order"), err)
		return
	}
}

// Order is used to retrieve a existing order object
func (wfe *WebFrontEndImpl) Order(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
	fields := strings.SplitN(request.URL.Path, "/", 2)
	if len(fields) != 2 {
		wfe.sendError(response, logEvent, probs.Malformed("Invalid request path"), nil)
		return
	}
	acctID, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		wfe.sendError(response, logEvent, probs.Malformed("Invalid account ID"), err)
		return
	}
	orderID, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		wfe.sendError(response, logEvent, probs.Malformed("Invalid order ID"), err)
		return
	}

	order, err := wfe.SA.GetOrder(ctx, &sapb.OrderRequest{Id: &orderID})
	if err != nil {
		if berrors.Is(err, berrors.NotFound) {
			wfe.sendError(response, logEvent, probs.NotFound(fmt.Sprintf("No order for ID %d", orderID)), err)
			return
		}
		wfe.sendError(response, logEvent, probs.ServerInternal(fmt.Sprintf("Failed to retrieve order for ID %d", orderID)), err)
		return
	}

	if *order.RegistrationID != acctID {
		wfe.sendError(response, logEvent, probs.NotFound(fmt.Sprintf("No order found for account ID %d", acctID)), nil)
		return
	}

	respObj := orderJSON{
		Status:         core.AcmeStatus(*order.Status),
		Expires:        time.Unix(0, *order.Expires).UTC(),
		CSR:            core.JSONBuffer(order.Csr),
		Authorizations: make([]string, len(order.Authorizations)),
		Certificate:    wfe.relativeEndpoint(request, fmt.Sprintf("%s%s", certPath, *order.CertificateSerial)),
		Error:          string(order.Error),
	}
	for i, authzID := range order.Authorizations {
		respObj.Authorizations[i] = wfe.relativeEndpoint(request, fmt.Sprintf("%s%s", authzPath, authzID))
	}

	err = wfe.writeJsonResponse(response, logEvent, http.StatusOK, respObj)
	if err != nil {
		wfe.sendError(response, logEvent, probs.ServerInternal("Error marshaling order"), err)
		return
	}
}
