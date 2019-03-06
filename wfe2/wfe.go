package wfe2

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/metrics/measured_http"
	"github.com/letsencrypt/boulder/nonce"
	"github.com/letsencrypt/boulder/probs"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/revocation"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/web"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/context"
	jose "gopkg.in/square/go-jose.v2"
)

// Paths are the ACME-spec identified URL path-segments for various methods.
// NOTE: In metrics/measured_http we make the assumption that these are all
// lowercase plus hyphens. If you violate that assumption you should update
// measured_http.
const (
	directoryPath     = "/directory"
	newAcctPath       = "/acme/new-acct"
	acctPath          = "/acme/acct/"
	authzPath         = "/acme/authz/"
	challengePath     = "/acme/challenge/"
	certPath          = "/acme/cert/"
	revokeCertPath    = "/acme/revoke-cert"
	issuerPath        = "/acme/issuer-cert"
	buildIDPath       = "/build"
	rolloverPath      = "/acme/key-change"
	newNoncePath      = "/acme/new-nonce"
	newOrderPath      = "/acme/new-order"
	orderPath         = "/acme/order/"
	finalizeOrderPath = "/acme/finalize/"
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
	scope metrics.Scope

	// Issuer certificate (DER) for /acme/issuer-cert
	IssuerCert []byte

	// certificateChains maps AIA issuer URLs to a []byte containing a leading
	// newline and one or more PEM encoded certificates separated by a newline,
	// sorted from leaf to root
	certificateChains map[string][]byte

	// URL to the current subscriber agreement (should contain some version identifier)
	SubscriberAgreementURL string

	// DirectoryCAAIdentity is used for the /directory response's "meta"
	// element's "caaIdentities" field. It should match the VA's issuerDomain
	// field value.
	DirectoryCAAIdentity string

	// DirectoryWebsite is used for the /directory response's "meta" element's
	// "website" field.
	DirectoryWebsite string

	// Allowed prefix for legacy accounts used by verify.go's `lookupJWK`.
	// See `cmd/boulder-wfe2/main.go`'s comment on the configuration field
	// `LegacyKeyIDPrefix` for more informaton.
	LegacyKeyIDPrefix string

	// Register of anti-replay nonces
	nonceService *nonce.NonceService

	// Key policy.
	keyPolicy goodkey.KeyPolicy

	// CORS settings
	AllowOrigins []string

	// Maximum duration of a request
	RequestTimeout time.Duration

	AcceptRevocationReason bool
	AllowAuthzDeactivation bool
}

// NewWebFrontEndImpl constructs a web service for Boulder
func NewWebFrontEndImpl(
	scope metrics.Scope,
	clk clock.Clock,
	keyPolicy goodkey.KeyPolicy,
	certificateChains map[string][]byte,
	logger blog.Logger,
) (WebFrontEndImpl, error) {
	nonceService, err := nonce.NewNonceService(scope)
	if err != nil {
		return WebFrontEndImpl{}, err
	}

	return WebFrontEndImpl{
		log:               logger,
		clk:               clk,
		nonceService:      nonceService,
		keyPolicy:         keyPolicy,
		certificateChains: certificateChains,
		stats:             initStats(scope),
		scope:             scope,
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
	handler := http.StripPrefix(pattern, web.NewTopHandler(wfe.log,
		web.WFEHandlerFunc(func(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
			if request.Method != "GET" || pattern == newNoncePath {
				// We do not propagate errors here, because (1) they should be
				// transient, and (2) they fail closed.
				nonce, err := wfe.nonceService.Nonce()
				if err == nil {
					response.Header().Set("Replay-Nonce", nonce)
				} else {
					logEvent.AddError("unable to make nonce: %s", err)
				}
			}
			// Per section 7.1 "Resources":
			//   The "index" link relation is present on all resources other than the
			//   directory and indicates the URL of the directory.
			if pattern != directoryPath {
				directoryURL := web.RelativeEndpoint(request, "index")
				response.Header().Add("Link", link(directoryURL, "index"))
			}

			logEvent.Endpoint = pattern
			if request.URL != nil {
				logEvent.Slug = request.URL.Path
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
	))
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
		wfe.log.Warningf("Could not write response: %s", err)
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

const randomDirKeyExplanationLink = "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417"

func (wfe *WebFrontEndImpl) relativeDirectory(request *http.Request, directory map[string]interface{}) ([]byte, error) {
	// Create an empty map sized equal to the provided directory to store the
	// relative-ized result
	relativeDir := make(map[string]interface{}, len(directory))

	// Copy each entry of the provided directory into the new relative map,
	// prefixing it with the request protocol and host.
	for k, v := range directory {
		if v == randomDirKeyExplanationLink {
			relativeDir[k] = v
			continue
		}
		switch v := v.(type) {
		case string:
			// Only relative-ize top level string values, e.g. not the "meta" element
			relativeDir[k] = web.RelativeEndpoint(request, v)
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
	// Boulder specific endpoints
	wfe.HandleFunc(m, issuerPath, wfe.Issuer, "GET")
	wfe.HandleFunc(m, buildIDPath, wfe.BuildID, "GET")

	// GETable ACME endpoints
	wfe.HandleFunc(m, directoryPath, wfe.Directory, "GET")
	wfe.HandleFunc(m, newNoncePath, wfe.Nonce, "GET")

	// POSTable ACME endpoints
	wfe.HandleFunc(m, newAcctPath, wfe.NewAccount, "POST")
	wfe.HandleFunc(m, acctPath, wfe.Account, "POST")
	wfe.HandleFunc(m, revokeCertPath, wfe.RevokeCertificate, "POST")
	wfe.HandleFunc(m, rolloverPath, wfe.KeyRollover, "POST")
	wfe.HandleFunc(m, newOrderPath, wfe.NewOrder, "POST")
	wfe.HandleFunc(m, finalizeOrderPath, wfe.FinalizeOrder, "POST")

	// POST-as-GETable ACME endpoints
	// TODO(@cpu): After November 1st, 2019 support for "GET" to the following
	// endpoints will be removed, leaving only POST-as-GET support.
	wfe.HandleFunc(m, orderPath, wfe.GetOrder, "GET", "POST")
	wfe.HandleFunc(m, authzPath, wfe.Authorization, "GET", "POST")
	wfe.HandleFunc(m, challengePath, wfe.Challenge, "GET", "POST")
	wfe.HandleFunc(m, certPath, wfe.Certificate, "GET", "POST")

	// We don't use our special HandleFunc for "/" because it matches everything,
	// meaning we can wind up returning 405 when we mean to return 404. See
	// https://github.com/letsencrypt/boulder/issues/717
	m.Handle("/", web.NewTopHandler(wfe.log, web.WFEHandlerFunc(wfe.Index)))
	return measured_http.New(m, wfe.clk, wfe.scope)
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
		response.Header().Set("Allow", "GET")
		wfe.sendError(response, logEvent, probs.MethodNotAllowed(), errors.New("Bad method"))
		return
	}

	addNoCacheHeader(response)
	response.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(response, `<html>
		<body>
			This is an <a href="https://github.com/ietf-wg-acme/acme/">ACME</a>
			Certificate Authority running <a href="https://github.com/letsencrypt/boulder">Boulder</a>.
			JSON directory is available at <a href="%s">%s</a>.
		</body>
	</html>
	`, directoryPath, directoryPath)
}

func addNoCacheHeader(w http.ResponseWriter) {
	w.Header().Add("Cache-Control", "public, max-age=0, no-cache")
}

func addRequesterHeader(w http.ResponseWriter, requester int64) {
	if requester > 0 {
		w.Header().Set("Boulder-Requester", strconv.FormatInt(requester, 10))
	}
}

// Directory is an HTTP request handler that provides the directory
// object stored in the WFE's DirectoryEndpoints member with paths prefixed
// using the `request.Host` of the HTTP request.
func (wfe *WebFrontEndImpl) Directory(
	ctx context.Context,
	logEvent *web.RequestEvent,
	response http.ResponseWriter,
	request *http.Request) {
	directoryEndpoints := map[string]interface{}{
		"newAccount": newAcctPath,
		"newNonce":   newNoncePath,
		"revokeCert": revokeCertPath,
		"newOrder":   newOrderPath,
		"keyChange":  rolloverPath,
	}

	// Add a random key to the directory in order to make sure that clients don't hardcode an
	// expected set of keys. This ensures that we can properly extend the directory when we
	// need to add a new endpoint or meta element.
	directoryEndpoints[core.RandomString(8)] = randomDirKeyExplanationLink

	// ACME since draft-02 describes an optional "meta" directory entry. The
	// meta entry may optionally contain a "termsOfService" URI for the
	// current ToS.
	metaMap := map[string]interface{}{
		"termsOfService": wfe.SubscriberAgreementURL,
	}
	// The "meta" directory entry may also include a []string of CAA identities
	if wfe.DirectoryCAAIdentity != "" {
		// The specification says caaIdentities is an array of strings. In
		// practice Boulder's VA only allows configuring ONE CAA identity. Given
		// that constraint it doesn't make sense to allow multiple directory CAA
		// identities so we use just the `wfe.DirectoryCAAIdentity` alone.
		metaMap["caaIdentities"] = []string{
			wfe.DirectoryCAAIdentity,
		}
	}
	// The "meta" directory entry may also include a string with a website URL
	if wfe.DirectoryWebsite != "" {
		metaMap["website"] = wfe.DirectoryWebsite
	}
	directoryEndpoints["meta"] = metaMap

	response.Header().Set("Content-Type", "application/json")

	relDir, err := wfe.relativeDirectory(request, directoryEndpoints)
	if err != nil {
		marshalProb := probs.ServerInternal("unable to marshal JSON directory")
		wfe.sendError(response, logEvent, marshalProb, nil)
		return
	}

	response.Write(relDir)
}

// Nonce is an endpoint for getting a fresh nonce with an HTTP GET or HEAD
// request. This endpoint only returns a status code header - the `HandleFunc`
// wrapper ensures that a nonce is written in the correct response header.
func (wfe *WebFrontEndImpl) Nonce(
	ctx context.Context,
	logEvent *web.RequestEvent,
	response http.ResponseWriter,
	request *http.Request) {
	statusCode := http.StatusNoContent
	// The ACME specification says GET requets should receive http.StatusNoContent
	// and HEAD requests should receive http.StatusOK. We gate this with the
	// HeadNonceStatusOK feature flag because it may break clients that are
	// programmed to expect StatusOK.
	if features.Enabled(features.HeadNonceStatusOK) && request.Method == "HEAD" {
		statusCode = http.StatusOK
	}
	response.WriteHeader(statusCode)
}

// sendError wraps web.SendError
func (wfe *WebFrontEndImpl) sendError(response http.ResponseWriter, logEvent *web.RequestEvent, prob *probs.ProblemDetails, ierr error) {
	wfe.stats.httpErrorCount.With(prometheus.Labels{"type": string(prob.Type)}).Inc()
	web.SendError(wfe.log, probs.V2ErrorNS, response, logEvent, prob, ierr)
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

	var accountCreateRequest struct {
		Contact              *[]string `json:"contact"`
		TermsOfServiceAgreed bool      `json:"termsOfServiceAgreed"`
		OnlyReturnExisting   bool      `json:"onlyReturnExisting"`
	}

	err := json.Unmarshal(body, &accountCreateRequest)
	if err != nil {
		wfe.sendError(response, logEvent, probs.Malformed("Error unmarshaling JSON"), err)
		return
	}

	existingAcct, err := wfe.SA.GetRegistrationByKey(ctx, key)
	if err == nil {
		response.Header().Set("Location",
			web.RelativeEndpoint(request, fmt.Sprintf("%s%d", acctPath, existingAcct.ID)))
		logEvent.Requester = existingAcct.ID

		err = wfe.writeJsonResponse(response, logEvent, http.StatusOK, existingAcct)
		if err != nil {
			// ServerInternal because we just created this account, and it
			// should be OK.
			wfe.sendError(response, logEvent, probs.ServerInternal("Error marshaling account"), err)
			return
		}
		return
	} else if !berrors.Is(err, berrors.NotFound) {
		wfe.sendError(response, logEvent, probs.ServerInternal("failed check for existing account"), err)
		return
	}

	// If the request included a true "OnlyReturnExisting" field and we did not
	// find an existing registration with the key specified then we must return an
	// error and not create a new account.
	if accountCreateRequest.OnlyReturnExisting {
		wfe.sendError(response, logEvent, probs.AccountDoesNotExist(
			"No account exists with the provided key"), nil)
		return
	}

	if !accountCreateRequest.TermsOfServiceAgreed {
		wfe.sendError(response, logEvent, probs.Malformed("must agree to terms of service"), nil)
		return
	}

	ip := net.ParseIP(request.Header.Get("X-Real-IP"))
	if ip == nil {
		host, _, err := net.SplitHostPort(request.RemoteAddr)
		if err == nil {
			ip = net.ParseIP(host)
		} else {
			wfe.sendError(
				response,
				logEvent,
				probs.ServerInternal("couldn't parse the remote (that is, the client's) address"),
				fmt.Errorf("Couldn't parse RemoteAddr: %s", request.RemoteAddr),
			)
			return
		}
	}

	acct, err := wfe.RA.NewRegistration(ctx, core.Registration{
		Contact:   accountCreateRequest.Contact,
		Agreement: wfe.SubscriberAgreementURL,
		Key:       key,
		InitialIP: ip,
	})
	if err != nil {
		wfe.sendError(response, logEvent,
			web.ProblemDetailsForError(err, "Error creating new account"), err)
		return
	}
	logEvent.Requester = acct.ID
	addRequesterHeader(response, acct.ID)
	if acct.Contact != nil {
		logEvent.Contacts = *acct.Contact
	}

	// We populate the account Agreement field when creating a new response to
	// track which terms-of-service URL was in effect when an account with
	// "termsOfServiceAgreed":"true" is created. That said, we don't want to send
	// this value back to a V2 client. The "Agreement" field of an
	// account/registration is a V1 notion so we strip it here in the WFE2 before
	// returning the account.
	acct.Agreement = ""

	acctURL := web.RelativeEndpoint(request, fmt.Sprintf("%s%d", acctPath, acct.ID))

	response.Header().Add("Location", acctURL)
	if len(wfe.SubscriberAgreementURL) > 0 {
		response.Header().Add("Link", link(wfe.SubscriberAgreementURL, "terms-of-service"))
	}

	err = wfe.writeJsonResponse(response, logEvent, http.StatusCreated, acct)
	if err != nil {
		// ServerInternal because we just created this account, and it
		// should be OK.
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

	if parsedCertificate.NotAfter.Before(wfe.clk.Now()) {
		return probs.Unauthorized("Certificate is expired")
	}

	// Check the certificate status for the provided certificate to see if it is
	// already revoked
	certStatus, err := wfe.SA.GetCertificateStatus(ctx, serial)
	if err != nil {
		return probs.NotFound("Certificate status not yet available")
	}
	logEvent.Extra["CertificateStatus"] = certStatus.Status

	if certStatus.Status == core.OCSPStatusRevoked {
		return probs.AlreadyRevoked("Certificate already revoked")
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

	wfe.log.Debugf("Revoked %v", serial)
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
	// of the names in the certificate or was the issuing account
	authorizedToRevoke := func(parsedCertificate *x509.Certificate) *probs.ProblemDetails {
		cert, err := wfe.SA.GetCertificate(ctx, core.SerialToString(parsedCertificate.SerialNumber))
		if err != nil {
			return probs.ServerInternal("Failed to retrieve certificate")
		}
		if cert.RegistrationID == acct.ID {
			return nil
		}
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
		ClientAddr string
		CSR        string
		Requester  int64
	}{
		ClientAddr: web.GetClientAddr(request),
		CSR:        hex.EncodeToString(cr.Bytes),
		Requester:  account.ID,
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

	// Challenge URIs are of the form /acme/challenge/<auth id>/<challenge id>
	// or /acme/challenge/v2/<auth id>/<challenge id> depending on the authorization
	// version. Here we parse out the authorization and challenge IDs and retrieve
	// the authorization.
	slug := strings.Split(request.URL.Path, "/")
	if len(slug) != 2 && len(slug) != 3 {
		notFound()
		return
	}
	var authorizationID string
	var challengeID interface{}
	var err error
	var v2 bool
	if len(slug) == 3 {
		if !features.Enabled(features.NewAuthorizationSchema) || slug[0] != "v2" {
			notFound()
			return
		}
		v2 = true
		authorizationID, challengeID = slug[1], slug[2]
	} else {
		authorizationID = slug[0]
		challengeID, err = strconv.ParseInt(slug[1], 10, 64)
		if err != nil {
			notFound()
			return
		}
	}

	var authz core.Authorization
	if v2 {
		id, err := strconv.ParseInt(authorizationID, 10, 64)
		if err != nil {
			notFound()
			return
		}
		authzPB, err := wfe.SA.GetAuthorization2(ctx, &sapb.AuthorizationID2{Id: &id})
		if err != nil {
			if berrors.Is(err, berrors.NotFound) {
				notFound()
			} else {
				wfe.sendError(response, logEvent, probs.ServerInternal("Problem getting authorization"), err)
			}
			return
		}
		authz, err = bgrpc.PBToAuthz(authzPB)
		if err != nil {
			wfe.sendError(response, logEvent, probs.ServerInternal("Problem getting authorization"), err)
			return
		}
	} else {
		authz, err = wfe.SA.GetAuthorization(ctx, authorizationID)
		if err != nil {
			if berrors.Is(err, berrors.NotFound) {
				notFound()
			} else {
				wfe.sendError(response, logEvent, probs.ServerInternal("Problem getting authorization"), err)
			}
			return
		}
	}

	// After expiring, challenges are inaccessible
	if authz.Expires == nil || authz.Expires.Before(wfe.clk.Now()) {
		wfe.sendError(response, logEvent, probs.NotFound("Expired authorization"), nil)
		return
	}

	// Check that the requested challenge exists within the authorization
	var challengeIndex int
	if authz.V2 {
		challengeIndex = authz.FindChallengeByStringID(challengeID.(string))
	} else {
		challengeIndex = authz.FindChallenge(challengeID.(int64))
	}
	if challengeIndex == -1 {
		notFound()
		return
	}
	challenge := authz.Challenges[challengeIndex]

	logEvent.Extra["ChallengeType"] = challenge.Type
	if authz.Identifier.Type == core.IdentifierDNS {
		logEvent.DNSName = authz.Identifier.Value
	}
	logEvent.Status = string(authz.Status)

	switch request.Method {
	case "GET", "HEAD":
		wfe.getChallenge(ctx, response, request, authz, &challenge, logEvent)

	case "POST":
		wfe.postChallenge(ctx, response, request, authz, challengeIndex, logEvent)
	}
}

// prepChallengeForDisplay takes a core.Challenge and prepares it for display to
// the client by filling in its URL field and clearing its ID and URI fields.
func (wfe *WebFrontEndImpl) prepChallengeForDisplay(request *http.Request, authz core.Authorization, challenge *core.Challenge) {
	// Update the challenge URL to be relative to the HTTP request Host
	if authz.V2 {
		challenge.URL = web.RelativeEndpoint(request, fmt.Sprintf("%sv2/%s/%s", challengePath, authz.ID, challenge.StringID()))
	} else {
		challenge.URL = web.RelativeEndpoint(request, fmt.Sprintf("%s%s/%d", challengePath, authz.ID, challenge.ID))
	}
	// Ensure the challenge URI and challenge ID aren't written by setting them to
	// values that the JSON omitempty tag considers empty
	challenge.URI = ""
	challenge.ID = 0

	// ACMEv2 never sends the KeyAuthorization back in a challenge object.
	challenge.ProvidedKeyAuthorization = ""

	// Historically the Type field of a problem was always prefixed with a static
	// error namespace. To support the V2 API and migrating to the correct IETF
	// namespace we now prefix the Type with the correct namespace at runtime when
	// we write the problem JSON to the user. We skip this process if the
	// challenge error type has already been prefixed with the V1ErrorNS.
	if challenge.Error != nil && !strings.HasPrefix(string(challenge.Error.Type), probs.V1ErrorNS) {
		challenge.Error.Type = probs.V2ErrorNS + challenge.Error.Type
	}

	// If the authz has been marked invalid, consider all challenges on that authz
	// to be invalid as well.
	if authz.Status == core.StatusInvalid {
		challenge.Status = authz.Status
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

	// Combinations are a relic of the V1 API. Since they are tagged omitempty we
	// can set this field to nil to avoid sending it to users of the V2 API.
	authz.Combinations = nil

	// The ACME spec forbids allowing "*" in authorization identifiers. Boulder
	// allows this internally as a means of tracking when an authorization
	// corresponds to a wildcard request (e.g. to handle CAA properly). We strip
	// the "*." prefix from the Authz's Identifier's Value here to respect the law
	// of the protocol.
	if strings.HasPrefix(authz.Identifier.Value, "*.") {
		authz.Identifier.Value = strings.TrimPrefix(authz.Identifier.Value, "*.")
		// Mark that the authorization corresponds to a wildcard request since we've
		// now removed the wildcard prefix from the identifier.
		authz.Wildcard = true
	}
}

func (wfe *WebFrontEndImpl) getChallenge(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	authz core.Authorization,
	challenge *core.Challenge,
	logEvent *web.RequestEvent) {

	wfe.prepChallengeForDisplay(request, authz, challenge)

	authzURL := web.RelativeEndpoint(request, authzPath+string(authz.ID))
	response.Header().Add("Location", challenge.URL)
	response.Header().Add("Link", link(authzURL, "up"))

	err := wfe.writeJsonResponse(response, logEvent, http.StatusOK, challenge)
	if err != nil {
		// InternalServerError because this is a failure to decode data passed in
		// by the caller, which got it from the DB.
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

	// Check that the account ID matching the key used matches
	// the account ID on the authz object
	if currAcct.ID != authz.RegistrationID {
		wfe.sendError(response,
			logEvent,
			probs.Unauthorized("User account ID doesn't match account ID in authorization"),
			nil,
		)
		return
	}

	// If the JWS body is empty then this POST is a POST-as-GET to retreive
	// challenge details, not a POST to initiate a challenge
	if string(body) == "" {
		challenge := authz.Challenges[challengeIndex]
		wfe.getChallenge(ctx, response, request, authz, &challenge, logEvent)
		return
	}

	// We can expect some clients to try and update a challenge for an authorization
	// that is already valid. In this case we don't need to process the challenge
	// update. It wouldn't be helpful, the overall authorization is already good! We
	// increment a stat for this case and return early.
	var returnAuthz core.Authorization
	if authz.Status == core.StatusValid {
		wfe.scope.Inc("ReusedValidAuthzChallengeWFE", 1)
		returnAuthz = authz
	} else {

		// NOTE(@cpu): Historically a challenge update needed to include
		// a KeyAuthorization field. This is no longer the case, since both sides can
		// calculate the key authorization as needed. We unmarshal here only to check
		// that the POST body is valid JSON. Any data/fields included are ignored to
		// be kind to ACMEv2 implementations that still send a key authorization.
		var challengeUpdate struct{}
		if err := json.Unmarshal(body, &challengeUpdate); err != nil {
			wfe.sendError(response, logEvent, probs.Malformed("Error unmarshaling challenge response"), err)
			return
		}

		authzPB, err := bgrpc.AuthzToPB(authz)
		if err != nil {
			wfe.sendError(response, logEvent, web.ProblemDetailsForError(err, "Unable to serialize authz"), err)
			return
		}
		challIndex := int64(challengeIndex)

		authzPB, err = wfe.RA.PerformValidation(ctx, &rapb.PerformValidationRequest{
			Authz:          authzPB,
			ChallengeIndex: &challIndex,
		})
		if err != nil {
			wfe.sendError(response, logEvent, web.ProblemDetailsForError(err, "Unable to update challenge"), err)
			return
		}
		updatedAuthz, err := bgrpc.PBToAuthz(authzPB)
		if err != nil {
			wfe.sendError(response, logEvent, web.ProblemDetailsForError(err, "Unable to deserialize authz"), err)
			return
		}
		returnAuthz = updatedAuthz
	}

	// assumption: PerformValidation does not modify order of challenges
	challenge := returnAuthz.Challenges[challengeIndex]
	wfe.prepChallengeForDisplay(request, authz, &challenge)

	authzURL := web.RelativeEndpoint(request, authzPath+string(authz.ID))
	response.Header().Add("Location", challenge.URL)
	response.Header().Add("Link", link(authzURL, "up"))

	err := wfe.writeJsonResponse(response, logEvent, http.StatusOK, challenge)
	if err != nil {
		// ServerInternal because we made the challenges, they should be OK
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
		wfe.sendError(response, logEvent, probs.Malformed("Account ID must be an integer"), err)
		return
	} else if id <= 0 {
		msg := fmt.Sprintf("Account ID must be a positive non-zero integer, was %d", id)
		wfe.sendError(response, logEvent, probs.Malformed(msg), nil)
		return
	} else if id != currAcct.ID {
		wfe.sendError(response, logEvent,
			probs.Unauthorized("Request signing key did not match account key"), nil)
		return
	}

	// If the body was not empty, then this is an account update request.
	if string(body) != "" {
		currAcct, prob = wfe.updateAccount(ctx, body, currAcct)
		if prob != nil {
			wfe.sendError(response, logEvent, prob, nil)
			return
		}
	}

	if len(wfe.SubscriberAgreementURL) > 0 {
		response.Header().Add("Link", link(wfe.SubscriberAgreementURL, "terms-of-service"))
	}

	// We populate the account Agreement field when creating a new response to
	// track which terms-of-service URL was in effect when an account with
	// "termsOfServiceAgreed":"true" is created. That said, we don't want to send
	// this value back to a V2 client. The "Agreement" field of an
	// account/registration is a V1 notion so we strip it here in the WFE2 before
	// returning the account.
	currAcct.Agreement = ""

	err = wfe.writeJsonResponse(response, logEvent, http.StatusOK, currAcct)
	if err != nil {
		// ServerInternal because we just generated the account, it should be OK
		wfe.sendError(response, logEvent,
			probs.ServerInternal("Failed to marshal account"), err)
		return
	}
}

// updateAccount unmarshals an account update request from the provided
// requestBody to update the given registration. Important: It is assumed the
// request has already been authenticated by the caller. If the request is
// a valid update the resulting updated account is returned, otherwise a problem
// is returned.
func (wfe *WebFrontEndImpl) updateAccount(
	ctx context.Context,
	requestBody []byte,
	currAcct *core.Registration) (*core.Registration, *probs.ProblemDetails) {
	// Only the Contact and Status fields of an account may be updated this way.
	// For key updates clients should be using the key change endpoint.
	var accountUpdateRequest struct {
		Contact *[]string       `json:"contact"`
		Status  core.AcmeStatus `json:"status"`
	}

	err := json.Unmarshal(requestBody, &accountUpdateRequest)
	if err != nil {
		return nil, probs.Malformed("Error unmarshaling account")
	}

	// Copy over the fields from the request to the registration object used for
	// the RA updates.
	update := core.Registration{
		Contact: accountUpdateRequest.Contact,
		Status:  accountUpdateRequest.Status,
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
			return nil, probs.Malformed("Invalid value provided for status field")
		}
		if err := wfe.RA.DeactivateRegistration(ctx, *currAcct); err != nil {
			return nil, web.ProblemDetailsForError(err, "Unable to deactivate account")
		}
		currAcct.Status = core.StatusDeactivated
		return currAcct, nil
	}

	// Account objects contain a JWK object which are merged in UpdateRegistration
	// if it is different from the existing account key. Since this isn't how you
	// update the key we just copy the existing one into the update object here. This
	// ensures the key isn't changed and that we can cleanly serialize the update as
	// JSON to send via RPC to the RA.
	update.Key = currAcct.Key

	updatedAcct, err := wfe.RA.UpdateRegistration(ctx, *currAcct, update)
	if err != nil {
		return nil, web.ProblemDetailsForError(err, "Unable to update account")
	}
	return &updatedAcct, nil
}

// deactivateAuthorization processes the given JWS POST body as a request to
// deactivate the provided authorization. If an error occurs it is written to
// the response writer. Important: `deactivateAuthorization` does not check that
// the requester is authorized to deactivate the given authorization. It is
// assumed that this check is performed prior to calling deactivateAuthorzation.
func (wfe *WebFrontEndImpl) deactivateAuthorization(
	ctx context.Context,
	authz *core.Authorization,
	logEvent *web.RequestEvent,
	response http.ResponseWriter,
	body []byte) bool {
	var req struct {
		Status core.AcmeStatus
	}
	err := json.Unmarshal(body, &req)
	if err != nil {
		wfe.sendError(response, logEvent, probs.Malformed("Error unmarshaling JSON"), err)
		return false
	}
	if req.Status != core.StatusDeactivated {
		wfe.sendError(response, logEvent, probs.Malformed("Invalid status value"), err)
		return false
	}
	err = wfe.RA.DeactivateAuthorization(ctx, *authz)
	if err != nil {
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
	var requestAccount *core.Registration
	var requestBody []byte
	// If the request is a POST it is either:
	//   A) an update to an authorization to deactivate it
	//   B) a POST-as-GET to query the authorization details
	if request.Method == "POST" {
		// Both POST options need to be authenticated by an account
		body, _, acct, prob := wfe.validPOSTForAccount(request, ctx, logEvent)
		addRequesterHeader(response, logEvent.Requester)
		if prob != nil {
			wfe.sendError(response, logEvent, prob, nil)
			return
		}
		requestAccount = acct
		requestBody = body
	}

	// Requests to this handler should have a path that leads to a known authz
	id := request.URL.Path
	var authz core.Authorization
	var err error
	if features.Enabled(features.NewAuthorizationSchema) && strings.HasPrefix(id, "/v2/") {
		authzID, err := strconv.ParseInt(id[4:], 10, 64)
		if err != nil {
			wfe.sendError(response, logEvent, probs.NotFound("No such authorization"), nil)
			return
		}
		authzPB, err := wfe.SA.GetAuthorization2(ctx, &sapb.AuthorizationID2{Id: &authzID})
		if err != nil {
			if berrors.Is(err, berrors.NotFound) {
				wfe.sendError(response, logEvent, probs.NotFound("No such authorization"), nil)
			} else {
				wfe.sendError(response, logEvent, probs.ServerInternal("Problem getting authorization"), err)
			}
			return
		}
		authz, err = bgrpc.PBToAuthz(authzPB)
		if err != nil {
			wfe.sendError(response, logEvent, probs.ServerInternal("Problem getting authorization"), err)
			return
		}
	} else {
		authz, err = wfe.SA.GetAuthorization(ctx, id)
		if err != nil {
			if berrors.Is(err, berrors.NotFound) {
				wfe.sendError(response, logEvent, probs.NotFound("No such authorization"), nil)
			} else {
				wfe.sendError(response, logEvent, probs.ServerInternal("Problem getting authorization"), err)
			}
			return
		}
	}
	if authz.Identifier.Type == core.IdentifierDNS {
		logEvent.DNSName = authz.Identifier.Value
	}
	logEvent.Status = string(authz.Status)

	// After expiring, authorizations are inaccessible
	if authz.Expires == nil || authz.Expires.Before(wfe.clk.Now()) {
		wfe.sendError(response, logEvent, probs.NotFound("Expired authorization"), nil)
		return
	}

	// If this was a POST that has an associated requestAccount and that account
	// doesn't own the authorization, abort before trying to deactivate the authz
	// or return its details
	if requestAccount != nil && requestAccount.ID != authz.RegistrationID {
		wfe.sendError(response, logEvent,
			probs.Unauthorized("Account ID doesn't match ID for authorization"), nil)
		return
	}

	// If the body isn't empty we know it isn't a POST-as-GET and must be an
	// attempt to deactivate an authorization.
	if string(requestBody) != "" && wfe.AllowAuthzDeactivation {
		// If the deactivation fails return early as errors and return codes
		// have already been set. Otherwise continue so that the user gets
		// sent the deactivated authorization.
		if !wfe.deactivateAuthorization(ctx, &authz, logEvent, response, requestBody) {
			return
		}
	}

	wfe.prepAuthorizationForDisplay(request, &authz)

	err = wfe.writeJsonResponse(response, logEvent, http.StatusOK, authz)
	if err != nil {
		// InternalServerError because this is a failure to decode from our DB.
		wfe.sendError(response, logEvent, probs.ServerInternal("Failed to JSON marshal authz"), err)
		return
	}
}

var allHex = regexp.MustCompile("^[0-9a-f]+$")

// Certificate is used by clients to request a copy of their current certificate, or to
// request a reissuance of the certificate.
func (wfe *WebFrontEndImpl) Certificate(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
	var requesterAccount *core.Registration
	// Any POSTs to the Certificate endpoint should be POST-as-GET requests. There are
	// no POSTs with a body allowed for this endpoint.
	if request.Method == "POST" {
		acct, prob := wfe.validPOSTAsGETForAccount(request, ctx, logEvent)
		if prob != nil {
			wfe.sendError(response, logEvent, prob, nil)
			return
		}
		requesterAccount = acct
	}

	serial := request.URL.Path
	// Certificate paths consist of the CertBase path, plus exactly sixteen hex
	// digits.
	if !core.ValidSerial(serial) {
		wfe.sendError(
			response,
			logEvent,
			probs.NotFound("Certificate not found"),
			fmt.Errorf("certificate serial provided was not valid: %s", serial),
		)
		return
	}
	logEvent.Extra["RequestedSerial"] = serial

	cert, err := wfe.SA.GetCertificate(ctx, serial)
	// TODO(#991): handle db errors
	if err != nil {
		ierr := fmt.Errorf("unable to get certificate by serial id %#v: %s", serial, err)
		if strings.HasPrefix(err.Error(), "gorp: multiple rows returned") {
			wfe.sendError(response, logEvent, probs.Conflict("Multiple certificates with same short serial"), ierr)
		} else {
			wfe.sendError(response, logEvent, probs.NotFound("Certificate not found"), ierr)
		}
		return
	}

	// If there was a requesterAccount (e.g. because it was a POST-as-GET request)
	// then the requesting account must be the owner of the certificate, otherwise
	// return an unauthorized error.
	if requesterAccount != nil && requesterAccount.ID != cert.RegistrationID {
		wfe.sendError(response, logEvent, probs.Unauthorized("Account in use did not issue specified certificate"), nil)
		return
	}

	leafPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.DER,
	})

	var responsePEM []byte

	// If the WFE is configured with certificateChains, construct a chain for this
	// certificate using its AIA Issuer URL.
	if len(wfe.certificateChains) > 0 {
		parsedCert, err := x509.ParseCertificate(cert.DER)
		if err != nil {
			// If we can't parse one of our own certs there's a serious problem
			wfe.sendError(response, logEvent, probs.ServerInternal(
				fmt.Sprintf(
					"unable to parse Boulder issued certificate with serial %#v",
					serial),
			), err)
			return
		}

		// NOTE(@cpu): Boulder assumes there will only be **ONE** AIA issuer URL
		// configured in the CA signing profile. At present this is not enforced by
		// the CA, but should be. See
		//  https://github.com/letsencrypt/boulder/issues/3374
		aiaIssuerURL := parsedCert.IssuingCertificateURL[0]
		if chain, ok := wfe.certificateChains[aiaIssuerURL]; ok {
			// Prepend the chain with the leaf certificate
			responsePEM = append(leafPEM, chain...)
		} else {
			// If there is no wfe.certificateChains entry for the AIA Issuer URL there
			// is probably a misconfiguration and we should treat it as an internal
			// server error.
			wfe.sendError(response, logEvent, probs.ServerInternal(
				fmt.Sprintf(
					"Certificate serial %#v has an unknown AIA Issuer URL %q"+
						"- no PEM certificate chain associated.",
					serial,
					aiaIssuerURL),
			), nil)
			return
		}
	} else {
		// Otherwise, with no configured certificateChains just serve the leaf
		// certificate.
		responsePEM = leafPEM
	}

	// NOTE(@cpu): We must explicitly set the Content-Length header here. The Go
	// HTTP library will only add this header if the body is below a certain size
	// and with the addition of a PEM encoded certificate chain the body size of
	// this endpoint will exceed this threshold. Since we know the length we can
	// reliably set it ourselves and not worry.
	response.Header().Set("Content-Length", strconv.Itoa(len(responsePEM)))
	response.Header().Set("Content-Type", "application/pem-certificate-chain")
	response.WriteHeader(http.StatusOK)
	if _, err = response.Write(responsePEM); err != nil {
		wfe.log.Warningf("Could not write response: %s", err)
	}
	return
}

// Issuer obtains the issuer certificate used by this instance of Boulder.
func (wfe *WebFrontEndImpl) Issuer(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
	// TODO Content negotiation
	response.Header().Set("Content-Type", "application/pkix-cert")
	response.WriteHeader(http.StatusOK)
	if _, err := response.Write(wfe.IssuerCert); err != nil {
		wfe.log.Warningf("Could not write response: %s", err)
	}
}

// BuildID tells the requestor what build we're running.
func (wfe *WebFrontEndImpl) BuildID(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "text/plain")
	response.WriteHeader(http.StatusOK)
	detailsString := fmt.Sprintf("Boulder=(%s %s)", core.GetBuildID(), core.GetBuildTime())
	if _, err := fmt.Fprintln(response, detailsString); err != nil {
		wfe.log.Warningf("Could not write response: %s", err)
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
	// NOTE(@cpu): "Content-Type" is considered a 'simple header' that doesn't
	// need to be explicitly allowed in 'access-control-allow-headers', but only
	// when the value is one of: `application/x-www-form-urlencoded`,
	// `multipart/form-data`, or `text/plain`. Since `application/jose+json` is
	// not one of these values we must be explicit in saying that `Content-Type`
	// is an allowed header. See MDN for more details:
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers
	response.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	response.Header().Set("Access-Control-Expose-Headers", "Link, Replay-Nonce, Location")
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
	oldKey := acct.Key

	// Parse the inner JWS from the validated outer JWS body
	innerJWS, prob := wfe.parseJWS(outerBody)
	if prob != nil {
		wfe.sendError(response, logEvent, prob, nil)
		return
	}

	// Validate the inner JWS as a key rollover request for the outer JWS
	rolloverOperation, prob := wfe.validKeyRollover(outerJWS, innerJWS, oldKey, logEvent)
	if prob != nil {
		wfe.sendError(response, logEvent, prob, nil)
		return
	}
	newKey := rolloverOperation.NewKey

	// Check that the rollover request's account URL matches the account URL used
	// to validate the outer JWS
	header := outerJWS.Signatures[0].Header
	if rolloverOperation.Account != header.KeyID {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "KeyRolloverMismatchedAccount"}).Inc()
		wfe.sendError(response, logEvent, probs.Malformed(
			fmt.Sprintf("Inner key rollover request specified Account %q, but outer JWS has Key ID %q",
				rolloverOperation.Account, header.KeyID)), nil)
		return
	}

	// Check that the new key isn't the same as the old key. This would fail as
	// part of the subsequent `wfe.SA.GetRegistrationByKey` check since the new key
	// will find the old account if its equal to the old account key. We
	// check new key against old key explicitly to save an RPC round trip and a DB
	// query for this easy rejection case
	keysEqual, err := core.PublicKeysEqual(newKey.Key, oldKey.Key)
	if err != nil {
		// This should not happen - both the old and new key have been validated by now
		wfe.sendError(response, logEvent, probs.ServerInternal("Unable to compare new and old keys"), err)
		return
	}
	if keysEqual {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "KeyRolloverUnchangedKey"}).Inc()
		wfe.sendError(response, logEvent, probs.Malformed(
			"New key specified by rollover request is the same as the old key"), nil)
		return
	}

	// Check that the new key isn't already being used for an existing account
	if existingAcct, err := wfe.SA.GetRegistrationByKey(ctx, &newKey); err == nil {
		response.Header().Set("Location",
			web.RelativeEndpoint(request, fmt.Sprintf("%s%d", acctPath, existingAcct.ID)))
		wfe.sendError(response, logEvent,
			probs.Conflict("New key is already in use for a different account"), err)
		return
	} else if !berrors.Is(err, berrors.NotFound) {
		wfe.sendError(response, logEvent, probs.ServerInternal("Failed to lookup existing keys"), err)
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
		wfe.sendError(response, logEvent, probs.ServerInternal("Failed to marshal updated account"), err)
	}
}

type orderJSON struct {
	Status         core.AcmeStatus       `json:"status"`
	Expires        time.Time             `json:"expires"`
	Identifiers    []core.AcmeIdentifier `json:"identifiers"`
	Authorizations []string              `json:"authorizations"`
	Finalize       string                `json:"finalize"`
	Certificate    string                `json:"certificate,omitempty"`
	Error          *probs.ProblemDetails `json:"error,omitempty"`
}

// orderToOrderJSON converts a *corepb.Order instance into an orderJSON struct
// that is returned in HTTP API responses. It will convert the order names to
// DNS type identifiers and additionally create absolute URLs for the finalize
// URL and the ceritificate URL as appropriate.
func (wfe *WebFrontEndImpl) orderToOrderJSON(request *http.Request, order *corepb.Order) orderJSON {
	idents := make([]core.AcmeIdentifier, len(order.Names))
	for i, name := range order.Names {
		idents[i] = core.AcmeIdentifier{Type: core.IdentifierDNS, Value: name}
	}
	finalizeURL := web.RelativeEndpoint(request,
		fmt.Sprintf("%s%d/%d", finalizeOrderPath, *order.RegistrationID, *order.Id))
	respObj := orderJSON{
		Status:         core.AcmeStatus(*order.Status),
		Expires:        time.Unix(0, *order.Expires).UTC(),
		Identifiers:    idents,
		Authorizations: make([]string, len(order.Authorizations)),
		Finalize:       finalizeURL,
	}
	// If there is an order error, prefix its type with the V2 namespace
	if order.Error != nil {
		prob, err := bgrpc.PBToProblemDetails(order.Error)
		if err != nil {
			wfe.log.AuditErrf("Internal error converting order ID %d "+
				"proto buf prob to problem details: %q", *order.Id, err)
		}
		respObj.Error = prob
		respObj.Error.Type = probs.V2ErrorNS + respObj.Error.Type
	}
	for i, authzID := range order.Authorizations {
		respObj.Authorizations[i] = web.RelativeEndpoint(request, fmt.Sprintf("%s%s", authzPath, authzID))
	}
	if respObj.Status == core.StatusValid {
		certURL := web.RelativeEndpoint(request,
			fmt.Sprintf("%s%s", certPath, *order.CertificateSerial))
		respObj.Certificate = certURL
	}
	return respObj
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

	// We only allow specifying Identifiers in a new order request - if the
	// `notBefore` and/or `notAfter` fields described in Section 7.4 of acme-08
	// are sent we return a probs.Malformed as we do not support them
	var newOrderRequest struct {
		Identifiers         []core.AcmeIdentifier `json:"identifiers"`
		NotBefore, NotAfter string
	}
	err := json.Unmarshal(body, &newOrderRequest)
	if err != nil {
		wfe.sendError(response, logEvent,
			probs.Malformed("Unable to unmarshal NewOrder request body"), err)
		return
	}

	if len(newOrderRequest.Identifiers) == 0 {
		wfe.sendError(response, logEvent,
			probs.Malformed("NewOrder request did not specify any identifiers"), nil)
		return
	}
	if newOrderRequest.NotBefore != "" || newOrderRequest.NotAfter != "" {
		wfe.sendError(response, logEvent, probs.Malformed("NotBefore and NotAfter are not supported"), nil)
		return
	}

	// Collect up all of the DNS identifier values into a []string for subsequent
	// layers to process. We reject anything with a non-DNS type identifier here.
	names := make([]string, len(newOrderRequest.Identifiers))
	for i, ident := range newOrderRequest.Identifiers {
		if ident.Type != core.IdentifierDNS {
			wfe.sendError(response, logEvent,
				probs.Malformed("NewOrder request included invalid non-DNS type identifier: type %q, value %q",
					ident.Type, ident.Value),
				nil)
			return
		}
		names[i] = ident.Value
	}

	order, err := wfe.RA.NewOrder(ctx, &rapb.NewOrderRequest{
		RegistrationID: &acct.ID,
		Names:          names,
	})
	if err != nil {
		wfe.sendError(response, logEvent, web.ProblemDetailsForError(err, "Error creating new order"), err)
		return
	}
	logEvent.Created = fmt.Sprintf("%d", *order.Id)

	orderURL := web.RelativeEndpoint(request,
		fmt.Sprintf("%s%d/%d", orderPath, acct.ID, *order.Id))
	response.Header().Set("Location", orderURL)

	respObj := wfe.orderToOrderJSON(request, order)
	err = wfe.writeJsonResponse(response, logEvent, http.StatusCreated, respObj)
	if err != nil {
		wfe.sendError(response, logEvent, probs.ServerInternal("Error marshaling order"), err)
		return
	}
}

// GetOrder is used to retrieve a existing order object
func (wfe *WebFrontEndImpl) GetOrder(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
	var requesterAccount *core.Registration
	// Any POSTs to the Order endpoint should be POST-as-GET requests. There are
	// no POSTs with a body allowed for this endpoint.
	if request.Method == "POST" {
		acct, prob := wfe.validPOSTAsGETForAccount(request, ctx, logEvent)
		if prob != nil {
			wfe.sendError(response, logEvent, prob, nil)
			return
		}
		requesterAccount = acct
	}

	// Path prefix is stripped, so this should be like "<account ID>/<order ID>"
	fields := strings.SplitN(request.URL.Path, "/", 2)
	if len(fields) != 2 {
		wfe.sendError(response, logEvent, probs.NotFound("Invalid request path"), nil)
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
			wfe.sendError(response, logEvent, probs.NotFound("No order for ID %d", orderID), err)
			return
		}
		wfe.sendError(response, logEvent, probs.ServerInternal("Failed to retrieve order for ID %d", orderID), err)
		return
	}

	if *order.RegistrationID != acctID {
		wfe.sendError(response, logEvent, probs.NotFound("No order found for account ID %d", acctID), nil)
		return
	}

	// If the requesterAccount is not nil then this was an authenticated
	// POST-as-GET request and we need to verify the requesterAccount is the
	// order's owner.
	if requesterAccount != nil && *order.RegistrationID != requesterAccount.ID {
		wfe.sendError(response, logEvent, probs.NotFound("No order found for account ID %d", acctID), nil)
		return
	}

	respObj := wfe.orderToOrderJSON(request, order)
	err = wfe.writeJsonResponse(response, logEvent, http.StatusOK, respObj)
	if err != nil {
		wfe.sendError(response, logEvent, probs.ServerInternal("Error marshaling order"), err)
		return
	}
}

// FinalizeOrder is used to request issuance for a existing order object.
// Most processing of the order details is handled by the RA but
// we do attempt to throw away requests with invalid CSRs here.
func (wfe *WebFrontEndImpl) FinalizeOrder(ctx context.Context, logEvent *web.RequestEvent, response http.ResponseWriter, request *http.Request) {
	// Validate the POST body signature and get the authenticated account for this
	// finalize order request
	body, _, acct, prob := wfe.validPOSTForAccount(request, ctx, logEvent)
	addRequesterHeader(response, logEvent.Requester)
	if prob != nil {
		wfe.sendError(response, logEvent, prob, nil)
		return
	}

	// Order URLs are like: /acme/finalize/<account>/<order>/. The prefix is
	// stripped by the time we get here.
	fields := strings.SplitN(request.URL.Path, "/", 2)
	if len(fields) != 2 {
		wfe.sendError(response, logEvent, probs.NotFound("Invalid request path"), nil)
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
			wfe.sendError(response, logEvent, probs.NotFound("No order for ID %d", orderID), err)
			return
		}
		wfe.sendError(response, logEvent, probs.ServerInternal("Failed to retrieve order for ID %d", orderID), err)
		return
	}

	if *order.RegistrationID != acctID {
		wfe.sendError(response, logEvent, probs.NotFound("No order found for account ID %d", acctID), nil)
		return
	}

	// If the authenticated account ID doesn't match the order's registration ID
	// pretend it doesn't exist and abort.
	if acct.ID != *order.RegistrationID {
		wfe.sendError(response, logEvent, probs.NotFound("No order found for account ID %d", acct.ID), nil)
		return
	}

	// Only ready orders can be finalized.
	if *order.Status != string(core.StatusReady) {
		wfe.sendError(response, logEvent,
			probs.OrderNotReady(
				"Order's status (%q) is not acceptable for finalization",
				*order.Status),
			nil)
		return
	}

	// If the order is expired we can not finalize it and must return an error
	orderExpiry := time.Unix(*order.Expires, 0)
	if orderExpiry.Before(wfe.clk.Now()) {
		wfe.sendError(response, logEvent, probs.NotFound("Order %d is expired", *order.Id), nil)
		return
	}

	// The authenticated finalize message body should be an encoded CSR
	var rawCSR core.RawCertificateRequest
	err = json.Unmarshal(body, &rawCSR)
	if err != nil {
		wfe.sendError(response, logEvent,
			probs.Malformed("Error unmarshaling finalize order request"), err)
		return
	}

	// Check for a malformed CSR early to avoid unnecessary RPCs
	csr, err := x509.ParseCertificateRequest(rawCSR.CSR)
	if err != nil {
		wfe.sendError(response, logEvent, probs.Malformed("Error parsing certificate request: %s", err), err)
		return
	}

	certificateRequest := core.CertificateRequest{Bytes: rawCSR.CSR}
	certificateRequest.CSR = csr
	wfe.logCsr(request, certificateRequest, *acct)

	logEvent.Extra["CSRDNSNames"] = certificateRequest.CSR.DNSNames
	logEvent.Extra["CSREmailAddresses"] = certificateRequest.CSR.EmailAddresses
	logEvent.Extra["CSRIPAddresses"] = certificateRequest.CSR.IPAddresses

	// Inc CSR signature algorithm counter
	wfe.stats.csrSignatureAlgs.With(prometheus.Labels{"type": certificateRequest.CSR.SignatureAlgorithm.String()}).Inc()

	updatedOrder, err := wfe.RA.FinalizeOrder(ctx, &rapb.FinalizeOrderRequest{
		Csr:   rawCSR.CSR,
		Order: order,
	})
	if err != nil {
		wfe.sendError(response, logEvent, web.ProblemDetailsForError(err, "Error finalizing order"), err)
		return
	}

	orderURL := web.RelativeEndpoint(request,
		fmt.Sprintf("%s%d/%d", orderPath, acct.ID, *updatedOrder.Id))
	response.Header().Set("Location", orderURL)

	respObj := wfe.orderToOrderJSON(request, updatedOrder)
	err = wfe.writeJsonResponse(response, logEvent, http.StatusOK, respObj)
	if err != nil {
		wfe.sendError(response, logEvent, probs.ServerInternal("Unable to write finalize order response"), err)
		return
	}
}
