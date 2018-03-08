package wfe2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/square/go-jose.v2"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/web"
)

// POST requests with a JWS body must have the following Content-Type header
const expectedJWSContentType = "application/jose+json"

var sigAlgErr = errors.New("no signature algorithms suitable for given key type")

func sigAlgorithmForECDSAKey(key *ecdsa.PublicKey) (jose.SignatureAlgorithm, error) {
	params := key.Params()
	switch params.Name {
	case "P-256":
		return jose.ES256, nil
	case "P-384":
		return jose.ES384, nil
	case "P-521":
		return jose.ES512, nil
	}
	return "", sigAlgErr
}

func sigAlgorithmForKey(key crypto.PublicKey) (jose.SignatureAlgorithm, error) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return jose.RS256, nil
	case *ecdsa.PublicKey:
		return sigAlgorithmForECDSAKey(k)
	}
	return "", sigAlgErr
}

// Check that (1) there is a suitable algorithm for the provided key based on its
// Golang type, (2) the Algorithm field on the JWK is either absent, or matches
// that algorithm, and (3) the Algorithm field on the JWK is present and matches
// that algorithm. Precondition: parsedJws must have exactly one signature on
// it.
func checkAlgorithm(key *jose.JSONWebKey, parsedJWS *jose.JSONWebSignature) error {
	algorithm, err := sigAlgorithmForKey(key.Key)
	if err != nil {
		return err
	}
	jwsAlgorithm := parsedJWS.Signatures[0].Header.Algorithm
	if jwsAlgorithm != string(algorithm) {
		return fmt.Errorf(
			"signature type '%s' in JWS header is not supported, expected one of RS256, ES256, ES384 or ES512",
			jwsAlgorithm,
		)
	}
	if key.Algorithm != "" && key.Algorithm != string(algorithm) {
		return fmt.Errorf("algorithm '%s' on JWK is unacceptable", key.Algorithm)
	}
	return nil
}

// jwsAuthType represents whether a given POST request is authenticated using
// a JWS with an embedded JWK (v1 ACME style, new-account, revoke-cert) or an
// embeded Key ID (v2 AMCE style) or an unsupported/unknown auth type.
type jwsAuthType int

const (
	embeddedJWK jwsAuthType = iota
	embeddedKeyID
	invalidAuthType
)

// checkJWSAuthType examines a JWS' protected headers to determine if
// the request being authenticated by the JWS is identified using an embedded
// JWK or an embedded key ID. If no signatures are present, or mutually
// exclusive authentication types are specified at the same time, a problem is
// returned. checkJWSAuthType is separate from enforceJWSAuthType so that
// endpoints that need to handle both embedded JWK and embedded key ID requests
// can determine which type of request they have and act accordingly (e.g.
// acme v2 cert revocation).
func checkJWSAuthType(jws *jose.JSONWebSignature) (jwsAuthType, *probs.ProblemDetails) {
	// checkJWSAuthType is called after parseJWS() which defends against the
	// incorrect number of signatures.
	header := jws.Signatures[0].Header
	// There must not be a Key ID *and* an embedded JWK
	if header.KeyID != "" && header.JSONWebKey != nil {
		return invalidAuthType, probs.Malformed(
			"jwk and kid header fields are mutually exclusive")
	} else if header.KeyID != "" {
		return embeddedKeyID, nil
	} else if header.JSONWebKey != nil {
		return embeddedJWK, nil
	}
	return invalidAuthType, nil
}

// enforceJWSAuthType enforces a provided JWS has the provided auth type. If there
// is an error determining the auth type or if it is not the expected auth type
// then a problem is returned.
func (wfe *WebFrontEndImpl) enforceJWSAuthType(
	jws *jose.JSONWebSignature,
	expectedAuthType jwsAuthType) *probs.ProblemDetails {
	// Check the auth type for the provided JWS
	authType, prob := checkJWSAuthType(jws)
	if prob != nil {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "JWSAuthTypeInvalid"}).Inc()
		return prob
	}
	// If the auth type isn't the one expected return a sensible problem based on
	// what was expected
	if authType != expectedAuthType {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "JWSAuthTypeWrong"}).Inc()
		switch expectedAuthType {
		case embeddedKeyID:
			return probs.Malformed("No Key ID in JWS header")
		case embeddedJWK:
			return probs.Malformed("No embedded JWK in JWS header")
		}
	}
	return nil
}

// validPOSTRequest checks a *http.Request to ensure it has the headers
// a well-formed ACME POST request has, and to ensure there is a body to
// process.
func (wfe *WebFrontEndImpl) validPOSTRequest(request *http.Request) *probs.ProblemDetails {
	// All POSTs should have an accompanying Content-Length header
	if _, present := request.Header["Content-Length"]; !present {
		wfe.stats.httpErrorCount.With(prometheus.Labels{"type": "ContentLengthRequired"}).Inc()
		return probs.ContentLengthRequired()
	}

	if features.Enabled(features.EnforceV2ContentType) {
		// Per 6.2 ALL POSTs should have the correct JWS Content-Type for flattened
		// JSON serialization.
		if _, present := request.Header["Content-Type"]; !present {
			wfe.stats.httpErrorCount.With(prometheus.Labels{"type": "NoContentType"}).Inc()
			return probs.InvalidContentType(fmt.Sprintf(
				"No Content-Type header on POST. "+
					"Content-Type must be %q", expectedJWSContentType))
		}
		if contentType := request.Header.Get("Content-Type"); contentType != expectedJWSContentType {
			wfe.stats.httpErrorCount.With(prometheus.Labels{"type": "WrongContentType"}).Inc()
			return probs.InvalidContentType(fmt.Sprintf(
				"Invalid Content-Type header on POST. "+
					"Content-Type must be %q", expectedJWSContentType))
		}
	}

	// Per 6.4.1 "Replay-Nonce" clients should not send a Replay-Nonce header in
	// the HTTP request, it needs to be part of the signed JWS request body
	if _, present := request.Header["Replay-Nonce"]; present {
		wfe.stats.httpErrorCount.With(prometheus.Labels{"type": "ReplayNonceOutsideJWS"}).Inc()
		return probs.Malformed("HTTP requests should NOT contain Replay-Nonce header. Use JWS nonce field")
	}

	// All POSTs should have a non-nil body
	if request.Body == nil {
		wfe.stats.httpErrorCount.With(prometheus.Labels{"type": "NoPOSTBody"}).Inc()
		return probs.Malformed("No body on POST")
	}

	return nil
}

// validNonce checks a JWS' Nonce header to ensure it is one that the
// nonceService knows about, otherwise a bad nonce problem is returned.
// NOTE: this function assumes the JWS has already been verified with the
// correct public key.
func (wfe *WebFrontEndImpl) validNonce(jws *jose.JSONWebSignature) *probs.ProblemDetails {
	// validNonce is called after validPOSTRequest() and parseJWS() which
	// defend against the incorrect number of signatures.
	header := jws.Signatures[0].Header
	nonce := header.Nonce
	if len(nonce) == 0 {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "JWSMissingNonce"}).Inc()
		return probs.BadNonce("JWS has no anti-replay nonce")
	} else if !wfe.nonceService.Valid(nonce) {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "JWSInvalidNonce"}).Inc()
		return probs.BadNonce(fmt.Sprintf("JWS has an invalid anti-replay nonce: %q", nonce))
	}
	return nil
}

// validPOSTURL checks the JWS' URL header against the expected URL based on the
// HTTP request. This prevents a JWS intended for one endpoint being replayed
// against a different endpoint. If the URL isn't present, is invalid, or
// doesn't match the HTTP request a problem is returned.
func (wfe *WebFrontEndImpl) validPOSTURL(
	request *http.Request,
	jws *jose.JSONWebSignature) *probs.ProblemDetails {
	// validPOSTURL is called after parseJWS() which defends against the incorrect
	// number of signatures.
	header := jws.Signatures[0].Header
	extraHeaders := header.ExtraHeaders
	// Check that there is at least one Extra Header
	if len(extraHeaders) == 0 {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "JWSNoExtraHeaders"}).Inc()
		return probs.Malformed("JWS header parameter 'url' required")
	}
	// Try to read a 'url' Extra Header as a string
	headerURL, ok := extraHeaders[jose.HeaderKey("url")].(string)
	if !ok || len(headerURL) == 0 {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "JWSMissingURL"}).Inc()
		return probs.Malformed("JWS header parameter 'url' required")
	}
	// Compute the URL we expect to be in the JWS based on the HTTP request
	expectedURL := url.URL{
		Scheme: requestProto(request),
		Host:   request.Host,
		Path:   request.RequestURI,
	}
	// Check that the URL we expect is the one that was found in the signed JWS
	// header
	if expectedURL.String() != headerURL {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "JWSMismatchedURL"}).Inc()
		return probs.Malformed(fmt.Sprintf(
			"JWS header parameter 'url' incorrect. Expected %q got %q",
			expectedURL.String(), headerURL))
	}
	return nil
}

// matchJWSURLs checks two JWS' URL headers are equal. This is used during key
// rollover to check that the inner JWS URL matches the outer JWS URL. If the
// JWS URLs do not match a problem is returned.
func (wfe *WebFrontEndImpl) matchJWSURLs(outer, inner *jose.JSONWebSignature) *probs.ProblemDetails {
	// Verify that the outer JWS has a non-empty URL header. This is strictly
	// defensive since the expectation is that endpoints using `matchJWSURLs`
	// have received at least one of their JWS from calling validPOSTForAccount(),
	// which checks the outer JWS has the expected URL header before processing
	// the inner JWS.
	outerURL, ok := outer.Signatures[0].Header.ExtraHeaders[jose.HeaderKey("url")].(string)
	if !ok || len(outerURL) == 0 {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "KeyRolloverOuterJWSNoURL"}).Inc()
		return probs.Malformed("Outer JWS header parameter 'url' required")
	}

	// Verify the inner JWS has a non-empty URL header.
	innerURL, ok := inner.Signatures[0].Header.ExtraHeaders[jose.HeaderKey("url")].(string)
	if !ok || len(innerURL) == 0 {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "KeyRolloverInnerJWSNoURL"}).Inc()
		return probs.Malformed("Inner JWS header parameter 'url' required")
	}

	// Verify that the outer URL matches the inner URL
	if outerURL != innerURL {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "KeyRolloverMismatchedURLs"}).Inc()
		return probs.Malformed(fmt.Sprintf(
			"Outer JWS 'url' value %q does not match inner JWS 'url' value %q",
			outerURL, innerURL))
	}

	return nil
}

// parseJWS extracts a JSONWebSignature from a byte slice. If there is an error
// reading the JWS or it is unacceptable (e.g. too many/too few signatures,
// presence of unprotected headers) a problem is returned, otherwise the parsed
// *JSONWebSignature is returned.
func (wfe *WebFrontEndImpl) parseJWS(body []byte) (*jose.JSONWebSignature, *probs.ProblemDetails) {
	// Parse the raw JWS JSON to check that:
	// * the unprotected Header field is not being used.
	// * the "signatures" member isn't present, just "signature".
	//
	// This must be done prior to `jose.parseSigned` since it will strip away
	// these headers.
	var unprotected struct {
		Header     map[string]string
		Signatures []interface{}
	}
	if err := json.Unmarshal(body, &unprotected); err != nil {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "JWSUnmarshalFailed"}).Inc()
		return nil, probs.Malformed("Parse error reading JWS")
	}

	// ACME v2 never uses values from the unprotected JWS header. Reject JWS that
	// include unprotected headers.
	if unprotected.Header != nil {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "JWSUnprotectedHeaders"}).Inc()
		return nil, probs.Malformed(
			"JWS \"header\" field not allowed. All headers must be in \"protected\" field")
	}

	// ACME v2 never uses the "signatures" array of JSON serialized JWS, just the
	// mandatory "signature" field. Reject JWS that include the "signatures" array.
	if len(unprotected.Signatures) > 0 {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "JWSMultiSig"}).Inc()
		return nil, probs.Malformed(
			"JWS \"signatures\" field not allowed. Only the \"signature\" field should contain a signature")
	}

	// Parse the JWS using go-jose and enforce that the expected one non-empty
	// signature is present in the parsed JWS.
	bodyStr := string(body)
	parsedJWS, err := jose.ParseSigned(bodyStr)
	if err != nil {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "JWSParseError"}).Inc()
		return nil, probs.Malformed("Parse error reading JWS")
	}
	if len(parsedJWS.Signatures) > 1 {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "JWSTooManySignatures"}).Inc()
		return nil, probs.Malformed("Too many signatures in POST body")
	}
	if len(parsedJWS.Signatures) == 0 {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "JWSNoSignatures"}).Inc()
		return nil, probs.Malformed("POST JWS not signed")
	}
	if len(parsedJWS.Signatures) == 1 && len(parsedJWS.Signatures[0].Signature) == 0 {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "JWSEmptySignature"}).Inc()
		return nil, probs.Malformed("POST JWS not signed")
	}

	return parsedJWS, nil
}

// parseJWSRequest extracts a JSONWebSignature from an HTTP POST request's body using parseJWS.
func (wfe *WebFrontEndImpl) parseJWSRequest(request *http.Request) (*jose.JSONWebSignature, *probs.ProblemDetails) {
	// Verify that the POST request has the expected headers
	if prob := wfe.validPOSTRequest(request); prob != nil {
		return nil, prob
	}

	// Read the POST request body's bytes. validPOSTRequest has already checked
	// that the body is non-nil
	bodyBytes, err := ioutil.ReadAll(request.Body)
	if err != nil {
		wfe.stats.httpErrorCount.With(prometheus.Labels{"type": "UnableToReadReqBody"}).Inc()
		return nil, probs.ServerInternal("unable to read request body")
	}

	return wfe.parseJWS(bodyBytes)
}

// extractJWK extracts a JWK from a provided JWS or returns a problem. It
// expects that the JWS is using the embedded JWK style of authentication and
// does not contain an embedded Key ID. Callers should have acquired the
// provided JWS from parseJWS to ensure it has the correct number of signatures
// present.
func (wfe *WebFrontEndImpl) extractJWK(jws *jose.JSONWebSignature) (*jose.JSONWebKey, *probs.ProblemDetails) {
	// extractJWK expects the request to be using an embedded JWK auth type and
	// to not contain the mutually exclusive KeyID.
	if prob := wfe.enforceJWSAuthType(jws, embeddedJWK); prob != nil {
		return nil, prob
	}

	// extractJWK must be called after parseJWS() which defends against the
	// incorrect number of signatures.
	header := jws.Signatures[0].Header
	// We can be sure that JSONWebKey is != nil because we have already called
	// enforceJWSAuthType()
	key := header.JSONWebKey

	// If the key isn't considered valid by go-jose return a problem immediately
	if !key.Valid() {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "JWKInvalid"}).Inc()
		return nil, probs.Malformed("Invalid JWK in JWS header")
	}

	return key, nil
}

// lookupJWK finds a JWK associated with the Key ID present in a provided JWS,
// returning the JWK and a pointer to the associated account, or a problem. It
// expects that the JWS is using the embedded Key ID style of authentication
// and does not contain an embedded JWK. Callers should have acquired the
// provided JWS from parseJWS to ensure it has the correct number of signatures
// present.
func (wfe *WebFrontEndImpl) lookupJWK(
	jws *jose.JSONWebSignature,
	ctx context.Context,
	request *http.Request,
	logEvent *web.RequestEvent) (*jose.JSONWebKey, *core.Registration, *probs.ProblemDetails) {
	// We expect the request to be using an embedded Key ID auth type and to not
	// contain the mutually exclusive embedded JWK.
	if prob := wfe.enforceJWSAuthType(jws, embeddedKeyID); prob != nil {
		return nil, nil, prob
	}

	header := jws.Signatures[0].Header
	accountURL := header.KeyID
	prefix := wfe.relativeEndpoint(request, acctPath)
	accountIDStr := strings.TrimPrefix(accountURL, prefix)
	// Convert the account ID string to an int64 for use with the SA's
	// GetRegistration RPC
	accountID, err := strconv.ParseInt(accountIDStr, 10, 64)
	if err != nil {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "JWSInvalidKeyID"}).Inc()
		return nil, nil, probs.Malformed(fmt.Sprintf("Malformed account ID in KeyID header"))
	}

	// Try to find the account for this account ID
	account, err := wfe.SA.GetRegistration(ctx, accountID)
	if err != nil {
		// If the account isn't found, return a suitable problem
		if berrors.Is(err, berrors.NotFound) {
			wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "JWSKeyIDNotFound"}).Inc()
			return nil, nil, probs.AccountDoesNotExist(fmt.Sprintf(
				"Account %q not found", accountURL))
		}

		// If there was an error and it isn't a "Not Found" error, return
		// a ServerInternal problem since this is unexpected.
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "JWSKeyIDLookupFailed"}).Inc()
		// Add an error to the log event with the internal error message
		logEvent.AddError(fmt.Sprintf("Error calling SA.GetRegistration: %s", err.Error()))
		return nil, nil, probs.ServerInternal(fmt.Sprintf(
			"Error retreiving account %q", accountURL))
	}

	// Verify the account is not deactivated
	if account.Status != core.StatusValid {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "JWSKeyIDAccountInvalid"}).Inc()
		return nil, nil, probs.Unauthorized(
			fmt.Sprintf("Account is not valid, has status %q", account.Status))
	}

	// Update the logEvent with the account information and return the JWK
	logEvent.Requester = account.ID
	logEvent.Contacts = account.Contact
	return account.Key, &account, nil
}

// validJWSForKey checks a provided JWS for a given HTTP request validates
// correctly using the provided JWK. If the JWS verifies the protected payload
// is returned. The key/JWS algorithms are verified and
// the JWK is checked against the keyPolicy before any signature validation is
// done. If the JWS signature validates correctly then the JWS nonce value
// and the JWS URL are verified to ensure that they are correct.
func (wfe *WebFrontEndImpl) validJWSForKey(
	jws *jose.JSONWebSignature,
	jwk *jose.JSONWebKey,
	request *http.Request,
	logEvent *web.RequestEvent) ([]byte, *probs.ProblemDetails) {

	// Check that the public key and JWS algorithms match expected
	if err := checkAlgorithm(jwk, jws); err != nil {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "JWSAlgorithmCheckFailed"}).Inc()
		return nil, probs.Malformed(err.Error())
	}

	// Verify the JWS signature with the public key.
	// NOTE: It might seem insecure for the WFE to be trusted to verify
	// client requests, i.e., that the verification should be done at the
	// RA.  However the WFE is the RA's only view of the outside world
	// *anyway*, so it could always lie about what key was used by faking
	// the signature itself.
	payload, err := jws.Verify(jwk)
	if err != nil {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "JWSVerifyFailed"}).Inc()
		return nil, probs.Malformed("JWS verification error")
	}
	// Store the verified payload in the logEvent
	logEvent.Payload = string(payload)

	// Check that the JWS contains a correct Nonce header
	if prob := wfe.validNonce(jws); prob != nil {
		return nil, prob
	}

	// Check that the HTTP request URL matches the URL in the signed JWS
	if prob := wfe.validPOSTURL(request, jws); prob != nil {
		return nil, prob
	}

	// In the WFE1 package the check for the request URL required unmarshalling
	// the payload JSON to check the "resource" field of the protected JWS body.
	// This caught invalid JSON early and so we preserve this check by explicitly
	// trying to unmarshal the payload as part of the verification and failing
	// early if it isn't valid JSON.
	var parsedBody struct{}
	if err := json.Unmarshal(payload, &parsedBody); err != nil {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "JWSBodyUnmarshalFailed"}).Inc()
		return nil, probs.Malformed("Request payload did not parse as JSON")
	}

	return payload, nil
}

// validJWSForAccount checks that a given JWS is valid and verifies with the
// public key associated to a known account specified by the JWS Key ID. If the
// JWS is valid (e.g. the JWS is well formed, verifies with the JWK stored for the
// specified key ID, specifies the correct URL, and has a valid nonce) then
// `validJWSForAccount` returns the validated JWS body, the parsed
// JSONWebSignature, and a pointer to the JWK's associated account. If any of
// these conditions are not met or an error occurs only a problem is returned.
func (wfe *WebFrontEndImpl) validJWSForAccount(
	jws *jose.JSONWebSignature,
	request *http.Request,
	ctx context.Context,
	logEvent *web.RequestEvent) ([]byte, *jose.JSONWebSignature, *core.Registration, *probs.ProblemDetails) {
	// Lookup the account and JWK for the key ID that authenticated the JWS
	pubKey, account, prob := wfe.lookupJWK(jws, ctx, request, logEvent)
	if prob != nil {
		return nil, nil, nil, prob
	}

	// Verify the JWS with the JWK from the SA
	payload, prob := wfe.validJWSForKey(jws, pubKey, request, logEvent)
	if prob != nil {
		return nil, nil, nil, prob
	}

	return payload, jws, account, nil
}

// validPOSTForAccount checks that a given POST request has a valid JWS
// using `validJWSForAccount`.
func (wfe *WebFrontEndImpl) validPOSTForAccount(
	request *http.Request,
	ctx context.Context,
	logEvent *web.RequestEvent) ([]byte, *jose.JSONWebSignature, *core.Registration, *probs.ProblemDetails) {
	// Parse the JWS from the POST request
	jws, prob := wfe.parseJWSRequest(request)
	if prob != nil {
		return nil, nil, nil, prob
	}
	return wfe.validJWSForAccount(jws, request, ctx, logEvent)
}

// validSelfAuthenticatedJWS checks that a given JWS verifies with the JWK
// embedded in the JWS itself (e.g. self-authenticated). This type of JWS
// is only used for creating new accounts or revoking a certificate by signing
// the request with the private key corresponding to the certificate's public
// key and embedding that public key in the JWS. All other request should be
// validated using `validJWSforAccount`. If the JWS validates (e.g. the JWS is
// well formed, verifies with the JWK embedded in it, the JWK meets
// policy/algorithm requirements, has the correct URL and includes a valid
// nonce) then `validSelfAuthenticatedJWS` returns the validated JWS body and
// the JWK that was embedded in the JWS. Otherwise if the valid JWS conditions
// are not met or an error occurs only a problem is returned
func (wfe *WebFrontEndImpl) validSelfAuthenticatedJWS(
	jws *jose.JSONWebSignature,
	request *http.Request,
	logEvent *web.RequestEvent) ([]byte, *jose.JSONWebKey, *probs.ProblemDetails) {
	// Extract the embedded JWK from the parsed JWS
	pubKey, prob := wfe.extractJWK(jws)
	if prob != nil {
		return nil, nil, prob
	}

	// If the key doesn't meet the GoodKey policy return a problem immediately
	if err := wfe.keyPolicy.GoodKey(pubKey.Key); err != nil {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "JWKRejectedByGoodKey"}).Inc()
		return nil, nil, probs.Malformed(err.Error())
	}

	// Verify the JWS with the embedded JWK
	payload, prob := wfe.validJWSForKey(jws, pubKey, request, logEvent)
	if prob != nil {
		return nil, nil, prob
	}

	return payload, pubKey, nil
}

// validSelfAuthenticatedPOST checks that a given POST request has a valid JWS
// using `validSelfAuthenticatedJWS`.
func (wfe *WebFrontEndImpl) validSelfAuthenticatedPOST(
	request *http.Request,
	logEvent *web.RequestEvent) ([]byte, *jose.JSONWebKey, *probs.ProblemDetails) {
	// Parse the JWS from the POST request
	jws, prob := wfe.parseJWSRequest(request)
	if prob != nil {
		return nil, nil, prob
	}
	// Extract and validate the embedded JWK from the parsed JWS
	return wfe.validSelfAuthenticatedJWS(jws, request, logEvent)
}

// rolloverRequest is a struct representing an ACME key rollover request
type rolloverRequest struct {
	NewKey  jose.JSONWebKey
	Account string
}

// validKeyRollover checks if the innerJWS is a valid key rollover operation
// given the outer JWS that carried it. It is assumed that the outerJWS has
// already been validated per the normal ACME process using `validPOSTForAccount`.
// It is *critical* this is the case since `validKeyRollover` does not check the
// outerJWS signature. This function checks that:
// 1) the inner JWS is valid and well formed
// 2) the inner JWS has the same "url" header as the outer JWS
// 3) the inner JWS is self-authenticated with an embedded JWK
// 4) the payload of the inner JWS is a valid JSON key change object
// 5) that the key specified in the key change object *also* verifies the inner JWS
// A *rolloverRequest object and is returned if successfully validated,
// otherwise a problem is returned. The caller is left to verify whether the
// new key is appropriate (e.g. isn't being used by another existing account)
// and that the account field of the rollover object matches the account that
// verified the outer JWS.
func (wfe *WebFrontEndImpl) validKeyRollover(
	outerJWS *jose.JSONWebSignature,
	innerJWS *jose.JSONWebSignature,
	logEvent *web.RequestEvent) (*rolloverRequest, *probs.ProblemDetails) {

	// Extract the embedded JWK from the inner JWS
	jwk, prob := wfe.extractJWK(innerJWS)
	if prob != nil {
		return nil, prob
	}

	// If the key doesn't meet the GoodKey policy return a problem immediately
	if err := wfe.keyPolicy.GoodKey(jwk.Key); err != nil {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "KeyRolloverJWKRejectedByGoodKey"}).Inc()
		return nil, probs.Malformed(err.Error())
	}

	// Check that the public key and JWS algorithms match expected
	if err := checkAlgorithm(jwk, innerJWS); err != nil {
		return nil, probs.Malformed(err.Error())
	}

	// Verify the inner JWS signature with the public key from the embedded JWK.
	// NOTE(@cpu): We do not use `wfe.validJWSForKey` here because the inner JWS
	// of a key rollover operation is special (e.g. has no nonce, doesn't have an
	// HTTP request to match the URL to)
	innerPayload, err := innerJWS.Verify(jwk)
	if err != nil {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "KeyRolloverJWSVerifyFailed"}).Inc()
		return nil, probs.Malformed("Inner JWS does not verify with embedded JWK")
	}
	// NOTE(@cpu): we do not stomp the web.RequestEvent's payload here since that is set
	// from the outerJWS in validPOSTForAccount and contains the inner JWS and inner
	// payload already.

	// Verify that the outer and inner JWS protected URL headers match
	if wfe.matchJWSURLs(outerJWS, innerJWS) != nil {
		return nil, prob
	}

	// Unmarshal the inner JWS' key roll over request
	var req rolloverRequest
	if json.Unmarshal(innerPayload, &req) != nil {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "KeyRolloverUnmarshalFailed"}).Inc()
		return nil, probs.Malformed(
			"Inner JWS payload did not parse as JSON key rollover object")
	}

	// Verify that the key roll over request's NewKey *also* validates the inner
	// JWS. So far we've only checked that the JWK embedded in the inner JWS valides
	// the JWS.
	if _, err := innerJWS.Verify(req.NewKey); err != nil {
		wfe.stats.joseErrorCount.With(prometheus.Labels{"type": "KeyRolloverJWSNewKeyVerifyFailed"}).Inc()
		return nil, probs.Malformed("Inner JWS does not verify with specified new key")
	}

	return &req, nil
}
