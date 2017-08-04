package wfe2

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/probs"

	"gopkg.in/square/go-jose.v2"
)

const sigAlgErr = "no signature algorithms suitable for given key type"

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
	return "", fmt.Errorf(sigAlgErr)
}

func sigAlgorithmForKey(key interface{}) (jose.SignatureAlgorithm, error) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return jose.RS256, nil
	case *ecdsa.PublicKey:
		return sigAlgorithmForECDSAKey(k)
	}
	return "", fmt.Errorf(sigAlgErr)
}

const (
	noAlgorithmForKeyStat     = "WFE.Errors.NoAlgorithmForKey"
	invalidJWSAlgorithmStat   = "WFE.Errors.InvalidJWSAlgorithm"
	invalidAlgorithmOnKeyStat = "WFE.Errors.InvalidAlgorithmOnKey"
)

// Check that (1) there is a suitable algorithm for the provided key based on its
// Golang type, (2) the Algorithm field on the JWK is either absent, or matches
// that algorithm, and (3) the Algorithm field on the JWK is present and matches
// that algorithm. Precondition: parsedJws must have exactly one signature on
// it. Returns stat name to increment if err is non-nil.
func checkAlgorithm(key *jose.JSONWebKey, parsedJWS *jose.JSONWebSignature) (string, error) {
	algorithm, err := sigAlgorithmForKey(key.Key)
	if err != nil {
		return noAlgorithmForKeyStat, err
	}
	jwsAlgorithm := parsedJWS.Signatures[0].Header.Algorithm
	if jwsAlgorithm != string(algorithm) {
		return invalidJWSAlgorithmStat, fmt.Errorf(
			"signature type '%s' in JWS header is not supported, expected one of RS256, ES256, ES384 or ES512",
			jwsAlgorithm,
		)
	}
	if key.Algorithm != "" && key.Algorithm != string(algorithm) {
		return invalidAlgorithmOnKeyStat, fmt.Errorf(
			"algorithm '%s' on JWK is unacceptable",
			key.Algorithm,
		)
	}
	return "", nil
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
// exclusive authentication types are specified at the same time a problem is
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
		wfe.stats.Inc("Errors.InvalidJWSAuth", 1)
		return prob
	}
	// If the auth type isn't the one expected return a sensible problem based on
	// what was expected
	if authType != expectedAuthType {
		wfe.stats.Inc("Errors.WrongJWSAuthType", 1)
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
func (wfe *WebFrontEndImpl) validPOSTRequest(
	request *http.Request,
	logEvent *requestEvent) *probs.ProblemDetails {
	// All POSTs should have an accompanying Content-Length header
	if _, present := request.Header["Content-Length"]; !present {
		wfe.stats.Inc("HTTP.ClientErrors.LengthRequiredError", 1)
		logEvent.AddError("missing Content-Length header on POST")
		return probs.ContentLengthRequired()
	}

	// Per 6.4.1 "Replay-Nonce" clients should not send a Replay-Nonce header in
	// the HTTP request, it needs to be part of the signed JWS request body
	if _, present := request.Header["Replay-Nonce"]; present {
		wfe.stats.Inc("HTTP.ClientErrors.ReplayNonceOutsideJWSError", 1)
		logEvent.AddError("Replay-Nonce header included outside of JWS body")
		return probs.Malformed("HTTP requests should NOT contain Replay-Nonce header. Use JWS nonce field")
	}

	// All POSTs should have a non-nil body
	if request.Body == nil {
		wfe.stats.Inc("HTTP.ClientErrors.NoPOSTBody", 1)
		logEvent.AddError("no body on POST")
		return probs.Malformed("No body on POST")
	}

	return nil
}

// validNonce checks a JWS' Nonce header to ensure it is one that the
// nonceService knows about, otherwise a bad nonce problem is returned. The
// provided logEvent is mutated to set the observed RequestNonce and any
// associated errors. NOTE: this function assumes the JWS has already been
// verified with the correct public key.
func (wfe *WebFrontEndImpl) validNonce(jws *jose.JSONWebSignature, logEvent *requestEvent) *probs.ProblemDetails {
	// validNonce is called after validPOSTRequest() and parseJWS() which
	// defend against the incorrect number of signatures.
	header := jws.Signatures[0].Header
	nonce := header.Nonce
	logEvent.RequestNonce = nonce
	if len(nonce) == 0 {
		wfe.stats.Inc("Errors.JWSMissingNonce", 1)
		logEvent.AddError("JWS is missing an anti-replay nonce")
		return probs.BadNonce("JWS has no anti-replay nonce")
	} else if !wfe.nonceService.Valid(nonce) {
		wfe.stats.Inc("Errors.JWSInvalidNonce", 1)
		logEvent.AddError("JWS has an invalid anti-replay nonce: %q", nonce)
		return probs.BadNonce(fmt.Sprintf("JWS has an invalid anti-replay nonce: %q", nonce))
	}
	return nil
}

// validPOSTURL checks the JWS' URL header against the expected URL based on the
// HTTP request. This prevents a JWS intended for one endpoint being replayed
// against a different endpoint. It mutates the provided logEvent to capture any
// errors.
func (wfe *WebFrontEndImpl) validPOSTURL(
	request *http.Request,
	jws *jose.JSONWebSignature,
	logEvent *requestEvent) *probs.ProblemDetails {
	// validPOSTURL is called after parseJWS() which defends against the incorrect
	// number of signatures.
	header := jws.Signatures[0].Header
	extraHeaders := header.ExtraHeaders
	// Check that there is at least one Extra Header
	if len(extraHeaders) == 0 {
		wfe.stats.Inc("Errors.MissingURLinJWS", 1)
		logEvent.AddError("JWS header parameter 'url' missing")
		return probs.Malformed("JWS header parameter 'url' required")
	}
	// Try to read a 'url' Extra Header as a string
	headerURL, ok := extraHeaders[jose.HeaderKey("url")].(string)
	if !ok || len(headerURL) == 0 {
		wfe.stats.Inc("Errors.MissingURLinJWS", 1)
		logEvent.AddError("JWS header parameter 'url' missing")
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
		return probs.Malformed(fmt.Sprintf(
			"JWS header parameter 'url' incorrect. Expected %q got %q",
			expectedURL.String(), headerURL))
	}
	return nil
}

// parseJWS extracts a JSONWebSignature from an HTTP POST request's body. If
// there is an error reading the JWS or if it has too few or too many
// signatures, a problem is returned and the requestEvent is mutated to contain
// the error.
func (wfe *WebFrontEndImpl) parseJWS(
	request *http.Request,
	logEvent *requestEvent) (*jose.JSONWebSignature, string, *probs.ProblemDetails) {
	// Verify that the POST request has the expected headers
	if prob := wfe.validPOSTRequest(request, logEvent); prob != nil {
		return nil, "", prob
	}

	// Read the POST request body's bytes. validPOSTRequest has already checked
	// that the body is non-nil
	bodyBytes, err := ioutil.ReadAll(request.Body)
	if err != nil {
		wfe.stats.Inc("Errors.UnableToReadRequestBody", 1)
		logEvent.AddError("unable to read request body")
		return nil, "", probs.ServerInternal("unable to read request body")
	}

	// Parse the raw JWS JSON to check that the unprotected Header field is not
	// being used for a key ID or a JWK. This must be done prior to
	// `jose.parseSigned` since it will strip away these headers.
	var unprotected struct {
		Header map[string]string
	}
	if err := json.Unmarshal(bodyBytes, &unprotected); err != nil {
		wfe.stats.Inc("Errors.JWSParseError", 1)
		logEvent.AddError("Parse error reading JWS from POST body")
		return nil, "", probs.Malformed("Parse error reading JWS")
	}

	// ACME v2 never uses values from the unprotected JWS header. Reject JWS that
	// include unprotected headers.
	if unprotected.Header != nil {
		wfe.stats.Inc("Errors.JWSUnprotectedHeaders", 1)
		errMsg := "Unprotected headers included in JWS"
		logEvent.AddError(errMsg)
		return nil, "", probs.Malformed(errMsg)
	}

	// Parse the JWS using go-jose and enforce that the expected one non-empty
	// signature is present in the parsed JWS.
	body := string(bodyBytes)
	parsedJWS, err := jose.ParseSigned(body)
	if err != nil {
		wfe.stats.Inc("Errors.JWSParseError", 1)
		logEvent.AddError("Parse error reading JWS from POST body")
		return nil, "", probs.Malformed("Parse error reading JWS")
	}
	if len(parsedJWS.Signatures) > 1 {
		wfe.stats.Inc("Errors.TooManySignaturesInJWS", 1)
		logEvent.AddError("Too many signatures in POST body JWS")
		return nil, "", probs.Malformed("Too many signatures in POST body")
	}
	if len(parsedJWS.Signatures) == 0 {
		wfe.stats.Inc("Errors.NoSignaturesInJWS", 1)
		logEvent.AddError("POST JWS not signed")
		return nil, "", probs.Malformed("POST JWS not signed")
	}
	if len(parsedJWS.Signatures) == 1 && len(parsedJWS.Signatures[0].Signature) == 0 {
		wfe.stats.Inc("Errors.EmptySignatureInJWS", 1)
		logEvent.AddError("POST JWS not signed")
		return nil, "", probs.Malformed("POST JWS not signed")
	}

	return parsedJWS, body, nil
}

// extractJWK extracts a JWK from a provided JWS or returns a problem. It
// expects that the JWS is using the embedded JWK style of authentication and
// does not contain an embedded Key ID. Callers should have acquired the
// provided JWS from parseJWS to ensure it has the correct number of signatures
// present. The provided logEvent is mutated to add any observed errors.
func (wfe *WebFrontEndImpl) extractJWK(
	jws *jose.JSONWebSignature,
	logEvent *requestEvent) (*jose.JSONWebKey, *probs.ProblemDetails) {
	// extractJWK expects the request to be using an embedded JWK auth type and
	// to not contain the mutually exclusive KeyID.
	if prob := wfe.enforceJWSAuthType(jws, embeddedJWK); prob != nil {
		logEvent.AddError("JWS auth type was not expected embeddedJWK auth")
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
		wfe.stats.Inc("Errors.InvalidJWK", 1)
		logEvent.AddError("JWK in request was invalid")
		return nil, probs.Malformed("Invalid JWK in JWS header")
	}

	return key, nil
}

// lookupJWK finds a JWK associated with the Key ID present in a provided JWS,
// returning the JWK and a pointer to the associated account, or a problem. It
// expects that the JWS is using the embedded Key ID style of authentication
// and does not contain an embedded JWK. Callers should have acquired the
// provided JWS from parseJWS to ensure it has the correct number of signatures
// present. The provided logEvent is mutated to add any observed errors.
func (wfe *WebFrontEndImpl) lookupJWK(
	jws *jose.JSONWebSignature,
	ctx context.Context,
	request *http.Request,
	logEvent *requestEvent) (*jose.JSONWebKey, *core.Registration, *probs.ProblemDetails) {
	// We expect the request to be using an embedded Key ID auth type and to not
	// contain the mutually exclusive embedded JWK.
	if prob := wfe.enforceJWSAuthType(jws, embeddedKeyID); prob != nil {
		logEvent.AddError("JWS auth type was not expected embeddedKeyID auth")
		return nil, nil, prob
	}

	// lookupJWK is called after parseJWS() which defends against the
	// incorrect number of signatures.
	header := jws.Signatures[0].Header
	accountURL := header.KeyID
	prefix := wfe.relativeEndpoint(request, regPath)
	accountIDStr := strings.TrimPrefix(accountURL, prefix)
	// Convert the account ID string to an int64 for use with the SA's
	// GetRegistration RPC
	accountID, err := strconv.ParseInt(accountIDStr, 10, 64)
	if err != nil {
		wfe.stats.Inc("Errors.InvalidKeyID", 1)
		logEvent.AddError("JWS key ID was invalid int64")
		return nil, nil, probs.Malformed(fmt.Sprintf("Malformed account ID in KeyID header"))
	}

	// Try to find the account for this account ID
	account, err := wfe.SA.GetRegistration(ctx, accountID)
	if err != nil {
		// If the account isn't found, return a suitable problem
		if berrors.Is(err, berrors.NotFound) {
			wfe.stats.Inc("Errors.KeyIDNotFound", 1)
			logEvent.AddError(fmt.Sprintf("Account %q not found", accountURL))
			return nil, nil, probs.AccountDoesNotExist(fmt.Sprintf(
				"Account %q not found", accountURL))
		}

		// If there was an error and it isn't a "Not Found" error, return
		// a ServerInternal problem since this is unexpected.
		wfe.stats.Inc("Errors.UnableToGetAccountByID", 1)
		logEvent.AddError(fmt.Sprintf("Error calling SA.GetRegistration: %s", err.Error()))
		return nil, nil, probs.ServerInternal(fmt.Sprintf(
			"Error retreiving account %q", accountURL))
	}

	// Verify the account is not deactivated
	if account.Status != core.StatusValid {
		wfe.stats.Inc("Errors.AccountIsNotValid", 1)
		logEvent.AddError(fmt.Sprintf("Account %q has status %q", accountURL, account.Status))
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
	body string,
	request *http.Request,
	logEvent *requestEvent) ([]byte, *probs.ProblemDetails) {

	// Check that the public key and JWS algorithms match expected
	if statName, err := checkAlgorithm(jwk, jws); err != nil {
		wfe.stats.Inc(statName, 1)
		logEvent.AddError("checkAlgorithm failed: %q", err.Error())
		return nil, probs.Malformed(err.Error())
	}

	// Verify the JWS signature with the public key.
	// NOTE: It might seem insecure for the WFE to be trusted to verify
	// client requests, i.e., that the verification should be done at the
	// RA.  However the WFE is the RA's only view of the outside world
	// *anyway*, so it could always lie about what key was used by faking
	// the signature itself.
	payload, err := jws.Verify(jwk)
	// If the signature verification fails, then return an error immediately with
	// a small bit of context from the JWS body
	if err != nil {
		n := len(body)
		if n > 100 {
			n = 100
		}
		wfe.stats.Inc("Errors.JWSVerificationFailed", 1)
		logEvent.AddError("verification of JWS with the JWK failed: %v; body: %s", err, body[:n])
		return nil, probs.Malformed("JWS verification error")
	}
	// Store the verified payload in the logEvent
	logEvent.Payload = string(payload)

	// Check that the JWS contains a correct Nonce header
	if prob := wfe.validNonce(jws, logEvent); prob != nil {
		return nil, prob
	}

	// Check that the HTTP request URL matches the URL in the signed JWS
	if prob := wfe.validPOSTURL(request, jws, logEvent); prob != nil {
		return nil, prob
	}

	// Previously the check for the request URL required unmarshalling the payload JSON
	// to check the "resource" field of the protected JWS body. This caught
	// invalid JSON early and so we preserve this check by explicitly trying to
	// unmarshal the payload as part of the verification and failing early if it
	// isn't JSON.
	var parsedBody struct{}
	if err := json.Unmarshal(payload, &parsedBody); err != nil {
		wfe.stats.Inc("Errors.UnparseableJWSPayload", 1)
		logEvent.AddError("POST JWS Body is invalid JSON: %q", err.Error())
		return nil, probs.Malformed("Request payload did not parse as JSON")
	}

	return payload, nil
}

// validPOSTForAccount checks that a given POST request has a valid JWS
// verified with the public key associated to a known account,
// specified by the JWS key ID. If the request is valid (e.g. the JWS is well
// formed, verifies with the JWK stored for the specified key ID, specifies the
// correct URL, and has a valid nonce) then `validPOSTForAccount` returns the
// validated JWS body, the JWK used to validate the JWS, the JWS that was
// validated and a pointer to the JWK's associated account. If any of these
// conditions are not met or an error occurs only a problem is returned.
func (wfe *WebFrontEndImpl) validPOSTForAccount(
	request *http.Request,
	ctx context.Context,
	logEvent *requestEvent) ([]byte, *jose.JSONWebKey, *jose.JSONWebSignature, *core.Registration, *probs.ProblemDetails) {
	// Parse the JWS from the POST request
	jws, body, prob := wfe.parseJWS(request, logEvent)
	if prob != nil {
		return nil, nil, nil, nil, prob
	}

	// Lookup the account and JWK for the key ID that authenticated the JWS
	pubKey, account, prob := wfe.lookupJWK(jws, ctx, request, logEvent)
	if prob != nil {
		return nil, nil, nil, nil, prob
	}

	// Verify the JWS with the JWK from the SA
	payload, prob := wfe.validJWSForKey(jws, pubKey, body, request, logEvent)
	if prob != nil {
		return nil, nil, nil, nil, prob
	}

	return payload, pubKey, jws, account, nil
}

// validSelfAuthenticatedPOST checks that a given POST request has a valid JWS
// verified with the JWK embedded in the JWS itself (e.g. self-authenticated).
// This type of POST request is only used for creating new accounts or revoking a
// certificate by signing the request with the private key corresponding to the
// certificate's public key and embedding that public key in the JWS. All other
// request should be validated using `validPOSTforAccount`. If the POST request
// validates (e.g. the JWS is well formed, verifies with the JWK embedded in it,
// the JWK meets policy/algorithm requirements, has the correct URL and includes a
// valid nonce) then `validSelfAuthenticatedPOST` returns the JWK that was
// embedded in the JWK and the JWS that was validated with the JWK. Otherwise if
// the valid JWS conditions are not met or an error occurs only a problem is
// returned.
func (wfe *WebFrontEndImpl) validSelfAuthenticatedPOST(
	request *http.Request,
	logEvent *requestEvent) ([]byte, *jose.JSONWebKey, *jose.JSONWebSignature, *probs.ProblemDetails) {

	// Parse the JWS from the POST request
	jws, body, prob := wfe.parseJWS(request, logEvent)
	if prob != nil {
		return nil, nil, nil, prob
	}

	// Extract the embedded JWK from the parsed JWS
	pubKey, prob := wfe.extractJWK(jws, logEvent)
	if prob != nil {
		return nil, nil, nil, prob
	}

	// If the key doesn't meet the GoodKey policy return a problem immediately
	if err := wfe.keyPolicy.GoodKey(pubKey.Key); err != nil {
		wfe.stats.Inc("Errors.JWKRejectedByGoodKey", 1)
		logEvent.AddError("JWK rejected by GoodKey: %s", err.Error())
		return nil, nil, nil, probs.Malformed(err.Error())
	}

	// Verify the JWS with the embedded JWK
	payload, prob := wfe.validJWSForKey(jws, pubKey, body, request, logEvent)
	if prob != nil {
		return nil, nil, nil, prob
	}

	return payload, pubKey, jws, nil
}
