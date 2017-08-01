package wfe2

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/probs"

	"gopkg.in/square/go-jose.v2"
)

// signatureValidationError indicates that the user's signature could not
// be verified, either through adversarial activity, or misconfiguration of
// the user client.
type signatureValidationError string

func (e signatureValidationError) Error() string { return string(e) }

func algorithmForKey(key *jose.JSONWebKey) (string, error) {
	switch k := key.Key.(type) {
	case *rsa.PublicKey:
		return string(jose.RS256), nil
	case *ecdsa.PublicKey:
		switch k.Params().Name {
		case "P-256":
			return string(jose.ES256), nil
		case "P-384":
			return string(jose.ES384), nil
		case "P-521":
			return string(jose.ES512), nil
		}
	}
	return "", signatureValidationError("no signature algorithms suitable for given key type")
}

const (
	noAlgorithmForKey     = "WFE.Errors.NoAlgorithmForKey"
	invalidJWSAlgorithm   = "WFE.Errors.InvalidJWSAlgorithm"
	invalidAlgorithmOnKey = "WFE.Errors.InvalidAlgorithmOnKey"
)

// Check that (1) there is a suitable algorithm for the provided key based on its
// Golang type, (2) the Algorithm field on the JWK is either absent, or matches
// that algorithm, and (3) the Algorithm field on the JWK is present and matches
// that algorithm. Precondition: parsedJws must have exactly one signature on
// it. Returns stat name to increment if err is non-nil.
func checkAlgorithm(key *jose.JSONWebKey, parsedJws *jose.JSONWebSignature) (string, error) {
	algorithm, err := algorithmForKey(key)
	if err != nil {
		return noAlgorithmForKey, err
	}
	jwsAlgorithm := parsedJws.Signatures[0].Header.Algorithm
	if jwsAlgorithm != algorithm {
		return invalidJWSAlgorithm, signatureValidationError(fmt.Sprintf(
			"signature type '%s' in JWS header is not supported, expected one of RS256, ES256, ES384 or ES512",
			jwsAlgorithm,
		))
	}
	if key.Algorithm != "" && key.Algorithm != algorithm {
		return invalidAlgorithmOnKey, signatureValidationError(fmt.Sprintf(
			"algorithm '%s' on JWK is unacceptable",
			key.Algorithm,
		))
	}
	return "", nil
}

const (
	unknownKey = "No registration exists matching provided key"
)

func (wfe *WebFrontEndImpl) extractJWSKey(body string) (*jose.JSONWebKey, *jose.JSONWebSignature, error) {
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

	key := parsedJws.Signatures[0].Header.JSONWebKey
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
func (wfe *WebFrontEndImpl) verifyPOST(ctx context.Context, logEvent *requestEvent, request *http.Request, regCheck bool, resource core.AcmeResource) ([]byte, *jose.JSONWebKey, core.Registration, *probs.ProblemDetails) {
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

	var key *jose.JSONWebKey
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
	if regCheck && reg.Status != core.StatusValid {
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
