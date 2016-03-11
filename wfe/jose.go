package wfe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"
	"github.com/letsencrypt/boulder/core"
)

// HMAC signatures are disallowed as they do not rely on asymmetric cryptography.
// They aren't great to verify account ownership.
var disallowedAlgorithms = map[string]bool{
	"HS256": true,
	"HS384": true,
	"HS512": true,
}

func determineAlgorithm(jwk *jose.JsonWebKey) (string, error) {
	if jwk.Algorithm != "" && jwk.Algorithm != "none" &&
		!disallowedAlgorithms[jwk.Algorithm] {
		return jwk.Algorithm, nil
	}

	switch ktype := jwk.Key.(type) {
	case *rsa.PublicKey:
		return string(jose.RS256), nil
	case *ecdsa.PublicKey:
		switch ktype.Params() {
		case elliptic.P256().Params():
			return string(jose.ES256), nil
		case elliptic.P384().Params():
			return string(jose.ES384), nil
		case elliptic.P521().Params():
			return string(jose.ES512), nil
		}
	}

	return "", core.SignatureValidationError("no signature algorithms suitable for given key type")
}

const (
	noAlgorithmForKey     = "WFE.Errors.NoAlgorithmForKey"
	invalidJWSAlgorithm   = "WFE.Errors.InvalidJWSAlgorithm"
	invalidAlgorithmOnKey = "WFE.Errors.InvalidAlgorithmOnKey"
	jwsNotSigned          = "WFE.Errors.JWSNotSignedInPOST"
)

// checkAlgorithm makes sure a valid signing algorithm is used for the given JWK,
// and matches that of the JWS header.
func checkAlgorithm(key *jose.JsonWebKey, parsedJws *jose.JsonWebSignature) (string, error) {
	if len(parsedJws.Signatures) == 0 {
		return jwsNotSigned, core.SignatureValidationError("POST JWS not signed")
	}

	algorithm, err := determineAlgorithm(key)
	if err != nil {
		return noAlgorithmForKey, err
	}

	jwsAlgorithm := parsedJws.Signatures[0].Header.Algorithm
	if jwsAlgorithm != algorithm {
		return invalidJWSAlgorithm,
			core.SignatureValidationError(fmt.Sprintf(
				"algorithm '%s' in JWS header not acceptable", jwsAlgorithm))
	}

	if key.Algorithm != "" && key.Algorithm != algorithm {
		return invalidAlgorithmOnKey,
			core.SignatureValidationError(fmt.Sprintf(
				"algorithm '%s' on JWK is unacceptable", key.Algorithm))
	}
	return "", nil
}
