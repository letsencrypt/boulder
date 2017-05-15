package wfe

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"

	"gopkg.in/square/go-jose.v1"
)

func algorithmForKey(key *jose.JsonWebKey) (string, error) {
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
func checkAlgorithm(key *jose.JsonWebKey, parsedJws *jose.JsonWebSignature) (string, error) {
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
