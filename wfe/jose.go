package wfe

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"

	"gopkg.in/square/go-jose.v2"
)

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
	return "", fmt.Errorf("JWK contains unsupported key type (expected RSA, or ECDSA P-256, P-384, or P-521")
}

const (
	noAlgorithmForKey     = "WFE.Errors.NoAlgorithmForKey"
	invalidJWSAlgorithm   = "WFE.Errors.InvalidJWSAlgorithm"
	invalidAlgorithmOnKey = "WFE.Errors.InvalidAlgorithmOnKey"
)

var supportedAlgs = map[string]bool{
	string(jose.RS256): true,
	string(jose.ES256): true,
	string(jose.ES384): true,
	string(jose.ES512): true,
}

// Check that (1) there is a suitable algorithm for the provided key based on its
// Golang type, (2) the Algorithm field on the JWK is either absent, or matches
// that algorithm, and (3) the Algorithm field on the JWK is present and matches
// that algorithm. Precondition: parsedJWS must have exactly one signature on
// it. Returns stat name to increment if err is non-nil.
func checkAlgorithm(key *jose.JSONWebKey, parsedJWS *jose.JSONWebSignature) (string, error) {
	sigHeaderAlg := parsedJWS.Signatures[0].Header.Algorithm
	if !supportedAlgs[sigHeaderAlg] {
		return invalidJWSAlgorithm, fmt.Errorf(
			"JWS signature header contains unsupported algorithm %q, expected one of RS256, ES256, ES384 or ES512",
			parsedJWS.Signatures[0].Header.Algorithm,
		)
	}
	expectedAlg, err := algorithmForKey(key)
	if err != nil {
		return noAlgorithmForKey, err
	}
	if sigHeaderAlg != string(expectedAlg) {
		return invalidJWSAlgorithm, fmt.Errorf("JWS signature header algorithm %q does not match expected algorithm %q for JWK", sigHeaderAlg, string(expectedAlg))
	}
	if key.Algorithm != "" && key.Algorithm != string(expectedAlg) {
		return invalidAlgorithmOnKey, fmt.Errorf("JWK key header algorithm %q does not match expected algorithm %q for JWK", key.Algorithm, string(expectedAlg))
	}
	return "", nil
}
