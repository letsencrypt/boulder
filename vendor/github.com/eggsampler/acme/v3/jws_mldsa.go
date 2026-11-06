//go:build go1.27

package acme

import (
	"crypto"
	"crypto/mldsa"
	"encoding/base64"
	"fmt"
)

func maybeMLDSASign(key crypto.Signer, message []byte) ([]byte, error) {
	switch key.(type) {
	case *mldsa.PrivateKey:
		return key.Sign(nil, message, nil)
	default:
		return nil, ErrUnsupportedKey
	}
}

func maybeMLDSAHasher(pub crypto.PublicKey) (string, crypto.Hash) {
	switch pub := pub.(type) {
	case *mldsa.PublicKey:
		switch pub.Parameters() {
		case mldsa.MLDSA44():
			return "ML-DSA-44", crypto.Hash(0)
		case mldsa.MLDSA65():
			return "ML-DSA-65", crypto.Hash(0)
		case mldsa.MLDSA87():
			return "ML-DSA-87", crypto.Hash(0)
		default:
			return "", crypto.Hash(0)
		}
	default:
		return "", crypto.Hash(0)
	}
}

func maybeMLDSAEncodeJWK(pub crypto.PublicKey) (string, error) {
	switch pub := pub.(type) {
	case *mldsa.PublicKey:
		var alg string
		switch pub.Parameters() {
		case mldsa.MLDSA44():
			alg = "ML-DSA-44"
		case mldsa.MLDSA65():
			alg = "ML-DSA-65"
		case mldsa.MLDSA87():
			alg = "ML-DSA-87"
		default:
			return "", ErrUnsupportedKey
		}
		res := fmt.Sprintf(`{"alg":"%s","kty":"AKP","pub":"%s"}`,
			alg,
			base64.RawURLEncoding.EncodeToString(pub.Bytes()))
		return res, nil
	default:
		return "", ErrUnsupportedKey
	}
}
