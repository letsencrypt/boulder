//go:build !go1.27

package acme

import (
	"crypto"
)

func maybeMLDSASign(key crypto.Signer, message []byte) ([]byte, error) {
	return nil, ErrUnsupportedKey
}

func maybeMLDSAHasher(pub crypto.PublicKey) (string, crypto.Hash) {
	return "", crypto.Hash(0)
}

func maybeMLDSAEncodeJWK(pub crypto.PublicKey) (string, error) {
	return "", ErrUnsupportedKey
}
