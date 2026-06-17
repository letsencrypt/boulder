//go:build !go1.27

package linter

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

func makeSigner(realSigner crypto.Signer) (crypto.Signer, error) {
	var lintSigner crypto.Signer
	var err error
	switch k := realSigner.Public().(type) {
	case *rsa.PublicKey:
		lintSigner, err = rsa.GenerateKey(rand.Reader, k.Size()*8)
		if err != nil {
			return nil, fmt.Errorf("failed to create RSA lint signer: %w", err)
		}
	case *ecdsa.PublicKey:
		lintSigner, err = ecdsa.GenerateKey(k.Curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to create ECDSA lint signer: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported lint signer type: %T", k)
	}
	return lintSigner, nil
}
