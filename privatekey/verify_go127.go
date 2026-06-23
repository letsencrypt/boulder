//go:build go1.27

package privatekey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/mldsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"hash"
)

// verify ensures that the embedded PublicKey of the provided privateKey is
// actually a match for the private key. For an example of private keys
// embedding a mismatched public key, see:
// https://blog.hboeck.de/archives/888-How-I-tricked-Symantec-with-a-Fake-Private-Key.html.
//
// TODO(#8812): move this back to privatekey.go, above Load().
func verify(privateKey crypto.Signer) (crypto.Signer, crypto.PublicKey, error) {
	verifyHash, err := makeVerifyHash()
	if err != nil {
		return nil, nil, err
	}

	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		return verifyRSA(k, &k.PublicKey, verifyHash)

	case *ecdsa.PrivateKey:
		return verifyECDSA(k, &k.PublicKey, verifyHash)

	case *mldsa.PrivateKey:
		return verifyMLDSA(k, k.PublicKey(), verifyHash)

	default:
		// This should never happen.
		return nil, nil, errors.New("the provided private key was not *rsa.PrivateKey, *ecdsa.PrivateKey, or *mldsa.PrivateKey")
	}
}

// verifyMLDSA verifies ML-DSA private keys.
func verifyMLDSA(privKey *mldsa.PrivateKey, pubKey *mldsa.PublicKey, msgHash hash.Hash) (crypto.Signer, crypto.PublicKey, error) {
	sig, err := privKey.Sign(nil, msgHash.Sum(nil), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign using the provided ML-DSA private key: %s", err)
	}

	err = mldsa.Verify(pubKey, msgHash.Sum(nil), sig, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("the provided ML-DSA private key failed signature verification: %s", err)
	}
	return privKey, privKey.Public(), nil
}
