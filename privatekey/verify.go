//go:build !go1.27

package privatekey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
)

// verify ensures that the embedded PublicKey of the provided privateKey is
// actually a match for the private key. For an example of private keys
// embedding a mismatched public key, see:
// https://blog.hboeck.de/archives/888-How-I-tricked-Symantec-with-a-Fake-Private-Key.html.
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

	default:
		// This should never happen.
		return nil, nil, errors.New("the provided private key could not be asserted to ECDSA or RSA")
	}
}
