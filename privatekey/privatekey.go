package privatekey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io/ioutil"
)

// verifyRSA is broken out of Verify for testing purposes.
func verifyRSA(privKey *rsa.PrivateKey, pubKey *rsa.PublicKey, msgHash hash.Hash) error {
	signatureRSA, err := rsa.SignPSS(rand.Reader, privKey, crypto.SHA256, msgHash.Sum(nil), nil)
	if err != nil {
		return fmt.Errorf("failed to sign using the provided RSA private key: %s", err)
	}

	err = rsa.VerifyPSS(pubKey, crypto.SHA256, msgHash.Sum(nil), signatureRSA, nil)
	if err != nil {
		return fmt.Errorf("the provided RSA private key failed signature verification: %s", err)
	}
	return err
}

// verifyECDSA is broken out of Verify for testing purposes.
func verifyECDSA(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey, msgHash hash.Hash) error {
	r, s, err := ecdsa.Sign(rand.Reader, privKey, msgHash.Sum(nil))
	if err != nil {
		return fmt.Errorf("failed to sign using the provided ECDSA private key: %s", err)
	}

	verify := ecdsa.Verify(pubKey, msgHash.Sum(nil), r, s)
	if !verify {
		return errors.New("the provided ECDSA private key failed signature verification")
	}
	return err
}

// Verify ensures that the embedded PublicKey of the provided privateKey is
// actually a match for the private key. For an example of private keys
// embedding a mismatched public key, see:
// https://blog.hboeck.de/archives/888-How-I-tricked-Symantec-with-a-Fake-Private-Key.html.
func Verify(privateKey crypto.Signer) error {
	msgHash := sha256.New()
	_, err := msgHash.Write([]byte("verifiable"))
	if err != nil {
		return fmt.Errorf("failed to hash 'verifiable' message: %s", err)
	}

	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		return verifyRSA(k, &k.PublicKey, msgHash)

	case *ecdsa.PrivateKey:
		return verifyECDSA(k, &k.PublicKey, msgHash)

	default:
		// This should never happen.
		return errors.New("the provided private key could not be asserted to ECDSA or RSA")
	}
}

// Load decodes and parses a private key from the provided file path and returns
// the private key as crypto.Signer. path is expected to be a PEM formatted RSA
// or ECDSA private key in a PKCS #1, PKCS# 8, or SEC 1 container.
func Load(path string) (crypto.Signer, error) {
	keyBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read key file %q", path)
	}

	var keyDER *pem.Block
	for {
		keyDER, keyBytes = pem.Decode(keyBytes)
		if keyDER == nil || keyDER.Type != "EC PARAMETERS" {
			break
		}
	}
	if keyDER == nil {
		return nil, fmt.Errorf("no PEM formatted block found in %q", path)
	}

	// Attempt to parse the PEM block as a private key in a PKCS #8 container.
	signer, err := x509.ParsePKCS8PrivateKey(keyDER.Bytes)
	if err == nil {
		switch signer := signer.(type) {
		case *rsa.PrivateKey:
			return signer, nil

		case *ecdsa.PrivateKey:
			return signer, nil
		}
	}

	// Attempt to parse the PEM block as a private key in a PKCS #1 container.
	rsaSigner, err := x509.ParsePKCS1PrivateKey(keyDER.Bytes)
	if err == nil {
		return rsaSigner, nil
	}

	// Attempt to parse the PEM block as a private key in a SEC 1 container.
	ecdsaSigner, err := x509.ParseECPrivateKey(keyDER.Bytes)
	if err == nil {
		return ecdsaSigner, nil
	}
	return nil, fmt.Errorf("unable to parse %q as a private key", path)
}
