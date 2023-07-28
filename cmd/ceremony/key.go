package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/letsencrypt/boulder/pkcs11helpers"
	"github.com/miekg/pkcs11"
)

type hsmRandReader struct {
	*pkcs11helpers.Session
}

func newRandReader(session *pkcs11helpers.Session) *hsmRandReader {
	return &hsmRandReader{session}
}

func (hrr hsmRandReader) Read(p []byte) (n int, err error) {
	r, err := hrr.Module.GenerateRandom(hrr.Session.Session, len(p))
	if err != nil {
		return 0, err
	}
	copy(p[:], r)
	return len(r), nil
}

type generateArgs struct {
	mechanism    []*pkcs11.Mechanism
	privateAttrs []*pkcs11.Attribute
	publicAttrs  []*pkcs11.Attribute
}

// keyInfo is a struct used to pass around information about the public key
// associated with the generated private key. der contains the DER encoding
// of the SubjectPublicKeyInfo structure for the public key. id contains the
// HSM key pair object ID.
type keyInfo struct {
	key crypto.PublicKey
	der []byte
	id  []byte
}

func generateKey(session *pkcs11helpers.Session, label string, outputPath string, config keyGenConfig) (*keyInfo, error) {
	_, err := session.FindObject([]*pkcs11.Attribute{
		{Type: pkcs11.CKA_LABEL, Value: []byte(label)},
	})
	if err != pkcs11helpers.ErrNoObject {
		return nil, fmt.Errorf("expected no preexisting objects with label %q in slot for key storage. got error: %s", label, err)
	}

	var pubKey crypto.PublicKey
	var keyID []byte
	switch config.Type {
	case "rsa":
		pubKey, keyID, err = rsaGenerate(session, label, config.RSAModLength)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key pair: %s", err)
		}
	case "ecdsa":
		pubKey, keyID, err = ecGenerate(session, label, config.ECDSACurve)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECDSA key pair: %s", err)
		}
	}

	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal public key: %s", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	log.Printf("Public key PEM:\n%s\n", pemBytes)
	err = writeFile(outputPath, pemBytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to write public key to %q: %s", outputPath, err)
	}
	log.Printf("Public key written to %q\n", outputPath)

	return &keyInfo{key: pubKey, der: der, id: keyID}, nil
}

// loadKey loads a PEM key specified by filename or returns an error.
// The public key is checked by the GoodKey package.
func loadKey(filename string) (crypto.PublicKey, []byte, error) {
	keyPEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("Loaded public key from %s\n", filename)
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("No data in cert PEM file %s", filename)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	goodkeyErr := kp.GoodKey(context.Background(), key)
	if goodkeyErr != nil {
		return nil, nil, goodkeyErr
	}

	return key, block.Bytes, nil
}
