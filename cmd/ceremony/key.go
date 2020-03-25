package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/letsencrypt/boulder/pkcs11helpers"
	"github.com/miekg/pkcs11"
)

type generateArgs struct {
	mechanism    []*pkcs11.Mechanism
	privateAttrs []*pkcs11.Attribute
	publicAttrs  []*pkcs11.Attribute
}

func getRandomBytes(ctx pkcs11helpers.PKCtx, session pkcs11.SessionHandle) ([]byte, error) {
	r, err := ctx.GenerateRandom(session, 4)
	if err != nil {
		return nil, err
	}
	return r, nil
}

const (
	rsaExp = 65537
)

// keyInfo is a struct used to pass around information about the public key
// associated with the generated private key. der contains the DER encoding
// of the SubjectPublicKeyInfo structure for the public key. id contains the
// HSM key pair object ID.
type keyInfo struct {
	key crypto.PublicKey
	der []byte
	id  []byte
}

func generateKey(ctx pkcs11helpers.PKCtx, session pkcs11.SessionHandle, label string, outputPath string, config keyGenConfig) (*keyInfo, error) {
	var pubKey crypto.PublicKey
	var keyID []byte
	var err error
	switch config.Type {
	case "rsa":
		pubKey, keyID, err = rsaGenerate(ctx, session, label, config.RSAModLength, rsaExp)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key pair: %s", err)
		}
	case "ecdsa":
		pubKey, keyID, err = ecGenerate(ctx, session, label, config.ECDSACurve)
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
	if err := ioutil.WriteFile(outputPath, pemBytes, 0644); err != nil {
		return nil, fmt.Errorf("Failed to write public key to %q: %s", outputPath, err)
	}
	log.Printf("Public key written to %q\n", outputPath)
	return &keyInfo{key: pubKey, der: der, id: keyID}, nil
}
