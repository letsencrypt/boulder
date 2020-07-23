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

type hsmRandReader struct {
	ctx     pkcs11helpers.PKCtx
	session pkcs11.SessionHandle
}

func newRandReader(ctx pkcs11helpers.PKCtx, session pkcs11.SessionHandle) *hsmRandReader {
	return &hsmRandReader{
		ctx:     ctx,
		session: session,
	}
}

func (hrr hsmRandReader) Read(p []byte) (n int, err error) {
	r, err := hrr.ctx.GenerateRandom(hrr.session, len(p))
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
	_, err := pkcs11helpers.FindObject(ctx, session, []*pkcs11.Attribute{})
	if err != pkcs11helpers.ErrNoObject {
		return nil, fmt.Errorf("expected no objects in slot for key storage. got error: %s", err)
	}

	var pubKey crypto.PublicKey
	var keyID []byte
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
