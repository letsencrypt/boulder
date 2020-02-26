package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
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

// findObject looks up a PKCS#11 object handle based on the provided template.
// In the case where zero or more than one objects are found to match the
// template an error is returned.
func findObject(ctx pkcs11helpers.PKCtx, session pkcs11.SessionHandle, tmpl []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	if err := ctx.FindObjectsInit(session, tmpl); err != nil {
		return 0, err
	}
	handles, more, err := ctx.FindObjects(session, 1)
	if err != nil {
		return 0, err
	}
	if len(handles) == 0 {
		return 0, errors.New("no objects found matching provided template")
	}
	if more {
		return 0, errors.New("more than one object matches provided template")
	}
	if err := ctx.FindObjectsFinal(session); err != nil {
		return 0, err
	}
	return handles[0], nil
}

// getKey constructs a x509Signer for the private key object associated with the
// given label and ID. Unlike letsencrypt/pkcs11key this method doesn't rely on
// having the actual public key object in order to retrieve the private key
// handle. This is because we already have the key pair object ID, and as such
// do not need to query the HSM to retrieve it.
func getKey(ctx pkcs11helpers.PKCtx, session pkcs11.SessionHandle, label string, id []byte) (crypto.Signer, error) {
	// Retrieve the private key handle that will later be used for the certificate
	// signing operation
	privateHandle, err := findObject(ctx, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve private key handle: %s", err)
	}
	attrs, err := ctx.GetAttributeValue(session, privateHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil)},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve key type: %s", err)
	}
	if len(attrs) == 0 {
		return nil, errors.New("failed to retrieve key attributes")
	}

	// Retrieve the public key handle with the same CKA_ID as the private key
	// and construct a {rsa,ecdsa}.PublicKey for use in x509.CreateCertificate
	pubHandle, err := findObject(ctx, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, attrs[0].Value),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve public key handle: %s", err)
	}
	var pub crypto.PublicKey
	var keyType pkcs11helpers.KeyType
	switch {
	// 0x00000000, CKK_RSA
	case bytes.Compare(attrs[0].Value, []byte{0, 0, 0, 0, 0, 0, 0, 0}) == 0:
		keyType = pkcs11helpers.RSAKey
		pub, err = pkcs11helpers.GetRSAPublicKey(ctx, session, pubHandle)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve public key: %s", err)
		}
	// 0x00000003, CKK_ECDSA
	case bytes.Compare(attrs[0].Value, []byte{3, 0, 0, 0, 0, 0, 0, 0}) == 0:
		keyType = pkcs11helpers.ECDSAKey
		pub, err = pkcs11helpers.GetECDSAPublicKey(ctx, session, pubHandle)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve public key: %s", err)
		}
	default:
		return nil, errors.New("unsupported key type")
	}

	return &x509Signer{
		ctx:          ctx,
		session:      session,
		objectHandle: privateHandle,
		keyType:      keyType,
		pub:          pub,
	}, nil
}
