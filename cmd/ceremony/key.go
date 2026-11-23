package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"

	"github.com/miekg/pkcs11"

	"github.com/letsencrypt/boulder/pkcs11helpers"
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

// keyGenerator supplies the parts of generating a key pair on an HSM which are
// specific to one type of key. generateKeyPair supplies everything else,
// including the template attributes common to all types of key.
type keyGenerator interface {
	// mechanism returns the PKCS#11 mechanism (a CKM_* value) which generates
	// key pairs of this type.
	mechanism() uint
	// publicAttrs returns the attributes which specify the requested key, such
	// as its size, to add to the common public key template.
	publicAttrs() []*pkcs11.Attribute
	// publicKey retrieves the generated public key from the HSM, and checks
	// that it is the key that was requested.
	publicKey(session *pkcs11helpers.Session, object pkcs11.ObjectHandle) (crypto.PublicKey, error)
}

// generateKeyPair generates a key pair of the type specified by gen on the
// HSM, with the provided label and a random key ID. The private key is allowed
// to sign, and is marked sensitive and non-extractable. It returns the public
// part of the generated key pair and the key ID.
func generateKeyPair(session *pkcs11helpers.Session, label string, gen keyGenerator) (crypto.PublicKey, []byte, error) {
	keyID := make([]byte, 4)
	_, err := newRandReader(session).Read(keyID)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("\tKey ID: %x\n", keyID)

	publicAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		// Allow the key to verify signatures
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
	}
	publicAttrs = append(publicAttrs, gen.publicAttrs()...)
	privateAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		// Prevent attributes being retrieved
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		// Prevent the key being extracted from the device
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		// Allow the key to create signatures
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
	}
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(gen.mechanism(), nil)}

	pub, _, err := session.GenerateKeyPair(mechanism, publicAttrs, privateAttrs)
	if err != nil {
		return nil, nil, err
	}
	log.Println("Key generated")
	log.Println("Extracting public key")
	pk, err := gen.publicKey(session, pub)
	if err != nil {
		return nil, nil, err
	}
	log.Println("Extracted public key")
	return pk, keyID, nil
}

// keyInfo is a struct used to pass around information about the public key
// associated with the generated private key. id contains the HSM key pair
// object ID.
type keyInfo struct {
	key crypto.PublicKey
	id  []byte
}

func generateKey(session *pkcs11helpers.Session, label string, outputPath string, config keyGenConfig) (*keyInfo, error) {
	_, err := session.FindObject([]*pkcs11.Attribute{
		{Type: pkcs11.CKA_LABEL, Value: []byte(label)},
	})
	if err != pkcs11helpers.ErrNoObject {
		return nil, fmt.Errorf("expected no preexisting objects with label %q in slot for key storage. got error: %w", label, err)
	}

	var pubKey crypto.PublicKey
	var keyID []byte
	switch config.Type {
	case "rsa":
		pubKey, keyID, err = generateKeyPair(session, label, newRSAKeyGen(config.RSAModLength))
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
		}
	case "ecdsa":
		var gen ecKeyGen
		gen, err = newECKeyGen(config.ECDSACurve)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECDSA key pair: %w", err)
		}
		pubKey, keyID, err = generateKeyPair(session, label, gen)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECDSA key pair: %w", err)
		}
	}

	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	log.Printf("Public key PEM:\n%s\n", pemBytes)
	err = writeFile(outputPath, pemBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to write public key to %q: %w", outputPath, err)
	}
	log.Printf("Public key written to %q\n", outputPath)

	return &keyInfo{key: pubKey, id: keyID}, nil
}
