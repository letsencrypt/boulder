package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"math/big"

	"github.com/letsencrypt/boulder/pkcs11helpers"
	"github.com/miekg/pkcs11"
)

// rsaArgs constructs the private and public key template attributes sent to the
// device and specifies which mechanism should be used. modulusLen specifies the
// length of the modulus to be generated on the device in bits and exponent
// specifies the public exponent that should be used.
func rsaArgs(label string, modulusLen, exponent uint, keyID []byte) generateArgs {
	// Encode as unpadded big endian encoded byte slice
	expSlice := big.NewInt(int64(exponent)).Bytes()
	log.Printf("\tEncoded public exponent (%d) as: %0X\n", exponent, expSlice)
	return generateArgs{
		mechanism: []*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil),
		},
		publicAttrs: []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			// Allow the key to verify signatures
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			// Set requested modulus length
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, modulusLen),
			// Set requested public exponent
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, expSlice),
		},
		privateAttrs: []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			// Prevent attributes being retrieved
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			// Prevent the key being extracted from the device
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
			// Allow the key to create signatures
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		},
	}
}

// rsaPub extracts the generated public key, specified by the provided object
// handle, and constructs a rsa.PublicKey. It also checks that the key has the
// correct length modulus and that the public exponent is what was requested in
// the public key template.
func rsaPub(ctx pkcs11helpers.PKCtx, session pkcs11.SessionHandle, object pkcs11.ObjectHandle, modulusLen, exponent uint) (*rsa.PublicKey, error) {
	pubKey, err := pkcs11helpers.GetRSAPublicKey(ctx, session, object)
	if err != nil {
		return nil, err
	}
	if pubKey.E != int(exponent) {
		return nil, errors.New("returned CKA_PUBLIC_EXPONENT doesn't match expected exponent")
	}
	if pubKey.N.BitLen() != int(modulusLen) {
		return nil, errors.New("returned CKA_MODULUS isn't of the expected bit length")
	}
	log.Printf("\tPublic exponent: %d\n", pubKey.E)
	log.Printf("\tModulus: (%d bits) %X\n", pubKey.N.BitLen(), pubKey.N.Bytes())
	return pubKey, nil
}

// rsaVerify verifies that the extracted public key corresponds with the generated
// private key on the device, specified by the provided object handle, by signing
// a nonce generated on the device and verifying the returned signature using the
// public key.
func rsaVerify(ctx pkcs11helpers.PKCtx, session pkcs11.SessionHandle, object pkcs11.ObjectHandle, pub *rsa.PublicKey) error {
	nonce := make([]byte, 4)
	_, err := newRandReader(ctx, session).Read(nonce)
	if err != nil {
		return fmt.Errorf("Failed to retrieve nonce: %s", err)
	}
	log.Printf("\tConstructed nonce: %d (%X)\n", big.NewInt(0).SetBytes(nonce), nonce)
	digest := sha256.Sum256(nonce)
	log.Printf("\tMessage SHA-256 hash: %X\n", digest)
	signature, err := pkcs11helpers.Sign(ctx, session, object, pkcs11helpers.RSAKey, digest[:], crypto.SHA256)
	if err != nil {
		return fmt.Errorf("Failed to sign data: %s", err)
	}
	log.Printf("\tMessage signature: %X\n", signature)
	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature)
	if err != nil {
		return fmt.Errorf("Failed to verify signature: %s", err)
	}
	log.Println("\tSignature verified")
	return nil
}

// rsaGenerate is used to generate and verify a RSA key pair of the size
// specified by modulusLen and with the exponent specified by pubExponent.
// It returns the public part of the generated key pair as a rsa.PublicKey
// and the random key ID that the HSM uses to identify the key pair.
func rsaGenerate(ctx pkcs11helpers.PKCtx, session pkcs11.SessionHandle, label string, modulusLen, pubExponent uint) (*rsa.PublicKey, []byte, error) {
	keyID := make([]byte, 4)
	_, err := newRandReader(ctx, session).Read(keyID)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("Generating RSA key with %d bit modulus and public exponent %d and ID %x\n", modulusLen, pubExponent, keyID)
	args := rsaArgs(label, modulusLen, pubExponent, keyID)
	pub, priv, err := ctx.GenerateKeyPair(session, args.mechanism, args.publicAttrs, args.privateAttrs)
	if err != nil {
		return nil, nil, err
	}
	log.Println("Key generated")
	log.Println("Extracting public key")
	pk, err := rsaPub(ctx, session, pub, modulusLen, pubExponent)
	if err != nil {
		return nil, nil, err
	}
	log.Println("Extracted public key")
	log.Println("Verifying public key")
	err = rsaVerify(ctx, session, priv, pk)
	if err != nil {
		return nil, nil, err
	}
	return pk, keyID, nil
}
