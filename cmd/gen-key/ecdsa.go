package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"math/big"

	"github.com/letsencrypt/boulder/pkcs11helpers"
	"github.com/miekg/pkcs11"
)

var stringToCurve = map[string]*elliptic.CurveParams{
	elliptic.P224().Params().Name: elliptic.P224().Params(),
	elliptic.P256().Params().Name: elliptic.P256().Params(),
	elliptic.P384().Params().Name: elliptic.P384().Params(),
	elliptic.P521().Params().Name: elliptic.P521().Params(),
}

// curveToOIDDER maps the name of the curves to their DER encoded OIDs
var curveToOIDDER = map[string][]byte{
	elliptic.P224().Params().Name: []byte{6, 5, 43, 129, 4, 0, 33},
	elliptic.P256().Params().Name: []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7},
	elliptic.P384().Params().Name: []byte{6, 5, 43, 129, 4, 0, 34},
	elliptic.P521().Params().Name: []byte{6, 5, 43, 129, 4, 0, 35},
}

// oidDERToCurve maps the hex of the DER encoding of the various curve OIDs to
// the relevant curve parameters
var oidDERToCurve = map[string]*elliptic.CurveParams{
	"06052B81040021":       elliptic.P224().Params(),
	"06082A8648CE3D030107": elliptic.P256().Params(),
	"06052B81040022":       elliptic.P384().Params(),
	"06052B81040023":       elliptic.P521().Params(),
}

var curveToHash = map[*elliptic.CurveParams]crypto.Hash{
	elliptic.P224().Params(): crypto.SHA256,
	elliptic.P256().Params(): crypto.SHA256,
	elliptic.P384().Params(): crypto.SHA384,
	elliptic.P521().Params(): crypto.SHA512,
}

var hashToString = map[crypto.Hash]string{
	crypto.SHA256: "SHA-256",
	crypto.SHA384: "SHA-384",
	crypto.SHA512: "SHA-512",
}

// ecArgs constructs the private and public key template attributes sent to the
// device and specifies which mechanism should be used. curve determines which
// type of key should be generated.
func ecArgs(label string, curve *elliptic.CurveParams, keyID []byte) generateArgs {
	encodedCurve := curveToOIDDER[curve.Name]
	log.Printf("\tEncoded curve parameters for %s: %X\n", curve.Params().Name, encodedCurve)
	return generateArgs{
		mechanism: []*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil),
		},
		publicAttrs: []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, encodedCurve),
		},
		privateAttrs: []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			// Prevent attributes being retrieved
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			// Prevent the key being extracted from the device
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
			// Allow the key to sign data
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		},
	}
}

// ecPub extracts the generated public key, specified by the provided object
// handle, and constructs an ecdsa.PublicKey. It also checks that the key is of
// the correct curve type.
func ecPub(ctx pkcs11helpers.PKCtx, session pkcs11.SessionHandle, object pkcs11.ObjectHandle, expectedCurve *elliptic.CurveParams) (*ecdsa.PublicKey, error) {
	pubKey, err := pkcs11helpers.GetECDSAPublicKey(ctx, session, object)
	if err != nil {
		return nil, err
	}
	if pubKey.Curve != expectedCurve {
		return nil, errors.New("Returned EC parameters doesn't match expected curve")
	}
	log.Printf("\tX: %X\n", pubKey.X.Bytes())
	log.Printf("\tY: %X\n", pubKey.Y.Bytes())
	return pubKey, nil
}

// ecVerify verifies that the extracted public key corresponds with the generated
// private key on the device, specified by the provided object handle, by signing
// a nonce generated on the device and verifying the returned signature using the
// public key.
func ecVerify(ctx pkcs11helpers.PKCtx, session pkcs11.SessionHandle, object pkcs11.ObjectHandle, pub *ecdsa.PublicKey) error {
	nonce, err := getRandomBytes(ctx, session)
	if err != nil {
		return fmt.Errorf("failed to construct nonce: %s", err)
	}
	log.Printf("\tConstructed nonce: %d (%X)\n", big.NewInt(0).SetBytes(nonce), nonce)
	hashFunc := curveToHash[pub.Curve.Params()].New()
	hashFunc.Write(nonce)
	digest := hashFunc.Sum(nil)
	log.Printf("\tMessage %s hash: %X\n", hashToString[curveToHash[pub.Curve.Params()]], digest)
	signature, err := pkcs11helpers.Sign(ctx, session, object, pkcs11helpers.ECDSAKey, digest, curveToHash[pub.Curve.Params()])
	if err != nil {
		return err
	}
	log.Printf("\tMessage signature: %X\n", signature)
	r := big.NewInt(0).SetBytes(signature[:len(signature)/2])
	s := big.NewInt(0).SetBytes(signature[len(signature)/2:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return errors.New("failed to verify ECDSA signature over test data")
	}
	log.Println("\tSignature verified")
	return nil
}

// ecGenerate is used to generate and verify a ECDSA key pair of the type
// specified by curveStr and with the provided label. It returns the public
// part of the generated key pair as a ecdsa.PublicKey.
func ecGenerate(ctx pkcs11helpers.PKCtx, session pkcs11.SessionHandle, label, curveStr string) (*ecdsa.PublicKey, error) {
	curve, present := stringToCurve[curveStr]
	if !present {
		return nil, fmt.Errorf("curve %q not supported", curveStr)
	}
	keyID := make([]byte, 4)
	_, err := rand.Read(keyID)
	if err != nil {
		return nil, err
	}
	log.Printf("Generating ECDSA key with curve %s and ID %x\n", curveStr, keyID)
	args := ecArgs(label, curve, keyID)
	pub, priv, err := ctx.GenerateKeyPair(session, args.mechanism, args.publicAttrs, args.privateAttrs)
	if err != nil {
		return nil, err
	}
	log.Println("Key generated")
	log.Println("Extracting public key")
	pk, err := ecPub(ctx, session, pub, curve)
	if err != nil {
		return nil, err
	}
	log.Println("Extracted public key")
	log.Println("Verifying public key")
	err = ecVerify(ctx, session, priv, pk)
	if err != nil {
		return nil, err
	}
	log.Println("Key verified")
	return pk, nil
}
