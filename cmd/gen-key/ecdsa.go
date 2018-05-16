package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"log"
	"math/big"

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
// type of key should be generated. compatMode is used to determine which
// mechanism and attribute types should be used, for devices that implement
// a pre-2.11 version of the PKCS#11 specification compatMode should be true.
func ecArgs(label string, curve *elliptic.CurveParams, compatMode bool, keyID []byte) generateArgs {
	encodedCurve := curveToOIDDER[curve.Name]
	log.Printf("\tEncoded curve parameters for %s: %X\n", curve.Params().Name, encodedCurve)
	var genMech, paramType uint
	if compatMode {
		genMech = pkcs11.CKM_ECDSA_KEY_PAIR_GEN
		paramType = pkcs11.CKA_ECDSA_PARAMS
	} else {
		genMech = pkcs11.CKM_EC_KEY_PAIR_GEN
		paramType = pkcs11.CKA_EC_PARAMS
	}
	return generateArgs{
		mechanism: []*pkcs11.Mechanism{
			pkcs11.NewMechanism(genMech, nil),
		},
		publicAttrs: []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(paramType, encodedCurve),
		},
		privateAttrs: []*pkcs11.Attribute{
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
// the correct curve type. For devices that implement a pre-2.11 version of the
// PKCS#11 specification compatMode should be true.
func ecPub(ctx PKCtx, session pkcs11.SessionHandle, object pkcs11.ObjectHandle, expectedCurve *elliptic.CurveParams, compatMode bool) (*ecdsa.PublicKey, error) {
	var paramType uint
	if compatMode {
		paramType = pkcs11.CKA_ECDSA_PARAMS
	} else {
		paramType = pkcs11.CKA_EC_PARAMS
	}
	// Retrieve the curve and public point for the generated public key
	attrs, err := ctx.GetAttributeValue(session, object, []*pkcs11.Attribute{
		pkcs11.NewAttribute(paramType, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve key attributes: %s", err)
	}

	pubKey := &ecdsa.PublicKey{}
	gotCurve, gotPoint := false, false
	for _, a := range attrs {
		switch a.Type {
		case paramType:
			rCurve, present := oidDERToCurve[fmt.Sprintf("%X", a.Value)]
			if !present {
				return nil, errors.New("Unknown curve OID value returned")
			}
			pubKey.Curve = rCurve
			if pubKey.Curve != expectedCurve {
				return nil, errors.New("Returned EC parameters doesn't match expected curve")
			}
			gotCurve = true
		case pkcs11.CKA_EC_POINT:
			x, y := elliptic.Unmarshal(expectedCurve, a.Value)
			if x == nil {
				// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html#_ftn1
				// PKCS#11 v2.20 specified that the CKA_EC_POINT was to be stored in a DER-encoded
				// OCTET STRING.
				var point asn1.RawValue
				_, err = asn1.Unmarshal(a.Value, &point)
				if err != nil {
					return nil, fmt.Errorf("Failed to unmarshal returned CKA_EC_POINT: %s", err)
				}
				if len(point.Bytes) == 0 {
					return nil, errors.New("Invalid CKA_EC_POINT value returned, OCTET string is empty")
				}
				x, y = elliptic.Unmarshal(expectedCurve, point.Bytes)
				if x == nil {
					fmt.Println(point.Bytes)
					return nil, errors.New("Invalid CKA_EC_POINT value returned, point is malformed")
				}
			}
			pubKey.X, pubKey.Y = x, y
			gotPoint = true
			log.Printf("\tX: %X\n", pubKey.X.Bytes())
			log.Printf("\tY: %X\n", pubKey.Y.Bytes())
		}
	}
	if !gotPoint || !gotCurve {
		return nil, errors.New("Couldn't retrieve EC point and EC parameters")
	}
	return pubKey, nil
}

// ecVerify verifies that the extracted public key corresponds with the generated
// private key on the device, specified by the provided object handle, by signing
// a nonce generated on the device and verifying the returned signature using the
// public key.
func ecVerify(ctx PKCtx, session pkcs11.SessionHandle, object pkcs11.ObjectHandle, pub *ecdsa.PublicKey) error {
	err := ctx.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, object)
	if err != nil {
		return fmt.Errorf("failed to initialize signing operation: %s", err)
	}
	nonce, err := getRandomBytes(ctx, session)
	if err != nil {
		return fmt.Errorf("failed to construct nonce: %s", err)
	}
	log.Printf("\tConstructed nonce: %d (%X)\n", big.NewInt(0).SetBytes(nonce), nonce)
	hashFunc := curveToHash[pub.Curve.Params()].New()
	hashFunc.Write(nonce)
	hash := hashFunc.Sum(nil)
	log.Printf("\tMessage %s hash: %X\n", hashToString[curveToHash[pub.Curve.Params()]], hash)
	signature, err := ctx.Sign(session, hash)
	if err != nil {
		return fmt.Errorf("failed to sign data: %s", err)
	}
	log.Printf("\tMessage signature: %X\n", signature)
	r := big.NewInt(0).SetBytes(signature[:len(signature)/2])
	s := big.NewInt(0).SetBytes(signature[len(signature)/2:])
	if !ecdsa.Verify(pub, hash[:], r, s) {
		return errors.New("failed to verify ECDSA signature over test data")
	}
	log.Println("\tSignature verified")
	return nil
}

// ecGenerate is used to generate and verify a ECDSA key pair of the type
// specified by curveStr and with the provided label. For devices that implement
// a pre-2.11 version of the PKCS#11 specification compatMode should be true.
// It returns the public part of the generated key pair as a ecdsa.PublicKey.
func ecGenerate(ctx PKCtx, session pkcs11.SessionHandle, label, curveStr string, compatMode bool) (*ecdsa.PublicKey, error) {
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
	args := ecArgs(label, curve, compatMode, keyID)
	pub, priv, err := ctx.GenerateKeyPair(session, args.mechanism, args.publicAttrs, args.privateAttrs)
	if err != nil {
		return nil, err
	}
	log.Println("Key generated")
	log.Println("Extracting public key")
	pk, err := ecPub(ctx, session, pub, curve, compatMode)
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
