package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"log"
	"math/big"

	"github.com/miekg/pkcs11"
)

var stringToCurve = map[string]elliptic.Curve{
	"P224": elliptic.P224(),
	"P256": elliptic.P256(),
	"P384": elliptic.P384(),
	"P521": elliptic.P521(),
}

var curveToOID = map[elliptic.Curve]asn1.ObjectIdentifier{
	elliptic.P224(): asn1.ObjectIdentifier{1, 3, 132, 0, 33},
	elliptic.P256(): asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7},
	elliptic.P384(): asn1.ObjectIdentifier{1, 3, 132, 0, 34},
	elliptic.P521(): asn1.ObjectIdentifier{1, 3, 132, 0, 35},
}

func ecArgs(label string, curve elliptic.Curve, compatMode bool) ([]*pkcs11.Mechanism, []*pkcs11.Attribute, []*pkcs11.Attribute) {
	encodedCurve, err := asn1.Marshal(curveToOID[curve])
	if err != nil {
		panic(err)
	}
	log.Printf("\tEncoded curve parameters as: %X\n", encodedCurve)
	var paramType uint
	if compatMode {
		paramType = pkcs11.CKA_ECDSA_PARAMS
	} else {
		paramType = pkcs11.CKA_EC_PARAMS
	}
	return []*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil),
		}, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(paramType, encodedCurve),
		}, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			// Prevent attributes being retrieved
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			// Prevent the key being extracted from the device
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
			// Allow the key to sign data
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		}
}

var oidDERToCurve = map[string]elliptic.Curve{
	"06052B81040021":       elliptic.P224(),
	"06082A8648CE3D030107": elliptic.P256(),
	"06052B81040022":       elliptic.P384(),
	"06052B81040023":       elliptic.P521(),
}

func ecPub(ctx Ctx, session pkcs11.SessionHandle, object pkcs11.ObjectHandle, curve elliptic.Curve, compatMode bool) (*ecdsa.PublicKey, error) {
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
			if pubKey.Curve != curve {
				return nil, errors.New("Returned EC parameters doesn't match expected curve")
			}
			gotCurve = true
		case pkcs11.CKA_EC_POINT:
			x, y := elliptic.Unmarshal(curve, a.Value)
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
				x, y = elliptic.Unmarshal(curve, point.Bytes)
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
		return nil, errors.New("Couldn't retrieve EC point or EC parameters")
	}
	return pubKey, nil
}

var curveToHash = map[elliptic.Curve]crypto.Hash{
	elliptic.P224(): crypto.SHA256,
	elliptic.P256(): crypto.SHA256,
	elliptic.P384(): crypto.SHA384,
	elliptic.P521(): crypto.SHA512,
}

var hashToString = map[crypto.Hash]string{
	crypto.SHA256: "SHA-256",
	crypto.SHA384: "SHA-384",
	crypto.SHA512: "SHA-512",
}

func ecVerify(ctx Ctx, session pkcs11.SessionHandle, object pkcs11.ObjectHandle, pub *ecdsa.PublicKey) error {
	err := ctx.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, object)
	if err != nil {
		return fmt.Errorf("failed to initialize signing operation: %s", err)
	}
	msg, err := getRandomBytes(ctx, session)
	if err != nil {
		return fmt.Errorf("failed to retrieve random data: %s", err)
	}
	log.Printf("\tConstructed random number: %d (%X)\n", big.NewInt(0).SetBytes(msg), msg)
	hashFunc := curveToHash[pub.Curve].New()
	hashFunc.Write(msg)
	hash := hashFunc.Sum(nil)
	log.Printf("\tMessage %s hash: %X\n", hashToString[curveToHash[pub.Curve]], hash)
	signature, err := ctx.Sign(session, hash)
	if err != nil {
		return fmt.Errorf("failed to sign data: %s", err)
	}
	log.Printf("\tMessage signature: %X\n", signature)
	r := big.NewInt(0).SetBytes(signature[:len(signature)/2])
	s := big.NewInt(0).SetBytes(signature[len(signature)/2:])
	fmt.Println("post", r, s)
	if !ecdsa.Verify(pub, hash[:], r, s) {
		return errors.New("failed to verify ECDSA signature over test data")
	}
	log.Println("\tSignature verified")
	return nil
}

func ecdsaGenerate(ctx Ctx, session pkcs11.SessionHandle, label, curveStr string, compatMode bool) (*ecdsa.PublicKey, error) {
	curve, present := stringToCurve[curveStr]
	if !present {
		return nil, errors.New("curve not supported")
	}
	log.Printf("Generating ECDSA key with curve %s\n", curveStr)
	m, pubTmpl, privTmpl := ecArgs(label, curve, compatMode)
	pub, priv, err := ctx.GenerateKeyPair(session, m, pubTmpl, privTmpl)
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
