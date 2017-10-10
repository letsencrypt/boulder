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
	"P-224": elliptic.P224(),
	"P-256": elliptic.P256(),
	"P-384": elliptic.P384(),
	"P-521": elliptic.P521(),
}

var curveToOID = map[elliptic.Curve][]byte{
	elliptic.P224(): []byte{6, 5, 43, 129, 4, 0, 33},
	elliptic.P256(): []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7},
	elliptic.P384(): []byte{6, 5, 43, 129, 4, 0, 34},
	elliptic.P521(): []byte{6, 5, 43, 129, 4, 0, 35},
}

func ecArgs(label string, curve elliptic.Curve, compatMode bool) ([]*pkcs11.Mechanism, []*pkcs11.Attribute, []*pkcs11.Attribute) {
	encodedCurve := curveToOID[curve]
	log.Printf("\tEncoded curve parameters for %s: %X\n", curve.Params().Name, encodedCurve)
	var genMech, paramType uint
	if compatMode {
		genMech = pkcs11.CKM_ECDSA_KEY_PAIR_GEN
		paramType = pkcs11.CKA_ECDSA_PARAMS
	} else {
		genMech = pkcs11.CKM_EC_KEY_PAIR_GEN
		paramType = pkcs11.CKA_EC_PARAMS
	}
	return []*pkcs11.Mechanism{
			pkcs11.NewMechanism(genMech, nil),
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
	if !ecdsa.Verify(pub, hash[:], r, s) {
		return errors.New("failed to verify ECDSA signature over test data")
	}
	log.Println("\tSignature verified")
	return nil
}

func ecGenerate(ctx Ctx, session pkcs11.SessionHandle, label, curveStr string, compatMode bool) (*ecdsa.PublicKey, error) {
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
