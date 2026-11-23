package main

import (
	"crypto"
	"crypto/elliptic"
	"errors"
	"fmt"
	"log"

	"github.com/miekg/pkcs11"

	"github.com/letsencrypt/boulder/pkcs11helpers"
)

var stringToCurve = map[string]elliptic.Curve{
	elliptic.P256().Params().Name: elliptic.P256(),
	elliptic.P384().Params().Name: elliptic.P384(),
	elliptic.P521().Params().Name: elliptic.P521(),
}

// curveToOIDDER maps the name of the curves to their DER encoded OIDs
var curveToOIDDER = map[string][]byte{
	elliptic.P256().Params().Name: {6, 8, 42, 134, 72, 206, 61, 3, 1, 7},
	elliptic.P384().Params().Name: {6, 5, 43, 129, 4, 0, 34},
	elliptic.P521().Params().Name: {6, 5, 43, 129, 4, 0, 35},
}

// ecKeyGen is a keyGenerator for ECDSA key pairs on the given curve.
type ecKeyGen struct {
	curve elliptic.Curve
}

// newECKeyGen returns an ecKeyGen for ECDSA key pairs on the curve specified by
// curveStr.
func newECKeyGen(curveStr string) (ecKeyGen, error) {
	curve, present := stringToCurve[curveStr]
	if !present {
		return ecKeyGen{}, fmt.Errorf("curve %q not supported", curveStr)
	}
	log.Printf("Generating ECDSA key with curve %s\n", curveStr)
	return ecKeyGen{curve: curve}, nil
}

func (g ecKeyGen) mechanism() uint {
	return pkcs11.CKM_EC_KEY_PAIR_GEN
}

// publicAttrs specifies the curve of the key.
func (g ecKeyGen) publicAttrs() []*pkcs11.Attribute {
	encodedCurve := curveToOIDDER[g.curve.Params().Name]
	log.Printf("\tEncoded curve parameters for %s: %X\n", g.curve.Params().Name, encodedCurve)
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, encodedCurve),
	}
}

// publicKey extracts the generated public key, specified by the provided object
// handle, and constructs an ecdsa.PublicKey. It also checks that the key is of
// the correct curve type.
func (g ecKeyGen) publicKey(session *pkcs11helpers.Session, object pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	pubKey, err := session.GetECDSAPublicKey(object)
	if err != nil {
		return nil, err
	}
	if pubKey.Curve != g.curve {
		return nil, errors.New("returned EC parameters doesn't match expected curve")
	}
	log.Printf("\tX: %X\n", pubKey.X.Bytes())
	log.Printf("\tY: %X\n", pubKey.Y.Bytes())
	return pubKey, nil
}
