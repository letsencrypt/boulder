package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"

	"github.com/miekg/pkcs11"
)

func rsaArgs(label string, mod int) ([]*pkcs11.Mechanism, []*pkcs11.Attribute, []*pkcs11.Attribute) {
	return []*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil),
		},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, mod),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		}, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		}
}

func rsaPub(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, object pkcs11.ObjectHandle) crypto.PublicKey {
	attrs, err := ctx.GetAttributeValue(session, object, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
	})
	if err != nil {
		panic(err)
	}

	pubKey := rsa.PublicKey{}
	for _, a := range attrs {
		switch a.Type {
		case pkcs11.CKA_PUBLIC_EXPONENT:
			pubKey.E = int(big.NewInt(0).SetBytes(a.Value).Int64())
		case pkcs11.CKA_MODULUS:
			pubKey.N = big.NewInt(0).SetBytes(a.Value)
		}
	}
	return pubKey
}

var stringToCurveOID = map[string]asn1.ObjectIdentifier{
	"P256": asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7},
}

func ecArgs(label string, curve string) ([]*pkcs11.Mechanism, []*pkcs11.Attribute, []*pkcs11.Attribute) {
	encodedCurve, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}) // P256
	if err != nil {
		panic(err)
	}
	return []*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil),
		}, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, encodedCurve),
		}, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		}
}

func ecPub(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, object pkcs11.ObjectHandle, curve elliptic.Curve) crypto.PublicKey {
	return nil
}

func main() {
	ctx := pkcs11.New("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so")
	if ctx == nil {
		panic("failed to load module")
	}
	err := ctx.Initialize()
	if err != nil {
		panic(err)
	}

	fmt.Println(ctx.GetSlotList(true))

	slot := uint(0)
	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		panic(err)
	}

	pin := "1234"
	err = ctx.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		panic(err)
	}

	label := "testing"
	// mod := 2048
	curve := elliptic.P256()
	encodedCurve, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}) // P256
	if err != nil {
		panic(err)
	}

	m := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}
	pubTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, encodedCurve),
	}
	privTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
	}

	_, pub, err := ctx.GenerateKeyPair(session, m, pubTmpl, privTmpl)
	if err != nil {
		panic(err)
	}

	attrs, err := ctx.GetAttributeValue(session, pub, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		panic(err)
	}

	pubKey := ecdsa.PublicKey{Curve: curve}
	for i, a := range attrs {
		fmt.Printf("%d %x\n", i, a.Value)
		switch a.Type {
		case pkcs11.CKA_EC_POINT:
			x, y := elliptic.Unmarshal(curve, a.Value)
			if x == nil {
				// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html#_ftn1
				// PKCS#11 v2.20 specified that the CKA_EC_POINT was to be store in a DER-encoded
				// OCTET STRING.
				var point asn1.RawValue
				asn1.Unmarshal(a.Value, &point)
				if len(point.Bytes) > 0 {
					x, y = elliptic.Unmarshal(curve, point.Bytes)
				}
			}
			pubKey.X, pubKey.Y = x, y
		}
	}

	der, err := x509.MarshalPKIXPublicKey(&pubKey)
	if err != nil {
		panic(err)
	}

	err = pem.Encode(os.Stdout, &pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if err != nil {
		panic(err)
	}
}
