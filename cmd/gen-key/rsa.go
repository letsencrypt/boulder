package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/big"

	"github.com/miekg/pkcs11"
)

func rsaArgs(label string, modLen, exp uint) ([]*pkcs11.Mechanism, []*pkcs11.Attribute, []*pkcs11.Attribute) {
	expSlice := make([]byte, 8)
	binary.BigEndian.PutUint64(expSlice, uint64(exp))
	log.Printf("\tEncoded public exponent (%d) as: %0X\n", exp, expSlice)
	return []*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil),
		},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, modLen),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, expSlice),
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

func rsaPub(ctx Ctx, session pkcs11.SessionHandle, object pkcs11.ObjectHandle, modLen, exp uint) (*rsa.PublicKey, error) {
	// Retrieve the public exponent and modulus for the generated public key
	attrs, err := ctx.GetAttributeValue(session, object, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve key attributes: %s", err)
	}

	// Attempt to build the public key from the retrieved attributes
	pubKey := &rsa.PublicKey{}
	gotMod, gotExp := false, false
	for _, a := range attrs {
		switch a.Type {
		case pkcs11.CKA_PUBLIC_EXPONENT:
			pubKey.E = int(big.NewInt(0).SetBytes(a.Value).Int64())
			// Check the provided public exponent was used
			if pubKey.E != int(exp) {
				return nil, errors.New("Returned CKA_PUBLIC_EXPONENT doesn't match expected exponent")
			}
			gotExp = true
			log.Printf("\tPublic exponent: %d\n", pubKey.E)
		case pkcs11.CKA_MODULUS:
			pubKey.N = big.NewInt(0).SetBytes(a.Value)
			// Check the right length modulus was generated on the device
			if pubKey.N.BitLen() != int(modLen) {
				return nil, errors.New("Returned CKA_MODULUS isn't of the expected bit length")
			}
			gotMod = true
			log.Printf("\tModulus: (%d bits) %X\n", pubKey.N.BitLen(), pubKey.N.Bytes())
		}
	}
	// Fail if we are missing either the public exponent or modulus
	if !gotExp || !gotMod {
		return nil, errors.New("Couldn't retrieve modulus or exponent")
	}
	return pubKey, nil
}

func rsaVerify(ctx Ctx, session pkcs11.SessionHandle, object pkcs11.ObjectHandle, pub *rsa.PublicKey) error {
	// Initialize a signing operation
	err := ctx.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, object)
	if err != nil {
		return fmt.Errorf("Failed to initialize signing operation: %s", err)
	}
	// PKCS#11 requires a hash identifier prefix to the message in order to determine which hash was used.
	// This prefix indicates SHA-256.
	input := []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}
	msg, err := getRandomBytes(ctx, session)
	if err != nil {
		return fmt.Errorf("Failed to retrieve random data: %s", err)
	}
	log.Printf("\tConstructed random number: %d (%X)\n", big.NewInt(0).SetBytes(msg), msg)
	hash := sha256.Sum256(msg)
	log.Printf("\tMessage SHA-256 hash: %X\n", hash)
	input = append(input, hash[:]...)
	log.Println("\tSigning message")
	signature, err := ctx.Sign(session, input)
	if err != nil {
		return fmt.Errorf("Failed to sign data: %s", err)
	}
	log.Printf("\tMessage signature: %X\n", signature)
	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], signature)
	if err != nil {
		return fmt.Errorf("Failed to verify signature: %s", err)
	}
	log.Println("\tSignature verified")
	return nil
}

func rsaGenerate(ctx Ctx, session pkcs11.SessionHandle, label string, modLen, pubExp uint) (*rsa.PublicKey, error) {
	log.Printf("Generating RSA key with %d bit modulus and public exponent %d\n", modLen, pubExp)
	m, pubTmpl, privTmpl := rsaArgs(label, modLen, pubExp)
	pub, priv, err := ctx.GenerateKeyPair(session, m, pubTmpl, privTmpl)
	if err != nil {
		return nil, err
	}
	log.Println("Key generated")
	log.Println("Extracting public key")
	pk, err := rsaPub(ctx, session, pub, modLen, pubExp)
	if err != nil {
		return nil, err
	}
	log.Println("Extracted public key")
	log.Println("Verifying public key")
	err = rsaVerify(ctx, session, priv, pk)
	if err != nil {
		return nil, err
	}
	return pk, nil
}
