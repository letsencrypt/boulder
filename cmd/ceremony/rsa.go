package main

import (
	"crypto"
	"errors"
	"log"
	"math/big"

	"github.com/miekg/pkcs11"

	"github.com/letsencrypt/boulder/pkcs11helpers"
)

const (
	rsaExp = 65537
)

// rsaKeyGen is a keyGenerator for RSA key pairs with a modulus of modulusLen
// bits and the public exponent rsaExp.
type rsaKeyGen struct {
	modulusLen int
}

// newRSAKeyGen returns an rsaKeyGen for RSA key pairs with a modulus of
// modulusLen bits and the public exponent rsaExp.
func newRSAKeyGen(modulusLen int) rsaKeyGen {
	log.Printf("Generating RSA key with %d bit modulus and public exponent %d\n", modulusLen, rsaExp)
	return rsaKeyGen{modulusLen: modulusLen}
}

func (g rsaKeyGen) mechanism() uint {
	return pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN
}

// publicAttrs specifies the modulus length and public exponent of the key.
func (g rsaKeyGen) publicAttrs() []*pkcs11.Attribute {
	// Encode as unpadded big endian encoded byte slice
	expSlice := big.NewInt(rsaExp).Bytes()
	log.Printf("\tEncoded public exponent (%d) as: %0X\n", rsaExp, expSlice)
	return []*pkcs11.Attribute{
		// Set requested modulus length
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, g.modulusLen),
		// Set requested public exponent
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, expSlice),
	}
}

// publicKey extracts the generated public key, specified by the provided object
// handle, and constructs a rsa.PublicKey. It also checks that the key has the
// correct length modulus and that the public exponent is what was requested in
// the public key template.
func (g rsaKeyGen) publicKey(session *pkcs11helpers.Session, object pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	pubKey, err := session.GetRSAPublicKey(object)
	if err != nil {
		return nil, err
	}
	if pubKey.E != rsaExp {
		return nil, errors.New("returned CKA_PUBLIC_EXPONENT doesn't match expected exponent")
	}
	if pubKey.N.BitLen() != g.modulusLen {
		return nil, errors.New("returned CKA_MODULUS isn't of the expected bit length")
	}
	log.Printf("\tPublic exponent: %d\n", pubKey.E)
	log.Printf("\tModulus: (%d bits) %X\n", pubKey.N.BitLen(), pubKey.N.Bytes())
	return pubKey, nil
}
