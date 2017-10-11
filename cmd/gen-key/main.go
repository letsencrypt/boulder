// gen-key is a tool for generating RSA or ECDSA keys on a HSM using PKCS#11.
// After generating the key it attempts to extract and construct the public
// key and verifies a test message that was signed using the generated private
// key. Any action it takes should be thoroughly logged and documented.
//
// When generating a key this tool follows the following steps:
//   1. Constructs templates for the private and public keys consisting
//      of the appropriate PKCS#11 attributes.
//   2. Executes a PKCS#11 GenerateKeyPair operation with the constructed
//      templates and either CKM_RSA_PKCS_KEY_PAIR_GEN or CKM_EC_KEY_PAIR_GEN
//      (or CKM_ECDSA_KEY_PAIR_GEN for pre-PKCS#11 v2.11 devices).
//   3. Extracts the public key components from the returned public key object
//      handle and construct a Golang public key object from them.
//   4. Generates 4 bytes of random data from the HSM using a PKCS#11 GenerateRandom
//      operation.
//   5. Signs the random data with the private key object handle using a PKCS#11
//      SignInit/Sign operation.
//   6. Verifies the returned signature of the random data with the constructed
//      public key.
//   7. Marshals the public key into a PEM public key object and print it to STDOUT.
//
package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/miekg/pkcs11"
)

type Ctx interface {
	GenerateKeyPair(pkcs11.SessionHandle, []*pkcs11.Mechanism, []*pkcs11.Attribute, []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error)
	GetAttributeValue(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error)
	SignInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error
	Sign(pkcs11.SessionHandle, []byte) ([]byte, error)
	GenerateRandom(pkcs11.SessionHandle, int) ([]byte, error)
}

func getRandomBytes(ctx Ctx, session pkcs11.SessionHandle) ([]byte, error) {
	r, err := ctx.GenerateRandom(session, 4)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func initialize(module string, slot uint, pin string) (Ctx, pkcs11.SessionHandle, error) {
	ctx := pkcs11.New(module)
	if ctx == nil {
		return nil, 0, errors.New("failed to load module")
	}
	err := ctx.Initialize()
	if err != nil {
		return nil, 0, fmt.Errorf("couldn't initialize context: %s", err)
	}

	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, 0, fmt.Errorf("couldn't open session: %s", err)
	}

	err = ctx.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		return nil, 0, fmt.Errorf("couldn't login: %s", err)
	}

	return ctx, session, nil
}

func main() {
	module := flag.String("module", "", "PKCS#11 module to use")
	keyType := flag.String("type", "", "Type of key to generate (RSA or ECDSA)")
	slot := flag.Uint("slot", 0, "Slot to generate key in")
	pin := flag.String("pin", "", "PIN for slot")
	label := flag.String("label", "", "Key label")
	rsaModLen := flag.Uint("modulus-bits", 0, "Size of RSA modulus in bits. Only used if --type=RSA")
	rsaExp := flag.Uint("public-exponent", 65537, "Public RSA exponent. Only used if --type=RSA")
	ecdsaCurve := flag.String("curve", "", "Type of ECDSA curve to use (P-224, P-256, P-384, P-521). Only used if --type=ECDSA")
	compatMode := flag.Bool("compat-mode", false, "Use pre PKCS#11 v2.11 style ECDSA parameters. Only used if --type=ECDSA")
	flag.Parse()

	if *module == "" {
		log.Fatal("--module is required")
	}
	if *keyType == "" {
		log.Fatal("--type is required")
	}
	if *keyType != "RSA" && *keyType != "ECDSA" {
		log.Fatal("--type may only be RSA or ECDSA")
	}
	if *pin == "" {
		log.Fatal("--pin is required")
	}
	if *label == "" {
		log.Fatal("--label is required")
	}

	ctx, session, err := initialize(*module, *slot, *pin)
	if err != nil {
		log.Fatalf("Failed to setup and session PKCS#11 context: %s", err)
	}

	var pubKey interface{}
	switch *keyType {
	case "RSA":
		if *rsaModLen == 0 {
			log.Fatal("--modulus-bits is required")
		}
		pubKey, err = rsaGenerate(ctx, session, *label, *rsaModLen, *rsaExp)
		if err != nil {
			log.Fatalf("Failed to generate RSA key pair: %s", err)
		}
	case "ECDSA":
		if *ecdsaCurve == "" {
			log.Fatal("--ecdsaCurve is required")
		}
		pubKey, err = ecGenerate(ctx, session, *label, *ecdsaCurve, *compatMode)
		if err != nil {
			log.Fatalf("Failed to generate ECDSA key pair: %s", err)
		}
	}

	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		log.Fatalf("Failed to marshal public key: %s", err)
	}

	err = pem.Encode(os.Stdout, &pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if err != nil {
		log.Fatalf("Failed to encode public key as PEM object: %s", err)
	}
}
