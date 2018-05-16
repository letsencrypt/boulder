// gen-key is a tool for generating RSA or ECDSA keys on a HSM using PKCS#11.
// After generating the key pair it attempts to extract and construct the public
// key and verifies a test message that was signed using the generated private
// key. Any action it takes should be thoroughly logged and documented.
//
// When generating a key this tool follows the following steps:
//   1. Constructs templates for the private and public keys consisting
//      of the appropriate PKCS#11 attributes.
//   2. Executes a PKCS#11 GenerateKeyPair operation with the constructed
//      templates and either CKM_RSA_PKCS_KEY_PAIR_GEN or CKM_EC_KEY_PAIR_GEN.
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
	"flag"
	"io/ioutil"
	"log"
	"os"

	"github.com/letsencrypt/boulder/pkcs11helpers"
	"github.com/miekg/pkcs11"
)

type generateArgs struct {
	mechanism    []*pkcs11.Mechanism
	privateAttrs []*pkcs11.Attribute
	publicAttrs  []*pkcs11.Attribute
}

func getRandomBytes(ctx pkcs11helpers.PKCtx, session pkcs11.SessionHandle) ([]byte, error) {
	r, err := ctx.GenerateRandom(session, 4)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func main() {
	module := flag.String("module", "", "PKCS#11 module to use")
	keyType := flag.String("type", "", "Type of key to generate (RSA or ECDSA)")
	slot := flag.Uint("slot", 0, "Slot to generate key in")
	pin := flag.String("pin", "", "PIN for slot if not using PED to login")
	label := flag.String("label", "", "Key label")
	rsaModLen := flag.Uint("modulus-bits", 0, "Size of RSA modulus in bits. Only used if --type=RSA")
	rsaExp := flag.Uint("public-exponent", 65537, "Public RSA exponent. Only used if --type=RSA")
	ecdsaCurve := flag.String("curve", "", "Type of ECDSA curve to use (P-224, P-256, P-384, P-521). Only used if --type=ECDSA")
	outputPath := flag.String("output", "", "Path to store generated PEM public key")
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
	if *label == "" {
		log.Fatal("--label is required")
	}
	if *outputPath == "" {
		log.Fatal("--output is required")
	}

	ctx, session, err := pkcs11helpers.Initialize(*module, *slot, *pin)
	if err != nil {
		log.Fatalf("Failed to setup session and PKCS#11 context: %s", err)
	}
	log.Println("Opened PKCS#11 session")

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
		pubKey, err = ecGenerate(ctx, session, *label, *ecdsaCurve)
		if err != nil {
			log.Fatalf("Failed to generate ECDSA key pair: %s", err)
		}
	}

	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		log.Fatalf("Failed to marshal public key: %s", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	log.Printf("Public key PEM:\n%s\n", pemBytes)
	if err := ioutil.WriteFile(*outputPath, pemBytes, os.ModePerm); err != nil {
		log.Fatalf("Failed to write public key to %q: %s", *outputPath, err)
	}
	log.Printf("Public key written to %q\n", *outputPath)
}
