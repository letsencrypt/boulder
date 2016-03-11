package wfe

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"testing"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"
)

func TestRejectsNone(t *testing.T) {
	wfe, _ := setupWFE(t)
	_, _, _, prob := wfe.verifyPOST(newRequestEvent(), makePostRequest(`
		{
			"header": {
				"alg": "none",
				"jwk": {
					"kty": "RSA",
					"n": "vrjT",
					"e": "AQAB"
				}
			},
			"payload": "aGkK",
			"signature": ""
		}
	`), true, "foo")
	if prob == nil {
		t.Fatalf("verifyPOST did not reject JWS with alg: 'none'")
	}
	if prob.Detail != "algorithm 'none' in JWS header not acceptable" {
		t.Fatalf("verifyPOST rejected JWS with alg: 'none', but for wrong reason: %#v", prob)
	}
}

func TestRejectsHS256(t *testing.T) {
	wfe, _ := setupWFE(t)
	_, _, _, prob := wfe.verifyPOST(newRequestEvent(), makePostRequest(`
		{
			"header": {
				"alg": "HS256",
				"jwk": {
					"kty": "RSA",
					"n": "vrjT",
					"e": "AQAB"
				}
			},
			"payload": "aGkK",
			"signature": ""
		}
	`), true, "foo")
	if prob == nil {
		t.Fatalf("verifyPOST did not reject JWS with alg: 'HS256'")
	}
	expected := "algorithm 'HS256' in JWS header not acceptable"
	if prob.Detail != expected {
		t.Fatalf("verifyPOST rejected JWS with alg: 'none', but for wrong reason: got '%s', wanted %s", prob, expected)
	}
}

// parsePEMPrivateKey takes the path to PEM encoded private key in disk, decodes it and
// returns a Go instance of the key.
func parsePEMPrivateKey(path string) (crypto.PrivateKey, error) {
	accountKeyPEM, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal("failed to read account key:", err)
	}

	block, _ := pem.Decode(accountKeyPEM)
	if block == nil {
		log.Fatal("bad account key data, not PEM encoded:", err)
	}

	if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	return x509.ParseECPrivateKey(block.Bytes)
}

func TestCheckAlgorithm(t *testing.T) {
	key, err := parsePEMPrivateKey("./testdata/rsa-2048.pem")
	if err != nil {
		t.Fatalf("expected error to be nil, got %q", err)
	}

	publicKey := key.(*rsa.PrivateKey).Public()
	testCases := []struct {
		key          jose.JsonWebKey
		jws          jose.JsonWebSignature
		expectedErr  string
		expectedStat string
	}{
		{
			jose.JsonWebKey{
				Algorithm: "HS256",
			},
			jose.JsonWebSignature{},
			"POST JWS not signed",
			jwsNotSigned,
		},
		{
			jose.JsonWebKey{
				Key: publicKey,
			},
			jose.JsonWebSignature{
				Signatures: []jose.Signature{
					{
						Header: jose.JoseHeader{
							Algorithm: "HS256",
						},
					},
				},
			},
			"algorithm 'HS256' in JWS header not acceptable",
			invalidJWSAlgorithm,
		},
		{
			jose.JsonWebKey{
				Algorithm: "HS256",
				Key:       publicKey,
			},
			jose.JsonWebSignature{
				Signatures: []jose.Signature{
					{
						Header: jose.JoseHeader{
							Algorithm: "HS256",
						},
					},
				},
			},
			"algorithm 'HS256' in JWS header not acceptable",
			invalidJWSAlgorithm,
		},
		{
			jose.JsonWebKey{
				Algorithm: "HS256",
				Key:       publicKey,
			},
			jose.JsonWebSignature{
				Signatures: []jose.Signature{
					{
						Header: jose.JoseHeader{
							Algorithm: "RS256",
						},
					},
				},
			},
			"algorithm 'HS256' on JWK is unacceptable",
			invalidAlgorithmOnKey,
		},
	}
	for i, tc := range testCases {
		stat, err := checkAlgorithm(&tc.key, &tc.jws)
		if tc.expectedErr != "" && err.Error() != tc.expectedErr {
			t.Errorf("TestCheckAlgorithm %d: Expected '%s', got '%s'", i, tc.expectedErr, err)
		}
		if tc.expectedStat != "" && stat != tc.expectedStat {
			t.Errorf("TestCheckAlgorithm %d: Expected stat '%s', got '%s'", i, tc.expectedStat, stat)
		}
	}
}

func TestCheckAlgorithmSuccess(t *testing.T) {
	tests := []struct {
		keyType      string
		jwkAlgorithm string
		bitSize      int
		err          error
	}{
		{"rsa", "RS256", 2048, nil},
		{"rsa", "RS384", 3072, nil},
		{"rsa", "RS512", 4096, nil},
		{"ecdsa", "ES256", 256, nil},
		{"ecdsa", "ES384", 384, nil},
		{"ecdsa", "ES512", 521, nil},
	}

	for _, tt := range tests {
		var publicKey crypto.PublicKey
		var err error

		switch tt.keyType {
		case "rsa":
			key, err := parsePEMPrivateKey(fmt.Sprintf("./testdata/rsa-%d.pem", tt.bitSize))
			if err != nil {
				t.Errorf("%s key: Expected nil error, got %q", tt.jwkAlgorithm, err)
			}
			publicKey = key.(*rsa.PrivateKey).Public()
		case "ecdsa":
			key, err := parsePEMPrivateKey(fmt.Sprintf("./testdata/ecdsa-%d.pem", tt.bitSize))
			if err != nil {
				t.Errorf("%s key: Expected nil error, got %q", tt.jwkAlgorithm, err)
			}
			publicKey = key.(*ecdsa.PrivateKey).Public()
		}

		jwk := &jose.JsonWebKey{
			Key:       publicKey,
			Algorithm: tt.jwkAlgorithm,
		}

		jws := &jose.JsonWebSignature{Signatures: []jose.Signature{
			{
				Header: jose.JoseHeader{
					Algorithm: tt.jwkAlgorithm,
				},
			},
		}}

		if _, err = checkAlgorithm(jwk, jws); err != tt.err {
			t.Errorf("%s key: Expected nil error, got %q", tt.jwkAlgorithm, err)
		}
	}
}
