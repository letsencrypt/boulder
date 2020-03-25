package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"testing"

	"github.com/letsencrypt/boulder/pkcs11helpers"
	"github.com/letsencrypt/boulder/test"
	"github.com/miekg/pkcs11"
)

func TestGenerateKey(t *testing.T) {
	tmp, err := ioutil.TempDir("", "ceremony-testing")
	test.AssertNotError(t, err, "Failed to create temporary directory")
	defer os.RemoveAll(tmp)

	// RSA
	ctx := pkcs11helpers.MockCtx{}
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 1024)
	test.AssertNotError(t, err, "Failed to generate a test RSA key")
	ctx.GenerateKeyPairFunc = func(pkcs11.SessionHandle, []*pkcs11.Mechanism, []*pkcs11.Attribute, []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
		return 0, 0, nil
	}
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(rsaPriv.E)).Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, rsaPriv.N.Bytes()),
		}, nil
	}
	ctx.SignInitFunc = func(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
		return nil
	}
	ctx.GenerateRandomFunc = func(pkcs11.SessionHandle, int) ([]byte, error) {
		return []byte{1, 2, 3}, nil
	}
	ctx.SignFunc = func(_ pkcs11.SessionHandle, msg []byte) ([]byte, error) {
		// Chop of the hash identifier and feed back into rsa.SignPKCS1v15
		return rsa.SignPKCS1v15(rand.Reader, rsaPriv, crypto.SHA256, msg[19:])
	}
	keyPath := path.Join(tmp, "test-rsa-key.pem")
	keyInfo, err := generateKey(ctx, 0, "", keyPath, keyGenConfig{
		Type:         "rsa",
		RSAModLength: 1024,
	})
	test.AssertNotError(t, err, "Failed to generate RSA key")
	diskKeyBytes, err := ioutil.ReadFile(keyPath)
	test.AssertNotError(t, err, "Failed to load key from disk")
	block, _ := pem.Decode(diskKeyBytes)
	diskKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	test.AssertNotError(t, err, "Failed to parse disk key")
	test.AssertDeepEquals(t, diskKey, keyInfo.key)

	// EC
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "Failed to generate a ECDSA test key")
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, elliptic.Marshal(elliptic.P256(), ecPriv.X, ecPriv.Y)),
		}, nil
	}
	ctx.SignFunc = func(_ pkcs11.SessionHandle, msg []byte) ([]byte, error) {
		return ecPKCS11Sign(ecPriv, msg)
	}
	keyPath = path.Join(tmp, "test-ecdsa-key.pem")
	keyInfo, err = generateKey(ctx, 0, "", keyPath, keyGenConfig{
		Type:       "ecdsa",
		ECDSACurve: "P-256",
	})
	test.AssertNotError(t, err, "Failed to generate ECDSA key")
	diskKeyBytes, err = ioutil.ReadFile(keyPath)
	test.AssertNotError(t, err, "Failed to load key from disk")
	block, _ = pem.Decode(diskKeyBytes)
	diskKey, err = x509.ParsePKIXPublicKey(block.Bytes)
	test.AssertNotError(t, err, "Failed to parse disk key")
	test.AssertDeepEquals(t, diskKey, keyInfo.key)
}
