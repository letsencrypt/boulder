package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
	"testing"

	"github.com/letsencrypt/boulder/pkcs11helpers"
	"github.com/letsencrypt/boulder/test"
	"github.com/miekg/pkcs11"
)

func TestRSAPub(t *testing.T) {
	ctx := pkcs11helpers.MockCtx{}

	// test we fail to construct key with non-matching exp
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, []byte{255}),
		}, nil
	}
	_, err := rsaPub(ctx, 0, 0, 0, 255)
	test.AssertError(t, err, "rsaPub didn't fail with non-matching exp")

	// test we fail to construct key with non-matching modulus
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, []byte{255}),
		}, nil
	}
	_, err = rsaPub(ctx, 0, 0, 16, 65537)
	test.AssertError(t, err, "rsaPub didn't fail with non-matching modulus size")

	// test we don't fail with the correct attributes
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, []byte{255}),
		}, nil
	}
	_, err = rsaPub(ctx, 0, 0, 8, 65537)
	test.AssertNotError(t, err, "rsaPub failed with valid attributes")
}

func TestRSAVerify(t *testing.T) {
	ctx := pkcs11helpers.MockCtx{}

	// test GenerateRandom failing
	ctx.GenerateRandomFunc = func(pkcs11.SessionHandle, int) ([]byte, error) {
		return nil, errors.New("yup")
	}
	err := rsaVerify(ctx, 0, 0, nil)
	test.AssertError(t, err, "rsaVerify didn't fail on GenerateRandom error")

	// test SignInit failing
	ctx.GenerateRandomFunc = func(pkcs11.SessionHandle, int) ([]byte, error) {
		return []byte{1, 2, 3}, nil
	}
	ctx.SignInitFunc = func(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
		return errors.New("yup")
	}
	err = rsaVerify(ctx, 0, 0, nil)
	test.AssertError(t, err, "rsaVerify didn't fail on SignInit error")

	// test Sign failing
	ctx.SignInitFunc = func(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
		return nil
	}
	ctx.GenerateRandomFunc = func(pkcs11.SessionHandle, int) ([]byte, error) {
		return []byte{1, 2, 3, 4}, nil
	}
	ctx.SignFunc = func(pkcs11.SessionHandle, []byte) ([]byte, error) {
		return nil, errors.New("yup")
	}
	err = rsaVerify(ctx, 0, 0, nil)
	test.AssertError(t, err, "rsaVerify didn't fail on Sign error")

	// test signature verification failing
	ctx.SignFunc = func(pkcs11.SessionHandle, []byte) ([]byte, error) {
		return []byte{1, 2, 3}, nil
	}
	tk, err := rsa.GenerateKey(rand.Reader, 1024)
	test.AssertNotError(t, err, "rsa.GenerateKey failed")
	err = rsaVerify(ctx, 0, 0, &tk.PublicKey)
	test.AssertError(t, err, "rsaVerify didn't fail on signature verification error")

	// test we don't fail with valid signature
	ctx.SignFunc = func(_ pkcs11.SessionHandle, msg []byte) ([]byte, error) {
		// Chop of the hash identifier and feed back into rsa.SignPKCS1v15
		return rsa.SignPKCS1v15(rand.Reader, tk, crypto.SHA256, msg[19:])
	}
	err = rsaVerify(ctx, 0, 0, &tk.PublicKey)
	test.AssertNotError(t, err, "rsaVerify failed with a valid signature")
}

func TestRSAGenerate(t *testing.T) {
	ctx := pkcs11helpers.MockCtx{}
	ctx.GenerateRandomFunc = func(pkcs11.SessionHandle, int) ([]byte, error) {
		return []byte{1, 2, 3}, nil
	}

	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	test.AssertNotError(t, err, "Failed to generate a RSA test key")

	// Test rsaGenerate fails when GenerateKeyPair fails
	ctx.GenerateKeyPairFunc = func(pkcs11.SessionHandle, []*pkcs11.Mechanism, []*pkcs11.Attribute, []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
		return 0, 0, errors.New("bad")
	}
	_, _, err = rsaGenerate(ctx, 0, "", 1024, 65537)
	test.AssertError(t, err, "rsaGenerate didn't fail on GenerateKeyPair error")

	// Test rsaGenerate fails when rsaPub fails
	ctx.GenerateKeyPairFunc = func(pkcs11.SessionHandle, []*pkcs11.Mechanism, []*pkcs11.Attribute, []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
		return 0, 0, nil
	}
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return nil, errors.New("bad")
	}
	_, _, err = rsaGenerate(ctx, 0, "", 1024, 65537)
	test.AssertError(t, err, "rsaGenerate didn't fail on rsaPub error")

	// Test rsaGenerate fails when rsaVerify fails
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(priv.E)).Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, priv.N.Bytes()),
		}, nil
	}
	ctx.GenerateRandomFunc = func(pkcs11.SessionHandle, int) ([]byte, error) {
		return nil, errors.New("yup")
	}
	_, _, err = rsaGenerate(ctx, 0, "", 1024, 65537)
	test.AssertError(t, err, "rsaGenerate didn't fail on rsaVerify error")

	// Test rsaGenerate doesn't fail when everything works
	ctx.SignInitFunc = func(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
		return nil
	}
	ctx.GenerateRandomFunc = func(pkcs11.SessionHandle, int) ([]byte, error) {
		return []byte{1, 2, 3}, nil
	}
	ctx.SignFunc = func(_ pkcs11.SessionHandle, msg []byte) ([]byte, error) {
		// Chop of the hash identifier and feed back into rsa.SignPKCS1v15
		return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, msg[19:])
	}
	_, _, err = rsaGenerate(ctx, 0, "", 1024, 65537)
	test.AssertNotError(t, err, "rsaGenerate didn't succeed when everything worked as expected")
}
