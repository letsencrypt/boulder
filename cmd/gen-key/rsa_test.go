package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/letsencrypt/boulder/test"
	"github.com/miekg/pkcs11"
)

func TestRSAPub(t *testing.T) {
	ctx := mockCtx{}

	// test attribute retrieval failing
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return nil, errors.New("yup")
	}
	_, err := rsaPub(ctx, 0, 0, 0, 0)
	test.AssertError(t, err, "rsaPub didn't fail on GetAttributeValue error")

	// test we fail to construct key with missing modulus and exp
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{}, nil
	}
	_, err = rsaPub(ctx, 0, 0, 0, 0)
	test.AssertError(t, err, "rsaPub didn't fail with empty attribute list")

	// test we fail to construct key with non-matching exp
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		}, nil
	}
	_, err = rsaPub(ctx, 0, 0, 0, 0)
	test.AssertError(t, err, "rsaPub didn't fail with non-matching exp")

	// test we fail to construct key with non-matching exp
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
	ctx := mockCtx{}

	// test SignInit failing
	ctx.SignInitFunc = func(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
		return errors.New("yup")
	}
	err := rsaVerify(ctx, 0, 0, nil)
	test.AssertError(t, err, "rsaVerify didn't fail on SignInit error")

	// test GenerateRandom failing
	ctx.SignInitFunc = func(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
		return nil
	}
	ctx.GenerateRandomFunc = func(pkcs11.SessionHandle, int) ([]byte, error) {
		return nil, errors.New("yup")
	}
	err = rsaVerify(ctx, 0, 0, nil)
	test.AssertError(t, err, "rsaVerify didn't fail on GenerateRandom error")

	// test Sign failing
	ctx.GenerateRandomFunc = func(pkcs11.SessionHandle, int) ([]byte, error) {
		return []byte{1, 2, 3}, nil
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
	ctx.SignFunc = func(pkcs11.SessionHandle, []byte) ([]byte, error) {
		hash := sha256.Sum256([]byte{1, 2, 3})
		return rsa.SignPKCS1v15(rand.Reader, tk, crypto.SHA256, hash[:])
	}
	err = rsaVerify(ctx, 0, 0, &tk.PublicKey)
	test.AssertNotError(t, err, "rsaVerify failed with a valid signature")
}
