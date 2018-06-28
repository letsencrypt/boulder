package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/letsencrypt/boulder/pkcs11helpers"
	"github.com/letsencrypt/boulder/test"
	"github.com/miekg/pkcs11"
)

func TestRSAPub(t *testing.T) {
	ctx := pkcs11helpers.MockCtx{}

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

func TestRSAGenerate(t *testing.T) {
	ctx := pkcs11helpers.MockCtx{}

	// Test rsaGenerate fails when GenerateKeyPair fails
	ctx.GenerateKeyPairFunc = func(pkcs11.SessionHandle, []*pkcs11.Mechanism, []*pkcs11.Attribute, []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
		return 0, 0, errors.New("bad")
	}
	_, err := rsaGenerate(ctx, 0, "", 1024, 65537)
	test.AssertError(t, err, "rsaGenerate didn't fail on GenerateKeyPair error")

	// Test rsaGenerate fails when rsaPub fails
	ctx.GenerateKeyPairFunc = func(pkcs11.SessionHandle, []*pkcs11.Mechanism, []*pkcs11.Attribute, []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
		return 0, 0, nil
	}
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return nil, errors.New("bad")
	}
	_, err = rsaGenerate(ctx, 0, "", 1024, 65537)
	test.AssertError(t, err, "rsaGenerate didn't fail on rsaPub error")

	// Test rsaGenerate fails when rsaVerify fails
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, []byte{217, 226, 207, 73, 127, 217, 136, 48, 203, 2, 12, 223, 251, 130, 143, 118, 13, 186, 82, 183, 220, 178, 158, 204, 19, 255, 121, 75, 243, 84, 118, 40, 128, 29, 11, 245, 43, 246, 217, 244, 166, 208, 36, 59, 69, 34, 142, 40, 22, 230, 195, 193, 111, 202, 186, 174, 233, 175, 140, 74, 19, 135, 191, 82, 27, 41, 123, 157, 174, 219, 38, 71, 19, 138, 28, 41, 48, 52, 142, 234, 196, 242, 51, 90, 204, 10, 235, 88, 150, 156, 89, 156, 199, 152, 173, 251, 88, 67, 138, 147, 86, 190, 236, 107, 190, 169, 53, 160, 219, 71, 147, 247, 230, 24, 188, 44, 61, 92, 106, 254, 125, 145, 233, 211, 76, 13, 159, 167}),
		}, nil
	}
	ctx.GenerateRandomFunc = func(pkcs11.SessionHandle, int) ([]byte, error) {
		return nil, errors.New("yup")
	}
	_, err = rsaGenerate(ctx, 0, "", 1024, 65537)
	test.AssertError(t, err, "rsaGenerate didn't fail on rsaVerify error")

	// Test rsaGenerate doesn't fail when everything works
	ctx.SignInitFunc = func(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
		return nil
	}
	ctx.GenerateRandomFunc = func(pkcs11.SessionHandle, int) ([]byte, error) {
		return []byte{1, 2, 3}, nil
	}
	ctx.SignFunc = func(pkcs11.SessionHandle, []byte) ([]byte, error) {
		return []byte{182, 42, 17, 237, 215, 151, 23, 254, 234, 219, 10, 119, 178, 76, 204, 254, 235, 67, 135, 83, 97, 134, 117, 38, 68, 115, 190, 250, 69, 200, 138, 225, 5, 188, 175, 45, 32, 179, 239, 145, 13, 168, 119, 75, 11, 171, 161, 220, 39, 185, 249, 87, 226, 132, 237, 82, 246, 187, 26, 232, 69, 86, 29, 12, 233, 8, 252, 59, 24, 194, 173, 74, 191, 101, 249, 108, 195, 240, 100, 28, 241, 70, 78, 236, 9, 136, 130, 218, 245, 195, 128, 80, 253, 42, 82, 99, 200, 115, 14, 75, 218, 176, 94, 98, 7, 226, 110, 24, 187, 108, 42, 144, 238, 244, 114, 153, 125, 3, 248, 129, 159, 51, 91, 26, 177, 118, 250, 79}, nil
	}
	_, err = rsaGenerate(ctx, 0, "", 1024, 65537)
	test.AssertNotError(t, err, "rsaGenerate didn't succeed when everything worked as expected")
}
