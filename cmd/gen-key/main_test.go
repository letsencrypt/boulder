package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/letsencrypt/boulder/test"
	"github.com/miekg/pkcs11"
)

type mockCtx struct {
	GetAttributeValueFunc func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error)
	SignInitFunc          func(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error
	SignFunc              func(pkcs11.SessionHandle, []byte) ([]byte, error)
	GenerateRandomFunc    func(pkcs11.SessionHandle, int) ([]byte, error)
}

func (mc mockCtx) GetAttributeValue(s pkcs11.SessionHandle, o pkcs11.ObjectHandle, a []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	return mc.GetAttributeValueFunc(s, o, a)
}
func (mc mockCtx) SignInit(s pkcs11.SessionHandle, m []*pkcs11.Mechanism, o pkcs11.ObjectHandle) error {
	return mc.SignInitFunc(s, m, o)
}
func (mc mockCtx) Sign(s pkcs11.SessionHandle, m []byte) ([]byte, error) {
	return mc.SignFunc(s, m)
}
func (mc mockCtx) GenerateRandom(s pkcs11.SessionHandle, c int) ([]byte, error) {
	return mc.GenerateRandomFunc(s, c)
}

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

func TestECPub(t *testing.T) {
	ctx := mockCtx{}

	// test attribute retrieval failing
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return nil, errors.New("yup")
	}
	_, err := ecPub(ctx, 0, 0, nil)
	test.AssertError(t, err, "ecPub didn't fail on GetAttributeValue error")

	// test we fail to construct key with missing params and point
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{}, nil
	}
	_, err = ecPub(ctx, 0, 0, nil)
	test.AssertError(t, err, "ecPub didn't fail with empty attribute list")

	// test we fail to construct key with unknown curve
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{1, 2, 3}),
		}, nil
	}
	_, err = ecPub(ctx, 0, 0, elliptic.P224())
	test.AssertError(t, err, "ecPub didn't fail with unknown curve")

	// test we fail to construct key with non-matching curve
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}),
		}, nil
	}
	_, err = ecPub(ctx, 0, 0, elliptic.P224())
	test.AssertError(t, err, "ecPub didn't fail with non-matching curve")

	// test we fail to construct key with invalid EC point (invalid encoding)
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{255}),
		}, nil
	}
	_, err = ecPub(ctx, 0, 0, elliptic.P256())
	test.AssertError(t, err, "ecPub didn't fail with invalid EC point (invalid encoding)")

	// test we fail to construct key with invalid EC point (empty octet string)
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{4, 0}),
		}, nil
	}
	_, err = ecPub(ctx, 0, 0, elliptic.P256())
	test.AssertError(t, err, "ecPub didn't fail with invalid EC point (octet string, invalid contents)")
	// test we fail to construct key with invalid EC point (empty octet string)
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{4, 4, 4, 1, 2, 3}),
		}, nil
	}
	_, err = ecPub(ctx, 0, 0, elliptic.P256())
	test.AssertError(t, err, "ecPub didn't fail with invalid EC point (empty octet string)")

	// test we don't fail with the correct attributes (traditional encoding)
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 5, 43, 129, 4, 0, 33}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{4, 217, 225, 246, 210, 153, 134, 246, 104, 95, 79, 122, 206, 135, 241, 37, 114, 199, 87, 56, 167, 83, 56, 136, 174, 6, 145, 97, 239, 221, 49, 67, 148, 13, 126, 65, 90, 208, 195, 193, 171, 105, 40, 98, 132, 124, 30, 189, 215, 197, 178, 226, 166, 238, 240, 57, 215}),
		}, nil
	}
	_, err = ecPub(ctx, 0, 0, elliptic.P224())
	test.AssertNotError(t, err, "ecPub failed with valid attributes (traditional encoding)")

	// test we don't fail with the correct attributes (untraditional encoding)
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 5, 43, 129, 4, 0, 33}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{4, 57, 4, 217, 225, 246, 210, 153, 134, 246, 104, 95, 79, 122, 206, 135, 241, 37, 114, 199, 87, 56, 167, 83, 56, 136, 174, 6, 145, 97, 239, 221, 49, 67, 148, 13, 126, 65, 90, 208, 195, 193, 171, 105, 40, 98, 132, 124, 30, 189, 215, 197, 178, 226, 166, 238, 240, 57, 215}),
		}, nil
	}
	_, err = ecPub(ctx, 0, 0, elliptic.P224())
	test.AssertNotError(t, err, "ecPub failed with valid attributes (untraditional encoding)")
}

func TestECVerify(t *testing.T) {
	ctx := mockCtx{}

	// test SignInit failing
	ctx.SignInitFunc = func(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
		return errors.New("yup")
	}
	err := ecVerify(ctx, 0, 0, nil)
	test.AssertError(t, err, "ecVerify didn't fail on SignInit error")

	// test GenerateRandom failing
	ctx.SignInitFunc = func(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
		return nil
	}
	ctx.GenerateRandomFunc = func(pkcs11.SessionHandle, int) ([]byte, error) {
		return nil, errors.New("yup")
	}
	err = ecVerify(ctx, 0, 0, nil)
	test.AssertError(t, err, "ecVerify didn't fail on GenerateRandom error")

	// test Sign failing
	ctx.GenerateRandomFunc = func(pkcs11.SessionHandle, int) ([]byte, error) {
		return []byte{1, 2, 3}, nil
	}
	ctx.SignFunc = func(pkcs11.SessionHandle, []byte) ([]byte, error) {
		return nil, errors.New("yup")
	}
	err = ecVerify(ctx, 0, 0, &ecdsa.PublicKey{Curve: elliptic.P256()})
	test.AssertError(t, err, "ecVerify didn't fail on Sign error")

	// test signature verification failing
	ctx.SignFunc = func(pkcs11.SessionHandle, []byte) ([]byte, error) {
		return []byte{1, 2, 3}, nil
	}
	tk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "ecdsa.GenerateKey failed")
	err = ecVerify(ctx, 0, 0, &tk.PublicKey)
	test.AssertError(t, err, "ecVerify didn't fail on signature verification error")

	// test we don't fail with valid signature
	ctx.SignFunc = func(pkcs11.SessionHandle, []byte) ([]byte, error) {
		hash := sha256.Sum256([]byte{1, 2, 3})
		r, s, err := ecdsa.Sign(rand.Reader, tk, hash[:])
		if err != nil {
			return nil, err
		}
		return append(r.Bytes(), s.Bytes()...), nil
	}
	err = ecVerify(ctx, 0, 0, &tk.PublicKey)
	test.AssertNotError(t, err, "ecVerify failed with a valid signature")
}
