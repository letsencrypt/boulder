package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/letsencrypt/boulder/test"
	"github.com/miekg/pkcs11"
)

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

	// test we don't fail with the correct attributes (non-traditional encoding)
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 5, 43, 129, 4, 0, 33}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{4, 57, 4, 217, 225, 246, 210, 153, 134, 246, 104, 95, 79, 122, 206, 135, 241, 37, 114, 199, 87, 56, 167, 83, 56, 136, 174, 6, 145, 97, 239, 221, 49, 67, 148, 13, 126, 65, 90, 208, 195, 193, 171, 105, 40, 98, 132, 124, 30, 189, 215, 197, 178, 226, 166, 238, 240, 57, 215}),
		}, nil
	}
	_, err = ecPub(ctx, 0, 0, elliptic.P224())
	test.AssertNotError(t, err, "ecPub failed with valid attributes (non-traditional encoding)")
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
