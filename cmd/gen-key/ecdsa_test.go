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
	_, err := ecPub(ctx, 0, 0, nil, false)
	test.AssertError(t, err, "ecPub didn't fail on GetAttributeValue error")

	// test we fail to construct key with missing params and point
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{}, nil
	}
	_, err = ecPub(ctx, 0, 0, nil, false)
	test.AssertError(t, err, "ecPub didn't fail with empty attribute list")

	// test we fail to construct key with unknown curve
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{1, 2, 3}),
		}, nil
	}
	_, err = ecPub(ctx, 0, 0, elliptic.P224(), false)
	test.AssertError(t, err, "ecPub didn't fail with unknown curve")

	// test we fail to construct key with non-matching curve
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}),
		}, nil
	}
	_, err = ecPub(ctx, 0, 0, elliptic.P224(), false)
	test.AssertError(t, err, "ecPub didn't fail with non-matching curve")

	// test we fail to construct key with invalid EC point (invalid encoding)
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{255}),
		}, nil
	}
	_, err = ecPub(ctx, 0, 0, elliptic.P256(), false)
	test.AssertError(t, err, "ecPub didn't fail with invalid EC point (invalid encoding)")

	// test we fail to construct key with invalid EC point (empty octet string)
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{4, 0}),
		}, nil
	}
	_, err = ecPub(ctx, 0, 0, elliptic.P256(), false)
	test.AssertError(t, err, "ecPub didn't fail with invalid EC point (octet string, invalid contents)")
	// test we fail to construct key with invalid EC point (empty octet string)
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{4, 4, 4, 1, 2, 3}),
		}, nil
	}
	_, err = ecPub(ctx, 0, 0, elliptic.P256(), false)
	test.AssertError(t, err, "ecPub didn't fail with invalid EC point (empty octet string)")

	// test we don't fail with the correct attributes (traditional encoding)
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 5, 43, 129, 4, 0, 33}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{4, 217, 225, 246, 210, 153, 134, 246, 104, 95, 79, 122, 206, 135, 241, 37, 114, 199, 87, 56, 167, 83, 56, 136, 174, 6, 145, 97, 239, 221, 49, 67, 148, 13, 126, 65, 90, 208, 195, 193, 171, 105, 40, 98, 132, 124, 30, 189, 215, 197, 178, 226, 166, 238, 240, 57, 215}),
		}, nil
	}
	_, err = ecPub(ctx, 0, 0, elliptic.P224(), false)
	test.AssertNotError(t, err, "ecPub failed with valid attributes (traditional encoding)")

	// test we don't fail with the correct attributes (non-traditional encoding)
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 5, 43, 129, 4, 0, 33}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{4, 57, 4, 217, 225, 246, 210, 153, 134, 246, 104, 95, 79, 122, 206, 135, 241, 37, 114, 199, 87, 56, 167, 83, 56, 136, 174, 6, 145, 97, 239, 221, 49, 67, 148, 13, 126, 65, 90, 208, 195, 193, 171, 105, 40, 98, 132, 124, 30, 189, 215, 197, 178, 226, 166, 238, 240, 57, 215}),
		}, nil
	}
	_, err = ecPub(ctx, 0, 0, elliptic.P224(), false)
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

func TestECGenerate(t *testing.T) {
	ctx := mockCtx{}

	// Test ecGenerate fails with unknown curve
	_, err := ecGenerate(ctx, 0, "", "bad-curve", false)
	test.AssertError(t, err, "ecGenerate accepted unknown curve")

	// Test ecGenerate fails when GenerateKeyPair fails
	ctx.GenerateKeyPairFunc = func(pkcs11.SessionHandle, []*pkcs11.Mechanism, []*pkcs11.Attribute, []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
		return 0, 0, errors.New("bad")
	}
	_, err = ecGenerate(ctx, 0, "", "P-256", false)
	test.AssertError(t, err, "ecGenerate didn't fail on GenerateKeyPair error")

	// Test ecGenerate fails when ecPub fails
	ctx.GenerateKeyPairFunc = func(pkcs11.SessionHandle, []*pkcs11.Mechanism, []*pkcs11.Attribute, []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
		return 0, 0, nil
	}
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return nil, errors.New("bad")
	}
	_, err = ecGenerate(ctx, 0, "", "P-256", false)
	test.AssertError(t, err, "ecGenerate didn't fail on ecPub error")

	// Test ecGenerate fails when ecVerify fails
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{4, 71, 137, 101, 56, 44, 59, 172, 148, 152, 118, 61, 183, 215, 242, 168, 62, 77, 94, 246, 212, 164, 96, 210, 134, 87, 169, 142, 226, 189, 118, 137, 203, 117, 55, 2, 215, 177, 159, 42, 196, 33, 91, 92, 251, 98, 53, 137, 221, 167, 148, 25, 209, 1, 5, 90, 52, 43, 18, 7, 30, 33, 142, 228, 235}),
		}, nil
	}
	ctx.SignInitFunc = func(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
		return errors.New("yup")
	}
	_, err = ecGenerate(ctx, 0, "", "P-256", false)
	test.AssertError(t, err, "ecGenerate didn't fail on ecVerify error")

	// Test ecGenerate doesn't fail when everything works
	ctx.SignInitFunc = func(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
		return nil
	}
	ctx.GenerateRandomFunc = func(pkcs11.SessionHandle, int) ([]byte, error) {
		return []byte{1, 2, 3}, nil
	}
	ctx.SignFunc = func(pkcs11.SessionHandle, []byte) ([]byte, error) {
		return []byte{82, 33, 179, 118, 118, 141, 38, 154, 5, 20, 207, 140, 127, 221, 237, 139, 222, 74, 189, 107, 84, 133, 127, 80, 226, 169, 25, 110, 141, 226, 196, 69, 202, 51, 204, 77, 22, 198, 104, 91, 74, 120, 221, 156, 122, 11, 43, 54, 106, 10, 165, 202, 229, 71, 44, 18, 113, 236, 213, 47, 208, 239, 198, 33}, nil
	}
	_, err = ecGenerate(ctx, 0, "", "P-256", false)
	test.AssertNotError(t, err, "ecGenerate didn't succeed when everything worked as expected")

	// Test ecGenerate doesn't fail when everything works with compatibility mode
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ECDSA_PARAMS, []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{4, 71, 137, 101, 56, 44, 59, 172, 148, 152, 118, 61, 183, 215, 242, 168, 62, 77, 94, 246, 212, 164, 96, 210, 134, 87, 169, 142, 226, 189, 118, 137, 203, 117, 55, 2, 215, 177, 159, 42, 196, 33, 91, 92, 251, 98, 53, 137, 221, 167, 148, 25, 209, 1, 5, 90, 52, 43, 18, 7, 30, 33, 142, 228, 235}),
		}, nil
	}
	_, err = ecGenerate(ctx, 0, "", "P-256", true)
	test.AssertNotError(t, err, "ecGenerate didn't succeed when everything worked as expected")
}
