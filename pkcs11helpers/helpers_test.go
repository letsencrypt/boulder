package pkcs11helpers

import (
	"errors"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/test"
	"github.com/miekg/pkcs11"
)

func TestGetECDSAPublicKey(t *testing.T) {
	ctx := MockCtx{}

	// test attribute retrieval failing
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return nil, errors.New("yup")
	}
	_, err := GetECDSAPublicKey(ctx, 0, 0)
	test.AssertError(t, err, "ecPub didn't fail on GetAttributeValue error")

	// test we fail to construct key with missing params and point
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{}, nil
	}
	_, err = GetECDSAPublicKey(ctx, 0, 0)
	test.AssertError(t, err, "ecPub didn't fail with empty attribute list")

	// test we fail to construct key with unknown curve
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{1, 2, 3}),
		}, nil
	}
	_, err = GetECDSAPublicKey(ctx, 0, 0)
	test.AssertError(t, err, "ecPub didn't fail with unknown curve")

	// test we fail to construct key with invalid EC point (invalid encoding)
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{255}),
		}, nil
	}
	_, err = GetECDSAPublicKey(ctx, 0, 0)
	test.AssertError(t, err, "ecPub didn't fail with invalid EC point (invalid encoding)")

	// test we fail to construct key with invalid EC point (empty octet string)
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{4, 0}),
		}, nil
	}
	_, err = GetECDSAPublicKey(ctx, 0, 0)
	test.AssertError(t, err, "ecPub didn't fail with invalid EC point (empty octet string)")

	// test we fail to construct key with invalid EC point (octet string, invalid contents)
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{4, 4, 4, 1, 2, 3}),
		}, nil
	}
	_, err = GetECDSAPublicKey(ctx, 0, 0)
	test.AssertError(t, err, "ecPub didn't fail with invalid EC point (octet string, invalid contents)")

	// test we don't fail with the correct attributes (traditional encoding)
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 5, 43, 129, 4, 0, 33}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{4, 217, 225, 246, 210, 153, 134, 246, 104, 95, 79, 122, 206, 135, 241, 37, 114, 199, 87, 56, 167, 83, 56, 136, 174, 6, 145, 97, 239, 221, 49, 67, 148, 13, 126, 65, 90, 208, 195, 193, 171, 105, 40, 98, 132, 124, 30, 189, 215, 197, 178, 226, 166, 238, 240, 57, 215}),
		}, nil
	}
	_, err = GetECDSAPublicKey(ctx, 0, 0)
	test.AssertNotError(t, err, "ecPub failed with valid attributes (traditional encoding)")

	// test we don't fail with the correct attributes (non-traditional encoding)
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 5, 43, 129, 4, 0, 33}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{4, 57, 4, 217, 225, 246, 210, 153, 134, 246, 104, 95, 79, 122, 206, 135, 241, 37, 114, 199, 87, 56, 167, 83, 56, 136, 174, 6, 145, 97, 239, 221, 49, 67, 148, 13, 126, 65, 90, 208, 195, 193, 171, 105, 40, 98, 132, 124, 30, 189, 215, 197, 178, 226, 166, 238, 240, 57, 215}),
		}, nil
	}
	_, err = GetECDSAPublicKey(ctx, 0, 0)
	test.AssertNotError(t, err, "ecPub failed with valid attributes (non-traditional encoding)")
}

func TestRSAPublicKey(t *testing.T) {
	ctx := MockCtx{}

	// test attribute retrieval failing
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return nil, errors.New("yup")
	}
	_, err := GetRSAPublicKey(ctx, 0, 0)
	test.AssertError(t, err, "rsaPub didn't fail on GetAttributeValue error")

	// test we fail to construct key with missing modulus and exp
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{}, nil
	}
	_, err = GetRSAPublicKey(ctx, 0, 0)
	test.AssertError(t, err, "rsaPub didn't fail with empty attribute list")

	// test we don't fail with the correct attributes
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, []byte{255}),
		}, nil
	}
	_, err = GetRSAPublicKey(ctx, 0, 0)
	test.AssertNotError(t, err, "rsaPub failed with valid attributes")
}

func findObjectsFinalOK(pkcs11.SessionHandle) error {
	return nil
}

func findObjectsInitOK(pkcs11.SessionHandle, []*pkcs11.Attribute) error {
	return nil
}

func TestFindObjectFailsOnFailedInit(t *testing.T) {
	ctx := MockCtx{}
	ctx.FindObjectsFinalFunc = findObjectsFinalOK

	// test FindObject fails when FindObjectsInit fails
	ctx.FindObjectsInitFunc = func(pkcs11.SessionHandle, []*pkcs11.Attribute) error {
		return errors.New("broken")
	}
	_, err := FindObject(ctx, 0, nil)
	test.AssertError(t, err, "FindObject didn't fail when FindObjectsInit failed")
}

func TestFindObjectFailsOnFailedFindObjects(t *testing.T) {
	ctx := MockCtx{}
	ctx.FindObjectsInitFunc = findObjectsInitOK
	ctx.FindObjectsFinalFunc = findObjectsFinalOK

	// test FindObject fails when FindObjects fails
	ctx.FindObjectsFunc = func(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
		return nil, false, errors.New("broken")
	}
	_, err := FindObject(ctx, 0, nil)
	test.AssertError(t, err, "FindObject didn't fail when FindObjects failed")
}

func TestFindObjectFailsOnNoHandles(t *testing.T) {
	ctx := MockCtx{}
	ctx.FindObjectsInitFunc = findObjectsInitOK
	ctx.FindObjectsFinalFunc = findObjectsFinalOK

	// test FindObject fails when no handles are returned
	ctx.FindObjectsFunc = func(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
		return []pkcs11.ObjectHandle{}, false, nil
	}
	_, err := FindObject(ctx, 0, nil)
	test.AssertEquals(t, err, ErrNoObject)
}

func TestFindObjectFailsOnMultipleHandles(t *testing.T) {
	ctx := MockCtx{}
	ctx.FindObjectsInitFunc = findObjectsInitOK
	ctx.FindObjectsFinalFunc = findObjectsFinalOK

	// test FindObject fails when multiple handles are returned
	ctx.FindObjectsFunc = func(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
		return []pkcs11.ObjectHandle{1, 2, 3}, false, nil
	}
	_, err := FindObject(ctx, 0, nil)
	test.AssertError(t, err, "FindObject didn't fail when FindObjects returns multiple handles")
	test.Assert(t, strings.HasPrefix(err.Error(), "too many objects"), "FindObject failed with wrong error")
}

func TestFindObjectFailsOnFinalizeFailure(t *testing.T) {
	ctx := MockCtx{}
	ctx.FindObjectsInitFunc = findObjectsInitOK

	// test FindObject fails when FindObjectsFinal fails
	ctx.FindObjectsFunc = func(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
		return []pkcs11.ObjectHandle{1}, false, nil
	}
	ctx.FindObjectsFinalFunc = func(pkcs11.SessionHandle) error {
		return errors.New("broken")
	}
	_, err := FindObject(ctx, 0, nil)
	test.AssertError(t, err, "FindObject didn't fail when FindObjectsFinal fails")
}

func TestFindObjectSucceeds(t *testing.T) {
	ctx := MockCtx{}

	ctx.FindObjectsInitFunc = findObjectsInitOK
	ctx.FindObjectsFinalFunc = findObjectsFinalOK
	ctx.FindObjectsFunc = func(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
		return []pkcs11.ObjectHandle{1}, false, nil
	}
	// test FindObject works
	handle, err := FindObject(ctx, 0, nil)
	test.AssertNotError(t, err, "FindObject failed when everything worked as expected")
	test.AssertEquals(t, handle, pkcs11.ObjectHandle(1))
}
