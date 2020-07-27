package pkcs11helpers

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/test"
	"github.com/miekg/pkcs11"
)

func TestGetECDSAPublicKey(t *testing.T) {
	ctx := &MockCtx{}
	s := &Session{ctx, 0}

	// test attribute retrieval failing
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return nil, errors.New("yup")
	}
	_, err := s.GetECDSAPublicKey(0)
	test.AssertError(t, err, "ecPub didn't fail on GetAttributeValue error")

	// test we fail to construct key with missing params and point
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{}, nil
	}
	_, err = s.GetECDSAPublicKey(0)
	test.AssertError(t, err, "ecPub didn't fail with empty attribute list")

	// test we fail to construct key with unknown curve
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{1, 2, 3}),
		}, nil
	}
	_, err = s.GetECDSAPublicKey(0)
	test.AssertError(t, err, "ecPub didn't fail with unknown curve")

	// test we fail to construct key with invalid EC point (invalid encoding)
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{255}),
		}, nil
	}
	_, err = s.GetECDSAPublicKey(0)
	test.AssertError(t, err, "ecPub didn't fail with invalid EC point (invalid encoding)")

	// test we fail to construct key with invalid EC point (empty octet string)
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{4, 0}),
		}, nil
	}
	_, err = s.GetECDSAPublicKey(0)
	test.AssertError(t, err, "ecPub didn't fail with invalid EC point (empty octet string)")

	// test we fail to construct key with invalid EC point (octet string, invalid contents)
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{4, 4, 4, 1, 2, 3}),
		}, nil
	}
	_, err = s.GetECDSAPublicKey(0)
	test.AssertError(t, err, "ecPub didn't fail with invalid EC point (octet string, invalid contents)")

	// test we don't fail with the correct attributes (traditional encoding)
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 5, 43, 129, 4, 0, 33}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{4, 217, 225, 246, 210, 153, 134, 246, 104, 95, 79, 122, 206, 135, 241, 37, 114, 199, 87, 56, 167, 83, 56, 136, 174, 6, 145, 97, 239, 221, 49, 67, 148, 13, 126, 65, 90, 208, 195, 193, 171, 105, 40, 98, 132, 124, 30, 189, 215, 197, 178, 226, 166, 238, 240, 57, 215}),
		}, nil
	}
	_, err = s.GetECDSAPublicKey(0)
	test.AssertNotError(t, err, "ecPub failed with valid attributes (traditional encoding)")

	// test we don't fail with the correct attributes (non-traditional encoding)
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 5, 43, 129, 4, 0, 33}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{4, 57, 4, 217, 225, 246, 210, 153, 134, 246, 104, 95, 79, 122, 206, 135, 241, 37, 114, 199, 87, 56, 167, 83, 56, 136, 174, 6, 145, 97, 239, 221, 49, 67, 148, 13, 126, 65, 90, 208, 195, 193, 171, 105, 40, 98, 132, 124, 30, 189, 215, 197, 178, 226, 166, 238, 240, 57, 215}),
		}, nil
	}
	_, err = s.GetECDSAPublicKey(0)
	test.AssertNotError(t, err, "ecPub failed with valid attributes (non-traditional encoding)")
}

func TestRSAPublicKey(t *testing.T) {
	ctx := &MockCtx{}
	s := &Session{ctx, 0}

	// test attribute retrieval failing
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return nil, errors.New("yup")
	}
	_, err := s.GetRSAPublicKey(0)
	test.AssertError(t, err, "rsaPub didn't fail on GetAttributeValue error")

	// test we fail to construct key with missing modulus and exp
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{}, nil
	}
	_, err = s.GetRSAPublicKey(0)
	test.AssertError(t, err, "rsaPub didn't fail with empty attribute list")

	// test we don't fail with the correct attributes
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, []byte{255}),
		}, nil
	}
	_, err = s.GetRSAPublicKey(0)
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
	ctx.FindObjectsFunc = func(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
		return []pkcs11.ObjectHandle{1}, false, nil
	}

	// test FindObject fails when FindObjectsInit fails
	ctx.FindObjectsInitFunc = func(pkcs11.SessionHandle, []*pkcs11.Attribute) error {
		return errors.New("broken")
	}
	s := &Session{ctx, 0}
	_, err := s.FindObject(nil)
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
	s := &Session{ctx, 0}
	_, err := s.FindObject(nil)
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
	s := &Session{ctx, 0}
	_, err := s.FindObject(nil)
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
	s := &Session{ctx, 0}
	_, err := s.FindObject(nil)
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
	s := &Session{ctx, 0}
	_, err := s.FindObject(nil)
	test.AssertError(t, err, "FindObject didn't fail when FindObjectsFinal fails")
}

func TestFindObjectSucceeds(t *testing.T) {
	ctx := MockCtx{}
	ctx.FindObjectsInitFunc = findObjectsInitOK
	ctx.FindObjectsFinalFunc = findObjectsFinalOK
	ctx.FindObjectsFunc = func(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
		return []pkcs11.ObjectHandle{1}, false, nil
	}
	s := &Session{ctx, 0}

	// test FindObject works
	handle, err := s.FindObject(nil)
	test.AssertNotError(t, err, "FindObject failed when everything worked as expected")
	test.AssertEquals(t, handle, pkcs11.ObjectHandle(1))
}

func TestX509Signer(t *testing.T) {
	ctx := MockCtx{}

	// test that x509Signer.Sign properly converts the PKCS#11 format signature to
	// the RFC 5480 format signature
	ctx.SignInitFunc = func(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
		return nil
	}
	tk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "Failed to generate test key")
	ctx.SignFunc = func(_ pkcs11.SessionHandle, digest []byte) ([]byte, error) {
		r, s, err := ecdsa.Sign(rand.Reader, tk, digest[:])
		if err != nil {
			return nil, err
		}
		rBytes := r.Bytes()
		sBytes := s.Bytes()
		// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html
		// Section 2.3.1: EC Signatures
		// "If r and s have different octet length, the shorter of both must be padded with
		// leading zero octets such that both have the same octet length."
		switch {
		case len(rBytes) < len(sBytes):
			padding := make([]byte, len(sBytes)-len(rBytes))
			rBytes = append(padding, rBytes...)
		case len(rBytes) > len(sBytes):
			padding := make([]byte, len(rBytes)-len(sBytes))
			sBytes = append(padding, sBytes...)
		}
		return append(rBytes, sBytes...), nil
	}
	digest := sha256.Sum256([]byte("hello"))
	s := &Session{ctx, 0}
	signer := &x509Signer{session: s, keyType: ECDSAKey, pub: tk.Public()}
	signature, err := signer.Sign(nil, digest[:], crypto.SHA256)
	test.AssertNotError(t, err, "x509Signer.Sign failed")

	var rfcFormat struct {
		R, S *big.Int
	}
	rest, err := asn1.Unmarshal(signature, &rfcFormat)
	test.AssertNotError(t, err, "asn1.Unmarshal failed trying to parse signature")
	test.Assert(t, len(rest) == 0, "Signature had trailing garbage")
	verified := ecdsa.Verify(&tk.PublicKey, digest[:], rfcFormat.R, rfcFormat.S)
	test.Assert(t, verified, "Failed to verify RFC format signature")
	// For the sake of coverage
	test.AssertEquals(t, signer.Public(), tk.Public())
}
