package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/letsencrypt/boulder/pkcs11helpers"
	"github.com/letsencrypt/boulder/test"
	"github.com/miekg/pkcs11"
)

func TestFindObject(t *testing.T) {
	ctx := pkcs11helpers.MockCtx{}

	// test findObject fails when FindObjectsInit fails
	ctx.FindObjectsInitFunc = func(pkcs11.SessionHandle, []*pkcs11.Attribute) error {
		return errors.New("broken")
	}
	_, err := findObject(ctx, 0, nil)
	test.AssertError(t, err, "findObject didn't fail when FindObjectsInit failed")

	// test findObject fails when FindObjects fails
	ctx.FindObjectsInitFunc = func(pkcs11.SessionHandle, []*pkcs11.Attribute) error {
		return nil
	}
	ctx.FindObjectsFunc = func(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
		return nil, false, errors.New("broken")
	}
	_, err = findObject(ctx, 0, nil)
	test.AssertError(t, err, "findObject didn't fail when FindObjects failed")

	// test findObject fails when no handles are returned
	ctx.FindObjectsFunc = func(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
		return []pkcs11.ObjectHandle{}, false, nil
	}
	_, err = findObject(ctx, 0, nil)
	test.AssertError(t, err, "findObject didn't fail when FindObjects returns no handles")

	// test findObject fails when multiple handles are returned
	ctx.FindObjectsFunc = func(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
		return []pkcs11.ObjectHandle{1}, true, nil
	}
	_, err = findObject(ctx, 0, nil)
	test.AssertError(t, err, "findObject didn't fail when FindObjects returns multiple handles")

	// test findObject fails when FindObjectsFinal fails
	ctx.FindObjectsFunc = func(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
		return []pkcs11.ObjectHandle{1}, false, nil
	}
	ctx.FindObjectsFinalFunc = func(pkcs11.SessionHandle) error {
		return errors.New("broken")
	}
	_, err = findObject(ctx, 0, nil)
	test.AssertError(t, err, "findObject didn't fail when FindObjectsFinal fails")

	// test findObject works
	ctx.FindObjectsFinalFunc = func(pkcs11.SessionHandle) error {
		return nil
	}
	handle, err := findObject(ctx, 0, nil)
	test.AssertNotError(t, err, "findObject failed when everything worked as expected")
	test.AssertEquals(t, handle, pkcs11.ObjectHandle(1))
}

func TestGetKey(t *testing.T) {
	ctx := pkcs11helpers.MockCtx{}

	// test getKey fails when findObject for private key handle fails
	ctx.FindObjectsInitFunc = func(pkcs11.SessionHandle, []*pkcs11.Attribute) error {
		return errors.New("broken")
	}
	_, err := getKey(ctx, 0, "label", []byte{255, 255})
	test.AssertError(t, err, "getKey didn't fail when findObject for private key handle failed")

	// test getKey fails when GetAttributeValue fails
	ctx.FindObjectsInitFunc = func(pkcs11.SessionHandle, []*pkcs11.Attribute) error {
		return nil
	}
	ctx.FindObjectsFunc = func(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
		return []pkcs11.ObjectHandle{1}, false, nil
	}
	ctx.FindObjectsFinalFunc = func(pkcs11.SessionHandle) error {
		return nil
	}
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return nil, errors.New("broken")
	}
	_, err = getKey(ctx, 0, "label", []byte{255, 255})
	test.AssertError(t, err, "getKey didn't fail when GetAttributeValue for private key type failed")

	// test getKey fails when GetAttributeValue returns no attributes
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return nil, nil
	}
	_, err = getKey(ctx, 0, "label", []byte{255, 255})
	test.AssertError(t, err, "getKey didn't fail when GetAttributeValue for private key type returned no attributes")

	// test getKey fails when findObject for public key handle fails
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC)}, nil
	}
	ctx.FindObjectsInitFunc = func(_ pkcs11.SessionHandle, tmpl []*pkcs11.Attribute) error {
		if bytes.Compare(tmpl[0].Value, []byte{2, 0, 0, 0, 0, 0, 0, 0}) == 0 {
			return errors.New("broken")
		}
		return nil
	}
	_, err = getKey(ctx, 0, "label", []byte{255, 255})
	test.AssertError(t, err, "getKey didn't fail when findObject for public key handle failed")

	// test getKey fails when findObject for private key returns unknown CKA_KEY_TYPE
	ctx.FindObjectsInitFunc = func(_ pkcs11.SessionHandle, tmpl []*pkcs11.Attribute) error {
		return nil
	}
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, []byte{2, 0, 0, 0, 0, 0, 0, 0})}, nil
	}
	_, err = getKey(ctx, 0, "label", []byte{255, 255})
	test.AssertError(t, err, "getKey didn't fail when GetAttributeValue for private key returned unknown key type")

	// test getKey fails when GetRSAPublicKey fails
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, []byte{0, 0, 0, 0, 0, 0, 0, 0})}, nil
	}
	_, err = getKey(ctx, 0, "label", []byte{255, 255})
	test.AssertError(t, err, "getKey didn't fail when GetRSAPublicKey fails")

	// test getKey fails when GetECDSAPublicKey fails
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, []byte{3, 0, 0, 0, 0, 0, 0, 0})}, nil
	}
	_, err = getKey(ctx, 0, "label", []byte{255, 255})
	test.AssertError(t, err, "getKey didn't fail when GetECDSAPublicKey fails")

	// test getKey works when everything... works
	ctx.GetAttributeValueFunc = func(_ pkcs11.SessionHandle, _ pkcs11.ObjectHandle, attrs []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		var returns []*pkcs11.Attribute
		for _, attr := range attrs {
			switch attr.Type {
			case pkcs11.CKA_KEY_TYPE:
				returns = append(returns, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, []byte{0, 0, 0, 0, 0, 0, 0, 0}))
			case pkcs11.CKA_PUBLIC_EXPONENT:
				returns = append(returns, pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 2, 3}))
			case pkcs11.CKA_MODULUS:
				returns = append(returns, pkcs11.NewAttribute(pkcs11.CKA_MODULUS, []byte{4, 5, 6}))
			default:
				return nil, errors.New("GetAttributeValue got unexpected attribute type")
			}
		}
		return returns, nil
	}
	_, err = getKey(ctx, 0, "label", []byte{255, 255})
	test.AssertNotError(t, err, "getKey failed when everything worked properly")
}

func TestGenerateKey(t *testing.T) {
	tmp, err := ioutil.TempDir("", "ceremony-testing")
	test.AssertNotError(t, err, "Failed to create temporary directory")
	defer os.RemoveAll(tmp)

	ctx := pkcs11helpers.MockCtx{}
	ctx.GenerateKeyPairFunc = func(pkcs11.SessionHandle, []*pkcs11.Mechanism, []*pkcs11.Attribute, []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
		return 0, 0, nil
	}
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, []byte{217, 226, 207, 73, 127, 217, 136, 48, 203, 2, 12, 223, 251, 130, 143, 118, 13, 186, 82, 183, 220, 178, 158, 204, 19, 255, 121, 75, 243, 84, 118, 40, 128, 29, 11, 245, 43, 246, 217, 244, 166, 208, 36, 59, 69, 34, 142, 40, 22, 230, 195, 193, 111, 202, 186, 174, 233, 175, 140, 74, 19, 135, 191, 82, 27, 41, 123, 157, 174, 219, 38, 71, 19, 138, 28, 41, 48, 52, 142, 234, 196, 242, 51, 90, 204, 10, 235, 88, 150, 156, 89, 156, 199, 152, 173, 251, 88, 67, 138, 147, 86, 190, 236, 107, 190, 169, 53, 160, 219, 71, 147, 247, 230, 24, 188, 44, 61, 92, 106, 254, 125, 145, 233, 211, 76, 13, 159, 167}),
		}, nil
	}
	ctx.SignInitFunc = func(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
		return nil
	}
	ctx.GenerateRandomFunc = func(pkcs11.SessionHandle, int) ([]byte, error) {
		return []byte{1, 2, 3}, nil
	}
	ctx.SignFunc = func(pkcs11.SessionHandle, []byte) ([]byte, error) {
		return []byte{182, 42, 17, 237, 215, 151, 23, 254, 234, 219, 10, 119, 178, 76, 204, 254, 235, 67, 135, 83, 97, 134, 117, 38, 68, 115, 190, 250, 69, 200, 138, 225, 5, 188, 175, 45, 32, 179, 239, 145, 13, 168, 119, 75, 11, 171, 161, 220, 39, 185, 249, 87, 226, 132, 237, 82, 246, 187, 26, 232, 69, 86, 29, 12, 233, 8, 252, 59, 24, 194, 173, 74, 191, 101, 249, 108, 195, 240, 100, 28, 241, 70, 78, 236, 9, 136, 130, 218, 245, 195, 128, 80, 253, 42, 82, 99, 200, 115, 14, 75, 218, 176, 94, 98, 7, 226, 110, 24, 187, 108, 42, 144, 238, 244, 114, 153, 125, 3, 248, 129, 159, 51, 91, 26, 177, 118, 250, 79}, nil
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

	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte{4, 71, 137, 101, 56, 44, 59, 172, 148, 152, 118, 61, 183, 215, 242, 168, 62, 77, 94, 246, 212, 164, 96, 210, 134, 87, 169, 142, 226, 189, 118, 137, 203, 117, 55, 2, 215, 177, 159, 42, 196, 33, 91, 92, 251, 98, 53, 137, 221, 167, 148, 25, 209, 1, 5, 90, 52, 43, 18, 7, 30, 33, 142, 228, 235}),
		}, nil
	}
	ctx.SignFunc = func(pkcs11.SessionHandle, []byte) ([]byte, error) {
		return []byte{82, 33, 179, 118, 118, 141, 38, 154, 5, 20, 207, 140, 127, 221, 237, 139, 222, 74, 189, 107, 84, 133, 127, 80, 226, 169, 25, 110, 141, 226, 196, 69, 202, 51, 204, 77, 22, 198, 104, 91, 74, 120, 221, 156, 122, 11, 43, 54, 106, 10, 165, 202, 229, 71, 44, 18, 113, 236, 213, 47, 208, 239, 198, 33}, nil
	}
	keyPath = path.Join(tmp, "test-ecdsa-key.pem")
	keyInfo, err = generateKey(ctx, 0, "", keyPath, keyGenConfig{
		Type:       "ecdsa",
		ECDSACurve: "P-256",
	})
	test.AssertNotError(t, err, "Failed to generate RSA key")
	diskKeyBytes, err = ioutil.ReadFile(keyPath)
	test.AssertNotError(t, err, "Failed to load key from disk")
	block, _ = pem.Decode(diskKeyBytes)
	diskKey, err = x509.ParsePKIXPublicKey(block.Bytes)
	test.AssertNotError(t, err, "Failed to parse disk key")
	test.AssertDeepEquals(t, diskKey, keyInfo.key)
}
