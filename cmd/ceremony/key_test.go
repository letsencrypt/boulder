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
	path := path.Join(tmp, "test-rsa-key.pem")
	keyInfo, err := generateKey(ctx, 0, "", path, keyGenConfig{
		Type:         "rsa",
		RSAModLength: 512,
	})
	test.AssertNotError(t, err, "Failed to generate RSA key")
	diskKeyBytes, err := ioutil.ReadFile(path)
	test.AssertNotError(t, err, "Failed to load key from disk")
	block, _ := pem.Decode(diskKeyBytes)
	diskKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	test.AssertNotError(t, err, "Failed to parse disk key")
	test.AssertDeepEquals(t, diskKey, keyInfo.key)
}
