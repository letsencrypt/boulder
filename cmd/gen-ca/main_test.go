package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"

	"github.com/letsencrypt/boulder/pkcs11helpers"
	"github.com/letsencrypt/boulder/test"
	"github.com/miekg/pkcs11"
)

func TestX509Signer(t *testing.T) {
	// Test that x509Signer.Sign properly converts the PKCS#11 format signature to
	// the RFC 5480 format signature
	ctx := pkcs11helpers.MockCtx{}
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
	signer := &x509Signer{ctx: ctx, keyType: pkcs11helpers.ECDSAKey, pub: tk.Public()}
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

	// test getKey fails with invalid key ID
	_, err := getKey(ctx, 0, "label", "not hex")
	test.AssertError(t, err, "getKey didn't fail with invalid key ID")

	// test getKey fails when findObject for private key handle fails
	ctx.FindObjectsInitFunc = func(pkcs11.SessionHandle, []*pkcs11.Attribute) error {
		return errors.New("broken")
	}
	_, err = getKey(ctx, 0, "label", "ffff")
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
	_, err = getKey(ctx, 0, "label", "ffff")
	test.AssertError(t, err, "getKey didn't fail when GetAttributeValue for private key type failed")

	// test getKey fails when GetAttributeValue returns no attributes
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return nil, nil
	}
	_, err = getKey(ctx, 0, "label", "ffff")
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
	_, err = getKey(ctx, 0, "label", "ffff")
	test.AssertError(t, err, "getKey didn't fail when findObject for public key handle failed")

	// test getKey fails when findObject for private key returns unknown CKA_KEY_TYPE
	ctx.FindObjectsInitFunc = func(_ pkcs11.SessionHandle, tmpl []*pkcs11.Attribute) error {
		return nil
	}
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, []byte{2, 0, 0, 0, 0, 0, 0, 0})}, nil
	}
	_, err = getKey(ctx, 0, "label", "ffff")
	test.AssertError(t, err, "getKey didn't fail when GetAttributeValue for private key returned unknown key type")

	// test getKey fails when GetRSAPublicKey fails

	// test getKey fails when GetECDSAPublicKey fails
}

func TestParseOID(t *testing.T) {

}

func TestConstructCert(t *testing.T) {

}
