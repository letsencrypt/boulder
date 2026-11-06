package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/pkcs11"

	"github.com/letsencrypt/boulder/pkcs11helpers"
	"github.com/letsencrypt/boulder/test"
)

func setupCtx() pkcs11helpers.MockCtx {
	return pkcs11helpers.MockCtx{
		GenerateKeyPairFunc: func(pkcs11.SessionHandle, []*pkcs11.Mechanism, []*pkcs11.Attribute, []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
			return 0, 0, nil
		},
		SignInitFunc: func(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
			return nil
		},
		GenerateRandomFunc: func(pkcs11.SessionHandle, int) ([]byte, error) {
			return []byte{1, 2, 3}, nil
		},
		FindObjectsInitFunc: func(pkcs11.SessionHandle, []*pkcs11.Attribute) error {
			return nil
		},
		FindObjectsFunc: func(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
			return nil, false, nil
		},
		FindObjectsFinalFunc: func(pkcs11.SessionHandle) error {
			return nil
		},
	}
}

func TestGenerateKeyRSA(t *testing.T) {
	tmp := t.TempDir()

	ctx := setupCtx()
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 1024)
	test.AssertNotError(t, err, "Failed to generate a test RSA key")
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(rsaPriv.E)).Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, rsaPriv.N.Bytes()),
		}, nil
	}
	ctx.SignFunc = func(_ pkcs11.SessionHandle, msg []byte) ([]byte, error) {
		// Chop of the hash identifier and feed back into rsa.SignPKCS1v15
		return rsa.SignPKCS1v15(rand.Reader, rsaPriv, crypto.SHA256, msg[19:])
	}
	s := &pkcs11helpers.Session{Module: &ctx, Session: 0}
	keyPath := path.Join(tmp, "test-rsa-key.pem")
	keyInfo, err := generateKey(s, "", keyPath, keyGenConfig{
		Type:         "rsa",
		RSAModLength: 1024,
	})
	test.AssertNotError(t, err, "Failed to generate RSA key")
	diskKeyBytes, err := os.ReadFile(keyPath)
	test.AssertNotError(t, err, "Failed to load key from disk")
	block, _ := pem.Decode(diskKeyBytes)
	diskKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	test.AssertNotError(t, err, "Failed to parse disk key")
	test.AssertDeepEquals(t, diskKey, keyInfo.key)
}

func setECGenerateFuncs(ctx *pkcs11helpers.MockCtx) {
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	ctx.GetAttributeValueFunc = func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
		return []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, elliptic.Marshal(elliptic.P256(), ecPriv.X, ecPriv.Y)),
		}, nil
	}
	ctx.SignFunc = func(_ pkcs11.SessionHandle, msg []byte) ([]byte, error) {
		return ecPKCS11Sign(ecPriv, msg)
	}
}

func TestGenerateKeyEC(t *testing.T) {
	tmp := t.TempDir()

	ctx := setupCtx()
	setECGenerateFuncs(&ctx)
	keyPath := path.Join(tmp, "test-ecdsa-key.pem")
	s := &pkcs11helpers.Session{Module: &ctx, Session: 0}
	keyInfo, err := generateKey(s, "", keyPath, keyGenConfig{
		Type:       "ecdsa",
		ECDSACurve: "P-256",
	})
	test.AssertNotError(t, err, "Failed to generate ECDSA key")
	diskKeyBytes, err := os.ReadFile(keyPath)
	test.AssertNotError(t, err, "Failed to load key from disk")
	block, _ := pem.Decode(diskKeyBytes)
	diskKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	test.AssertNotError(t, err, "Failed to parse disk key")
	test.AssertDeepEquals(t, diskKey, keyInfo.key)
}

// fmtAttrs formats attrs as their types and values, for test failure messages.
func fmtAttrs(attrs []*pkcs11.Attribute) string {
	var parts []string
	for _, a := range attrs {
		parts = append(parts, fmt.Sprintf("%#x=%x", a.Type, a.Value))
	}
	return "[" + strings.Join(parts, " ") + "]"
}

// fakeKeyGen is a keyGenerator which returns fixed values.
type fakeKeyGen struct {
	pub crypto.PublicKey
	err error
}

func (f fakeKeyGen) mechanism() uint {
	return pkcs11.CKM_VENDOR_DEFINED
}

func (f fakeKeyGen) publicAttrs() []*pkcs11.Attribute {
	return []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VENDOR_DEFINED, "fake")}
}

func (f fakeKeyGen) publicKey(*pkcs11helpers.Session, pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	return f.pub, f.err
}

func TestGenerateKeyPair(t *testing.T) {
	keyID := []byte{0xa, 0xb, 0xc, 0xd}
	ctx := setupCtx()
	ctx.GenerateRandomFunc = func(pkcs11.SessionHandle, int) ([]byte, error) {
		return keyID, nil
	}
	var gotMechs []*pkcs11.Mechanism
	var gotPubTmpl, gotPrivTmpl []*pkcs11.Attribute
	ctx.GenerateKeyPairFunc = func(_ pkcs11.SessionHandle, mechs []*pkcs11.Mechanism, pubTmpl []*pkcs11.Attribute, privTmpl []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
		gotMechs = mechs
		gotPubTmpl = pubTmpl
		gotPrivTmpl = privTmpl
		return 0, 0, nil
	}
	s := &pkcs11helpers.Session{Module: &ctx, Session: 0}
	wantPub := &rsa.PublicKey{N: big.NewInt(1337), E: 65537}

	gotPub, gotKeyID, err := generateKeyPair(s, "label", fakeKeyGen{pub: wantPub})
	if err != nil {
		t.Fatalf("generateKeyPair() = %v, want success", err)
	}
	if gotPub != wantPub {
		t.Errorf("generateKeyPair() returned key %v, want the keyGenerator's %v", gotPub, wantPub)
	}
	if !slices.Equal(gotKeyID, keyID) {
		t.Errorf("generateKeyPair() returned key ID %x, want %x", gotKeyID, keyID)
	}

	wantMechs := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_VENDOR_DEFINED, nil)}
	if !reflect.DeepEqual(gotMechs, wantMechs) {
		t.Errorf("GenerateKeyPair got mechanisms %v, want %v", gotMechs, wantMechs)
	}
	// The public template is the common attributes followed by the
	// keyGenerator's attributes.
	wantPubTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "label"),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_VENDOR_DEFINED, "fake"),
	}
	if !reflect.DeepEqual(gotPubTmpl, wantPubTmpl) {
		t.Errorf("GenerateKeyPair got public template %s, want %s", fmtAttrs(gotPubTmpl), fmtAttrs(wantPubTmpl))
	}
	wantPrivTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "label"),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
	}
	if !reflect.DeepEqual(gotPrivTmpl, wantPrivTmpl) {
		t.Errorf("GenerateKeyPair got private template %s, want %s", fmtAttrs(gotPrivTmpl), fmtAttrs(wantPrivTmpl))
	}

	// When the keyGenerator fails to retrieve the public key, generateKeyPair
	// fails and returns a nil key, even if the keyGenerator returned a typed
	// nil pointer.
	gotPub, _, err = generateKeyPair(s, "label", fakeKeyGen{pub: (*rsa.PublicKey)(nil), err: errors.New("publicKey broke")})
	if err == nil || !strings.Contains(err.Error(), "publicKey broke") {
		t.Errorf("generateKeyPair() = %v, want publicKey error", err)
	}
	if gotPub != nil {
		t.Errorf("generateKeyPair() returned key %#v alongside error, want nil", gotPub)
	}
}

func setFindObjectsFuncs(label string, ctx *pkcs11helpers.MockCtx) {
	var objectsFound []pkcs11.ObjectHandle
	ctx.FindObjectsInitFunc = func(_ pkcs11.SessionHandle, template []*pkcs11.Attribute) error {
		for _, attr := range template {
			if attr.Type == pkcs11.CKA_LABEL && string(attr.Value) == label {
				objectsFound = []pkcs11.ObjectHandle{1}
			}
		}
		return nil
	}
	ctx.FindObjectsFunc = func(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
		return objectsFound, false, nil
	}
	ctx.FindObjectsFinalFunc = func(pkcs11.SessionHandle) error {
		objectsFound = nil
		return nil
	}
}

func TestGenerateKeySlotHasSomethingWithLabel(t *testing.T) {
	tmp := t.TempDir()

	ctx := setupCtx()
	label := "someLabel"
	setFindObjectsFuncs(label, &ctx)
	keyPath := path.Join(tmp, "should-not-exist.pem")
	s := &pkcs11helpers.Session{Module: &ctx, Session: 0}
	_, err := generateKey(s, label, keyPath, keyGenConfig{
		Type:       "ecdsa",
		ECDSACurve: "P-256",
	})
	test.AssertError(t, err, "expected failure for a slot with an object already in it")
	test.Assert(t, strings.HasPrefix(err.Error(), "expected no preexisting objects with label"), "wrong error")
}

func TestGenerateKeySlotHasSomethingWithDifferentLabel(t *testing.T) {
	tmp := t.TempDir()

	ctx := setupCtx()
	setECGenerateFuncs(&ctx)
	setFindObjectsFuncs("someLabel", &ctx)
	keyPath := path.Join(tmp, "should-not-exist.pem")
	s := &pkcs11helpers.Session{Module: &ctx, Session: 0}
	_, err := generateKey(s, "someOtherLabel", keyPath, keyGenConfig{
		Type:       "ecdsa",
		ECDSACurve: "P-256",
	})
	test.AssertNotError(t, err, "expected success even though there was an object with a different label")
}
