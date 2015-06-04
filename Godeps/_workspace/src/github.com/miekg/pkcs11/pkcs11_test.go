// Copyright 2013 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs11

// These tests depend on SoftHSM and the library being in
// in /usr/lib/softhsm/libsofthsm.so

import (
	"fmt"
	"math/big"
	"os"
	"testing"
)

func setenv(t *testing.T) *Ctx {
	wd, _ := os.Getwd()
	os.Setenv("SOFTHSM_CONF", wd+"/softhsm.conf")
	p := New("/usr/lib/softhsm/libsofthsm.so") //p := New("/home/miek/libsofthsm.so")
	if p == nil {
		t.Fatal("Failed to init lib")
	}
	return p
}

func getSession(p *Ctx, t *testing.T) SessionHandle {
	if e := p.Initialize(); e != nil {
		t.Fatalf("init error %s\n", e.Error())
	}
	slots, e := p.GetSlotList(true)
	if e != nil {
		t.Fatalf("slots %s\n", e.Error())
	}
	session, e := p.OpenSession(slots[0], CKF_SERIAL_SESSION)
	if e != nil {
		t.Fatalf("session %s\n", e.Error())
	}
	if e := p.Login(session, CKU_USER, "1234"); e != nil {
		t.Fatal("user pin %s\n", e.Error())
	}
	return session
}

func TestGetInfo(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer p.Logout(session)
	defer p.CloseSession(session)
	defer p.Finalize()
	defer p.Destroy()
	info, err := p.GetInfo()
	if err != nil {
		t.Fatalf("Non zero error %s\n", err.Error())
	}
	if info.ManufacturerID != "SoftHSM" {
		t.Fatal("ID should be SoftHSM")
	}
	t.Logf("%+v\n", info)
}

func TestFindObject(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer p.Logout(session)
	defer p.CloseSession(session)
	defer p.Finalize()
	defer p.Destroy()
	// There are 2 keys in the db with this tag
	template := []*Attribute{NewAttribute(CKA_LABEL, "MyFirstKey")}
	if e := p.FindObjectsInit(session, template); e != nil {
		t.Fatalf("Failed to init: %s\n", e.Error())
	}
	obj, b, e := p.FindObjects(session, 2)
	if e != nil {
		t.Fatalf("Failed to find: %s %v\n", e.Error(), b)
	}
	if e := p.FindObjectsFinal(session); e != nil {
		t.Fatalf("Failed to finalize: %s\n", e.Error())
	}
	if len(obj) != 2 {
		t.Fatal("should have found two objects")
	}
}

func TestGetAttributeValue(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer p.Logout(session)
	defer p.Destroy()
	defer p.Finalize()
	defer p.CloseSession(session)
	// There are at least two RSA keys in the hsm.db, objecthandle 1 and 2.
	template := []*Attribute{
		NewAttribute(CKA_PUBLIC_EXPONENT, nil),
		NewAttribute(CKA_MODULUS_BITS, nil),
		NewAttribute(CKA_MODULUS, nil),
		NewAttribute(CKA_LABEL, nil),
	}
	// ObjectHandle two is the public key
	attr, err := p.GetAttributeValue(session, ObjectHandle(2), template)
	if err != nil {
		t.Fatalf("err %s\n", err.Error())
	}
	for i, a := range attr {
		t.Logf("Attr %d, type %d, valuelen %d", i, a.Type, len(a.Value))
		if a.Type == CKA_MODULUS {
			mod := big.NewInt(0)
			mod.SetBytes(a.Value)
			t.Logf("Modulus %s\n", mod.String())
		}
	}
}

func TestDigest(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer p.Logout(session)
	defer p.CloseSession(session)
	defer p.Finalize()
	defer p.Destroy()
	e := p.DigestInit(session, []*Mechanism{NewMechanism(CKM_SHA_1, nil)})
	if e != nil {
		t.Fatalf("DigestInit: %s\n", e.Error())
	}

	hash, e := p.Digest(session, []byte("this is a string"))
	if e != nil {
		t.Fatalf("Digest: %s\n", e.Error())
	}
	hex := ""
	for _, d := range hash {
		hex += fmt.Sprintf("%x", d)
	}
	// Teststring create with: echo -n "this is a string" | sha1sum
	if hex != "517592df8fec3ad146a79a9af153db2a4d784ec5" {
		t.Fatalf("wrong digest: %s", hex)
	}
}

func TestDigestUpdate(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer p.Logout(session)
	defer p.CloseSession(session)
	defer p.Finalize()
	defer p.Destroy()
	if e := p.DigestInit(session, []*Mechanism{NewMechanism(CKM_SHA_1, nil)}); e != nil {
		t.Fatalf("DigestInit: %s\n", e.Error())
	}
	if e := p.DigestUpdate(session, []byte("this is ")); e != nil {
		t.Fatalf("DigestUpdate: %s\n", e.Error())
	}
	if e := p.DigestUpdate(session, []byte("a string")); e != nil {
		t.Fatalf("DigestUpdate: %s\n", e.Error())
	}
	hash, e := p.DigestFinal(session)
	if e != nil {
		t.Fatalf("DigestFinal: %s\n", e.Error())
	}
	hex := ""
	for _, d := range hash {
		hex += fmt.Sprintf("%x", d)
	}
	// Teststring create with: echo -n "this is a string" | sha1sum
	if hex != "517592df8fec3ad146a79a9af153db2a4d784ec5" {
		t.Fatalf("wrong digest: %s", hex)
	}

}

func testDestroyObject(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer p.Logout(session)
	defer p.CloseSession(session)
	defer p.Finalize()
	defer p.Destroy()

	p.Logout(session) // log out the normal user
	if e := p.Login(session, CKU_SO, "1234"); e != nil {
		t.Fatal("security officer pin %s\n", e.Error())
	}

	// Looking the int values is tricky because they are stored in 64 bits in hsm.db,
	// this means looking up stuff on 32 bits will not found them.
	template := []*Attribute{
		NewAttribute(CKA_LABEL, "MyFirstKey")}

	if e := p.FindObjectsInit(session, template); e != nil {
		t.Fatalf("Failed to init: %s\n", e.Error())
	}
	obj, _, e := p.FindObjects(session, 1)
	if e != nil || len(obj) == 0 {
		t.Fatalf("Failed to find objects\n")
	}
	if e := p.FindObjectsFinal(session); e != nil {
		t.Fatalf("Failed to finalize: %s\n", e.Error())
	}

	if err := p.DestroyObject(session, obj[0]); err != nil {
		t.Fatal("DestroyObject failed" + err.Error())
	}
}

// ExampleSign show how to sign some data with a private key.
// Note: error correction is not implemented in this function.
func ExampleSign() {
	p := setenv(nil)
	p.Initialize()
	defer p.Destroy()
	defer p.Finalize()
	slots, _ := p.GetSlotList(true)
	session, _ := p.OpenSession(slots[0], CKF_SERIAL_SESSION|CKF_RW_SESSION)
	defer p.CloseSession(session)
	p.Login(session, CKU_USER, "1234")
	defer p.Logout(session)
	publicKeyTemplate := []*Attribute{
		NewAttribute(CKA_KEY_TYPE, CKO_PUBLIC_KEY),
		NewAttribute(CKA_TOKEN, true),
		NewAttribute(CKA_ENCRYPT, true),
		NewAttribute(CKA_PUBLIC_EXPONENT, []byte{3}),
		NewAttribute(CKA_MODULUS_BITS, 1024),
		NewAttribute(CKA_LABEL, "MyFirstKey"),
	}
	privateKeyTemplate := []*Attribute{
		NewAttribute(CKA_KEY_TYPE, CKO_PRIVATE_KEY),
		NewAttribute(CKA_TOKEN, true),
		NewAttribute(CKA_PRIVATE, true),
		NewAttribute(CKA_SIGN, true),
		NewAttribute(CKA_LABEL, "MyFirstKey"),
	}
	pub, priv, _ := p.GenerateKeyPair(session,
		[]*Mechanism{NewMechanism(CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate, privateKeyTemplate)
	p.SignInit(session, []*Mechanism{NewMechanism(CKM_SHA1_RSA_PKCS, nil)}, priv)
	// Sign something with the private key.
	data := []byte("Lets sign this data")

	sig, _ := p.Sign(session, data)
	fmt.Printf("%v validate with %v\n", sig, pub)
}
