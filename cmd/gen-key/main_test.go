package main

import "github.com/miekg/pkcs11"

type mockCtx struct {
	GenerateKeyPairFunc   func(pkcs11.SessionHandle, []*pkcs11.Mechanism, []*pkcs11.Attribute, []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error)
	GetAttributeValueFunc func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error)
	SignInitFunc          func(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error
	SignFunc              func(pkcs11.SessionHandle, []byte) ([]byte, error)
	GenerateRandomFunc    func(pkcs11.SessionHandle, int) ([]byte, error)
	FindObjectsInitFunc   func(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error
	FindObjectsFunc       func(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error)
	FindObjectsFinalFunc  func(sh pkcs11.SessionHandle) error
}

func (mc mockCtx) GenerateKeyPair(s pkcs11.SessionHandle, m []*pkcs11.Mechanism, a1 []*pkcs11.Attribute, a2 []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	return mc.GenerateKeyPairFunc(s, m, a1, a2)
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

func (mc mockCtx) FindObjectsInit(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error {
	return mc.FindObjectsInitFunc(sh, temp)
}

func (mc mockCtx) FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error) {
	return mc.FindObjectsFunc(sh, max)
}

func (mc mockCtx) FindObjectsFinal(sh pkcs11.SessionHandle) error {
	return mc.FindObjectsFinalFunc(sh)
}
