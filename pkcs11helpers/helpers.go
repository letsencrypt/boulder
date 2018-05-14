package pkcs11helpers

import (
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
)

type PKCtx interface {
	GenerateKeyPair(pkcs11.SessionHandle, []*pkcs11.Mechanism, []*pkcs11.Attribute, []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error)
	GetAttributeValue(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error)
	SignInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error
	Sign(pkcs11.SessionHandle, []byte) ([]byte, error)
	GenerateRandom(pkcs11.SessionHandle, int) ([]byte, error)
	FindObjectsInit(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error
	FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error)
	FindObjectsFinal(sh pkcs11.SessionHandle) error
}

func Initialize(module string, slot uint, pin string) (PKCtx, pkcs11.SessionHandle, error) {
	ctx := pkcs11.New(module)
	if ctx == nil {
		return nil, 0, errors.New("failed to load module")
	}
	err := ctx.Initialize()
	if err != nil {
		return nil, 0, fmt.Errorf("couldn't initialize context: %s", err)
	}

	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, 0, fmt.Errorf("couldn't open session: %s", err)
	}

	err = ctx.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		return nil, 0, fmt.Errorf("couldn't login: %s", err)
	}

	return ctx, session, nil
}

func GetRandomBytes(ctx PKCtx, session pkcs11.SessionHandle) ([]byte, error) {
	r, err := ctx.GenerateRandom(session, 4)
	if err != nil {
		return nil, err
	}
	return r, nil
}
