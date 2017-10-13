// This package wraps `miekg/pkcs11` to make it easier to use and more idiomatic
// to Go, as compared with the more straightforward C wrapper that
// `miekg/pkcs11` presents.
// Session and Object types are safe to use concurrently.
package p11ez

import (
	"errors"
	"sync"

	"github.com/miekg/pkcs11"
)

type Session struct {
	sync.Mutex
	ctx    *pkcs11.Ctx
	handle pkcs11.SessionHandle
}

type Object struct {
	session      *Session
	objectHandle pkcs11.ObjectHandle
}

type sessionType uint

const (
	ReadWrite sessionType = pkcs11.CKF_RW_SESSION
	ReadOnly  sessionType = 0
)

func NewSession(ctx *pkcs11.Ctx, slotID uint, sessType sessionType) (*Session, error) {
	// CKF_SERIAL_SESSION is always mandatory for legacy reasons, per PKCS#11.
	handle, err := ctx.OpenSession(slotID, uint(sessType)|pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, err
	}
	return &Session{
		ctx:    ctx,
		handle: handle,
	}, nil
}

func (s *Session) Close() error {
	s.Lock()
	defer s.Unlock()
	return s.ctx.CloseSession(s.handle)
}

func (s *Session) Login(userType uint, pin string) error {
	s.Lock()
	defer s.Unlock()
	return s.ctx.Login(s.handle, userType, pin)
}

func (s *Session) Logout() error {
	s.Lock()
	defer s.Unlock()
	return s.ctx.Logout(s.handle)
}

func (s *Session) GenerateRandom(length int) ([]byte, error) {
	s.Lock()
	defer s.Unlock()
	return s.ctx.GenerateRandom(s.handle, length)
}

// FindObject finds an object in the PKCS#11 token according to a template. It
// returns error if there is not exactly one result, or if there was an error
// during the find calls.
func (s *Session) FindObject(template []*pkcs11.Attribute) (Object, error) {
	s.Lock()
	defer s.Unlock()
	if err := s.ctx.FindObjectsInit(s.handle, template); err != nil {
		return Object{}, err
	}

	objectHandles, moreAvailable, err := s.ctx.FindObjects(s.handle, 1)
	if err != nil {
		return Object{}, err
	}
	if moreAvailable {
		return Object{}, errors.New("too many objects returned from FindObjects")
	}
	if err = s.ctx.FindObjectsFinal(s.handle); err != nil {
		return Object{}, err
	} else if len(objectHandles) == 0 {
		return Object{}, errors.New("no objects found")
	}
	return Object{
		session:      s,
		objectHandle: objectHandles[0],
	}, nil
}

// GetAttributeValue gets exactly one attribute from a PKCS#11 object, returning
// an error if the attribute is not found, or if multiple attributes are
// returned. On success, it will return the value of that attribute as a slice
// of bytes.
func (o Object) GetAttributeValue(attributeType uint) ([]byte, error) {
	o.session.Lock()
	defer o.session.Unlock()

	attrs, err := o.session.ctx.GetAttributeValue(o.session.handle, o.objectHandle,
		[]*pkcs11.Attribute{pkcs11.NewAttribute(attributeType, nil)})
	if err != nil {
		return nil, err
	}
	if len(attrs) == 0 {
		return nil, errors.New("attribute not found")
	}
	if len(attrs) > 1 {
		return nil, errors.New("too many attributes found")
	}
	return attrs[0].Value, nil
}
