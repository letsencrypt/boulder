package pkcs11helpers

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

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

func GetRSAPublicKey(ctx PKCtx, session pkcs11.SessionHandle, object pkcs11.ObjectHandle) (*rsa.PublicKey, error) {
	// Retrieve the public exponent and modulus for the public key
	attrs, err := ctx.GetAttributeValue(session, object, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve key attributes: %s", err)
	}

	// Attempt to build the public key from the retrieved attributes
	pubKey := &rsa.PublicKey{}
	gotMod, gotExp := false, false
	for _, a := range attrs {
		switch a.Type {
		case pkcs11.CKA_PUBLIC_EXPONENT:
			pubKey.E = int(big.NewInt(0).SetBytes(a.Value).Int64())
			gotExp = true
		case pkcs11.CKA_MODULUS:
			pubKey.N = big.NewInt(0).SetBytes(a.Value)
			gotMod = true
		}
	}
	// Fail if we are missing either the public exponent or modulus
	if !gotExp || !gotMod {
		return nil, errors.New("Couldn't retrieve modulus and exponent")
	}
	return pubKey, nil
}

// oidDERToCurve maps the hex of the DER encoding of the various curve OIDs to
// the relevant curve parameters
var oidDERToCurve = map[string]*elliptic.CurveParams{
	"06052B81040021":       elliptic.P224().Params(),
	"06082A8648CE3D030107": elliptic.P256().Params(),
	"06052B81040022":       elliptic.P384().Params(),
	"06052B81040023":       elliptic.P521().Params(),
}

func GetECDSAPublicKey(ctx PKCtx, session pkcs11.SessionHandle, object pkcs11.ObjectHandle) (*ecdsa.PublicKey, error) {
	// Retrieve the curve and public point for the generated public key
	attrs, err := ctx.GetAttributeValue(session, object, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve key attributes: %s", err)
	}

	pubKey := &ecdsa.PublicKey{}
	var pointBytes []byte
	for _, a := range attrs {
		switch a.Type {
		case pkcs11.CKA_EC_PARAMS:
			rCurve, present := oidDERToCurve[fmt.Sprintf("%X", a.Value)]
			if !present {
				return nil, errors.New("Unknown curve OID value returned")
			}
			pubKey.Curve = rCurve
		case pkcs11.CKA_EC_POINT:
			pointBytes = a.Value
		}
	}
	if pointBytes == nil || pubKey.Curve == nil {
		return nil, errors.New("Couldn't retrieve EC point and EC parameters")
	}

	x, y := elliptic.Unmarshal(pubKey.Curve, pointBytes)
	if x == nil {
		// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html#_ftn1
		// PKCS#11 v2.20 specified that the CKA_EC_POINT was to be stored in a DER-encoded
		// OCTET STRING.
		var point asn1.RawValue
		_, err = asn1.Unmarshal(pointBytes, &point)
		if err != nil {
			return nil, fmt.Errorf("Failed to unmarshal returned CKA_EC_POINT: %s", err)
		}
		if len(point.Bytes) == 0 {
			return nil, errors.New("Invalid CKA_EC_POINT value returned, OCTET string is empty")
		}
		x, y = elliptic.Unmarshal(pubKey.Curve, point.Bytes)
		if x == nil {
			return nil, errors.New("Invalid CKA_EC_POINT value returned, point is malformed")
		}
	}
	pubKey.X, pubKey.Y = x, y

	return pubKey, nil
}

type KeyType int

const (
	RSAKey KeyType = iota
	ECDSAKey
)

// Hash identifiers required for PKCS#11 RSA signing. Only support SHA-256, SHA-384,
// and SHA-512
var hashIdentifiers = map[crypto.Hash][]byte{
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

func Sign(ctx PKCtx, session pkcs11.SessionHandle, object pkcs11.ObjectHandle, keyType KeyType, digest []byte, hash crypto.Hash) ([]byte, error) {
	if len(digest) != hash.Size() {
		return nil, errors.New("digest length doesn't match hash length")
	}

	mech := make([]*pkcs11.Mechanism, 1)
	switch keyType {
	case RSAKey:
		mech[0] = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)
		prefix, ok := hashIdentifiers[hash]
		if !ok {
			return nil, errors.New("unsupported hash function")
		}
		digest = append(prefix, digest...)
	case ECDSAKey:
		mech[0] = pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)
	}

	err := ctx.SignInit(session, mech, object)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize signing operation: %s", err)
	}
	signature, err := ctx.Sign(session, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %s", err)
	}

	return signature, nil
}

type MockCtx struct {
	GenerateKeyPairFunc   func(pkcs11.SessionHandle, []*pkcs11.Mechanism, []*pkcs11.Attribute, []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error)
	GetAttributeValueFunc func(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error)
	SignInitFunc          func(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error
	SignFunc              func(pkcs11.SessionHandle, []byte) ([]byte, error)
	GenerateRandomFunc    func(pkcs11.SessionHandle, int) ([]byte, error)
	FindObjectsInitFunc   func(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error
	FindObjectsFunc       func(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error)
	FindObjectsFinalFunc  func(sh pkcs11.SessionHandle) error
}

func (mc MockCtx) GenerateKeyPair(s pkcs11.SessionHandle, m []*pkcs11.Mechanism, a1 []*pkcs11.Attribute, a2 []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	return mc.GenerateKeyPairFunc(s, m, a1, a2)
}

func (mc MockCtx) GetAttributeValue(s pkcs11.SessionHandle, o pkcs11.ObjectHandle, a []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	return mc.GetAttributeValueFunc(s, o, a)
}

func (mc MockCtx) SignInit(s pkcs11.SessionHandle, m []*pkcs11.Mechanism, o pkcs11.ObjectHandle) error {
	return mc.SignInitFunc(s, m, o)
}

func (mc MockCtx) Sign(s pkcs11.SessionHandle, m []byte) ([]byte, error) {
	return mc.SignFunc(s, m)
}

func (mc MockCtx) GenerateRandom(s pkcs11.SessionHandle, c int) ([]byte, error) {
	return mc.GenerateRandomFunc(s, c)
}

func (mc MockCtx) FindObjectsInit(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error {
	return mc.FindObjectsInitFunc(sh, temp)
}

func (mc MockCtx) FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error) {
	return mc.FindObjectsFunc(sh, max)
}

func (mc MockCtx) FindObjectsFinal(sh pkcs11.SessionHandle) error {
	return mc.FindObjectsFinalFunc(sh)
}

// X509Signer is a convenience wrapper used for converting between the
// PKCS#11 ECDSA signature format and the RFC 5480 one which is required
// for X.509 certificates
type X509Signer struct {
	ctx PKCtx

	session      pkcs11.SessionHandle
	objectHandle pkcs11.ObjectHandle
	keyType      KeyType

	pub crypto.PublicKey
}

// NewX509Signer constructs a X509Signer.
func NewX509Signer(ctx PKCtx, session pkcs11.SessionHandle, object pkcs11.ObjectHandle, kType KeyType, pub crypto.PublicKey) *X509Signer {
	return &X509Signer{
		ctx:          ctx,
		session:      session,
		objectHandle: object,
		keyType:      kType,
		pub:          pub,
	}
}

// Sign wraps Sign. If the signing key is ECDSA then the signature
// is converted from the PKCS#11 format to the RFC 5480 format. For RSA keys a
// conversion step is not needed.
func (p *X509Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signature, err := Sign(p.ctx, p.session, p.objectHandle, p.keyType, digest, opts.HashFunc())
	if err != nil {
		return nil, err
	}

	if p.keyType == ECDSAKey {
		// Convert from the PKCS#11 format to the RFC 5480 format so that
		// it can be used in a X.509 certificate
		r := big.NewInt(0).SetBytes(signature[:len(signature)/2])
		s := big.NewInt(0).SetBytes(signature[len(signature)/2:])
		signature, err = asn1.Marshal(struct {
			R, S *big.Int
		}{R: r, S: s})
		if err != nil {
			return nil, fmt.Errorf("failed to convert signature to RFC 5480 format: %s", err)
		}
	}
	return signature, nil
}

func (p *X509Signer) Public() crypto.PublicKey {
	return p.pub
}

// findObject looks up a PKCS#11 object handle based on the provided template.
// In the case where zero or more than one objects are found to match the
// template an error is returned.
func findObject(ctx PKCtx, session pkcs11.SessionHandle, tmpl []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	if err := ctx.FindObjectsInit(session, tmpl); err != nil {
		return 0, err
	}
	handles, more, err := ctx.FindObjects(session, 1)
	if err != nil {
		return 0, err
	}
	if len(handles) == 0 {
		return 0, errors.New("no objects found matching provided template")
	}
	if more {
		return 0, errors.New("more than one object matches provided template")
	}
	if err := ctx.FindObjectsFinal(session); err != nil {
		return 0, err
	}
	return handles[0], nil
}

// GetKey constructs a X509Signer for the private key object associated with the
// given label and ID
func GetKey(ctx PKCtx, session pkcs11.SessionHandle, label string, idStr string) (*X509Signer, error) {
	id, err := hex.DecodeString(idStr)
	if err != nil {
		return nil, err
	}

	// Retrieve the private key handle that will later be used for the certificate
	// signing operation
	privateHandle, err := findObject(ctx, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve private key handle: %s", err)
	}
	attrs, err := ctx.GetAttributeValue(session, privateHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil)},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve key type: %s", err)
	}
	if len(attrs) == 0 {
		return nil, errors.New("failed to retrieve key attributes")
	}

	// Retrieve the public key handle with the same CKA_ID as the private key
	// and construct a {rsa,ecdsa}.PublicKey for use in x509.CreateCertificate
	pubHandle, err := findObject(ctx, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, attrs[0].Value),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve public key handle: %s", err)
	}
	var pub crypto.PublicKey
	var keyType KeyType
	switch {
	// 0x00000000, CKK_RSA
	case bytes.Compare(attrs[0].Value, []byte{0, 0, 0, 0, 0, 0, 0, 0}) == 0:
		keyType = RSAKey
		pub, err = GetRSAPublicKey(ctx, session, pubHandle)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve public key: %s", err)
		}
	// 0x00000003, CKK_ECDSA
	case bytes.Compare(attrs[0].Value, []byte{3, 0, 0, 0, 0, 0, 0, 0}) == 0:
		keyType = ECDSAKey
		pub, err = GetECDSAPublicKey(ctx, session, pubHandle)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve public key: %s", err)
		}
	default:
		return nil, errors.New("unsupported key type")
	}

	return NewX509Signer(ctx, session, privateHandle, keyType, pub), nil
}
