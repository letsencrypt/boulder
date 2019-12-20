// Package pkcs11key implements crypto.Signer for PKCS #11 private keys.
// See https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.pdf
// for details of the Cryptoki PKCS#11 API.
// See https://github.com/letsencrypt/pkcs11key/blob/master/test.sh for examples
// of how to test and/or benchmark.
package pkcs11key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/miekg/pkcs11"
)

// from src/pkg/crypto/rsa/pkcs1v15.go
var hashPKCS1Prefixes = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}

type pssParams struct {
	ckmHash uint // CKM constant for hash function
	ckgMGF  uint // CKG constant for mask generation function
}

var hashPSSParams = map[crypto.Hash]pssParams{
	crypto.SHA1:   {pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1},
	crypto.SHA224: {pkcs11.CKM_SHA224, pkcs11.CKG_MGF1_SHA224},
	crypto.SHA256: {pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256},
	crypto.SHA384: {pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384},
	crypto.SHA512: {pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512},
}

// from src/pkg/crypto/x509/x509.go
var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

var curveOIDs = map[string]asn1.ObjectIdentifier{
	"P-224": oidNamedCurveP224,
	"P-256": oidNamedCurveP256,
	"P-384": oidNamedCurveP384,
	"P-521": oidNamedCurveP521,
}

type rfc5480ECDSASignature struct {
	R, S *big.Int
}

// ctx defines the subset of pkcs11.ctx's methods that we use, so we can inject
// a different ctx for testing.
type ctx interface {
	CloseSession(sh pkcs11.SessionHandle) error
	FindObjectsFinal(sh pkcs11.SessionHandle) error
	FindObjectsInit(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error
	FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error)
	GetAttributeValue(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle, a []*pkcs11.Attribute) ([]*pkcs11.Attribute, error)
	GetSlotList(tokenPresent bool) ([]uint, error)
	GetTokenInfo(slotID uint) (pkcs11.TokenInfo, error)
	Initialize() error
	Login(sh pkcs11.SessionHandle, userType uint, pin string) error
	Logout(sh pkcs11.SessionHandle) error
	OpenSession(slotID uint, flags uint) (pkcs11.SessionHandle, error)
	SignInit(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, o pkcs11.ObjectHandle) error
	Sign(sh pkcs11.SessionHandle, message []byte) ([]byte, error)
}

// Key is an implementation of the crypto.Signer interface using a key stored
// in a PKCS#11 hardware token.  This enables the use of PKCS#11 tokens with
// the Go x509 library's methods for signing certificates.
//
// Each Key represents one session. Its session handle is protected internally
// by a mutex, so at most one Sign operation can be active at a time. For best
// performance you may want to instantiate multiple Keys using pkcs11key.Pool.
// Each one will have its own session and can be used concurrently. Note that
// some smartcards like the Yubikey Neo do not support multiple simultaneous
// sessions and will error out on creation of the second Key object.
//
// Note: If you instantiate multiple Keys without using Pool, it is *highly*
// recommended that you create all your Key objects serially, on your main
// thread, checking for errors each time, and then farm them out for use by
// different goroutines. If you fail to do this, your application may attempt
// to login repeatedly with an incorrect PIN, locking the PKCS#11 token.
type Key struct {
	// The PKCS#11 library to use
	module ctx

	// The label of the token to be used (mandatory).
	// We will automatically search for this in the slot list.
	tokenLabel string

	// The PIN to be used to log in to the device
	pin string

	// The public key corresponding to the private key.
	publicKey crypto.PublicKey

	// The an ObjectHandle pointing to the private key on the HSM.
	privateKeyHandle pkcs11.ObjectHandle

	// A handle to the session used by this Key.
	session   *pkcs11.SessionHandle
	sessionMu sync.Mutex

	// True if the private key has the CKA_ALWAYS_AUTHENTICATE attribute set.
	alwaysAuthenticate bool
}

var modules = make(map[string]ctx)
var modulesMu sync.Mutex

// initialize loads the given PKCS#11 module (shared library) if it is not
// already loaded. It's an error to load a PKCS#11 module multiple times, so we
// maintain a map of loaded modules. Note that there is no facility yet to
// unload a module ("finalize" in PKCS#11 parlance). In general, modules will
// be unloaded at the end of the process.  The only place where you are likely
// to need to explicitly unload a module is if you fork your process after a
// Key has already been created, and the child process also needs to use
// that module.
func initialize(modulePath string) (ctx, error) {
	modulesMu.Lock()
	defer modulesMu.Unlock()
	module, ok := modules[modulePath]
	if ok {
		return module, nil
	}

	newModule := pkcs11.New(modulePath)
	if newModule == nil {
		return nil, fmt.Errorf("failed to load module '%s'", modulePath)
	}

	err := newModule.Initialize()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize module: %s", err)
	}

	modules[modulePath] = ctx(newModule)

	return ctx(newModule), nil
}

// New instantiates a new handle to a PKCS #11-backed key.
func New(modulePath, tokenLabel, pin string, publicKey crypto.PublicKey) (*Key, error) {
	module, err := initialize(modulePath)
	if err != nil {
		return nil, fmt.Errorf("pkcs11key: %s", err)
	}
	if module == nil {
		err = fmt.Errorf("pkcs11key: nil module")
		return nil, err
	}

	// Initialize a partial key
	ps := &Key{
		module:     module,
		tokenLabel: tokenLabel,
		pin:        pin,
		publicKey:  publicKey,
	}

	err = ps.setup()
	if err != nil {
		return nil, fmt.Errorf("pkcs11key: %s", err)
	}
	return ps, nil
}

// findObject finds an object in the PKCS#11 token according to a template. It
// returns error if there is not exactly one result, or if there was an error
// during the find calls. It must be called with the ps.sessionMu lock held.
func (ps *Key) findObject(template []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	if err := ps.module.FindObjectsInit(*ps.session, template); err != nil {
		return 0, err
	}

	handles, moreAvailable, err := ps.module.FindObjects(*ps.session, 1)
	if err != nil {
		return 0, err
	}
	if moreAvailable {
		return 0, errors.New("too many objects returned from FindObjects")
	}
	if err = ps.module.FindObjectsFinal(*ps.session); err != nil {
		return 0, err
	} else if len(handles) == 0 {
		return 0, errors.New("no objects found")
	}
	return handles[0], nil
}

// getPublicKeyID looks up the given public key in the PKCS#11 token, and
// returns its ID as a []byte, for use in looking up the corresponding private
// key. It must be called with the ps.sessionMu lock held.
func (ps *Key) getPublicKeyID(publicKey crypto.PublicKey) ([]byte, error) {
	var template []*pkcs11.Attribute
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		template = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, key.N.Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(key.E)).Bytes()),
		}
	case *ecdsa.PublicKey:
		// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html#_ftn1
		// PKCS#11 v2.20 specified that the CKA_EC_POINT was to be store in a DER-encoded
		// OCTET STRING.
		rawValue := asn1.RawValue{
			Tag:   4, // in Go 1.6+ this is asn1.TagOctetString
			Bytes: elliptic.Marshal(key.Curve, key.X, key.Y),
		}
		marshalledPoint, err := asn1.Marshal(rawValue)
		if err != nil {
			return nil, err
		}
		curveOID, err := asn1.Marshal(curveOIDs[key.Curve.Params().Name])
		if err != nil {
			return nil, err
		}
		template = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, curveOID),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, marshalledPoint),
		}
	default:
		return nil, fmt.Errorf("unsupported public key of type %T", publicKey)
	}

	publicKeyHandle, err := ps.findObject(template)
	if err != nil {
		return nil, err
	}

	attrs, err := ps.module.GetAttributeValue(*ps.session, publicKeyHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
	})
	if err != nil {
		return nil, err
	}
	if len(attrs) > 0 && attrs[0].Type == pkcs11.CKA_ID {
		return attrs[0].Value, nil
	}
	return nil, fmt.Errorf("invalid result from GetAttributeValue")
}

func (ps *Key) setup() error {
	// Open a session
	ps.sessionMu.Lock()
	defer ps.sessionMu.Unlock()
	session, err := ps.openSession()
	if err != nil {
		return fmt.Errorf("pkcs11key: opening session: %s", err)
	}
	ps.session = &session

	publicKeyID, err := ps.getPublicKeyID(ps.publicKey)
	if err != nil {
		ps.module.CloseSession(session)
		return fmt.Errorf("looking up public key: %s", err)
	}

	// Fetch the private key by matching its id to the public key handle.
	privateKeyHandle, err := ps.getPrivateKey(ps.module, session, publicKeyID)
	if err != nil {
		ps.module.CloseSession(session)
		return fmt.Errorf("getting private key: %s", err)
	}
	ps.privateKeyHandle = privateKeyHandle
	return nil
}

// getPrivateKey gets a handle to the private key whose CKA_ID matches the
// provided publicKeyID. It must be called with the ps.sessionMu lock held.
func (ps *Key) getPrivateKey(module ctx, session pkcs11.SessionHandle, publicKeyID []byte) (pkcs11.ObjectHandle, error) {
	var noHandle pkcs11.ObjectHandle
	privateKeyHandle, err := ps.findObject([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, publicKeyID),
	})
	if err != nil {
		return noHandle, err
	}

	// Check whether the key has the CKA_ALWAYS_AUTHENTICATE attribute.
	// If so, fail: we don't want to have to re-authenticate for each sign
	// operation.
	attributes, err := module.GetAttributeValue(session, privateKeyHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ALWAYS_AUTHENTICATE, false),
	})
	// The PKCS#11 spec states that C_GetAttributeValue may return
	// CKR_ATTRIBUTE_TYPE_INVALID if an object simply does not posses a given
	// attribute. We don't consider that an error: the absence of the
	// CKR_ATTRIBUTE_TYPE_INVALID property is just fine.
	if err != nil && err == pkcs11.Error(pkcs11.CKR_ATTRIBUTE_TYPE_INVALID) {
		return privateKeyHandle, nil
	} else if err != nil {
		return noHandle, err
	}
	if len(attributes) > 0 && len(attributes[0].Value) > 0 && attributes[0].Value[0] == 1 {
		ps.alwaysAuthenticate = true
	}

	return privateKeyHandle, nil
}

// Destroy tears down a Key by closing the session. It should be
// called before the key gets GC'ed, to avoid leaving dangling sessions.
func (ps *Key) Destroy() error {
	if ps.session != nil {
		// NOTE: We do not want to call module.Logout here. module.Logout applies
		// application-wide. So if there are multiple sessions active, the other ones
		// would be logged out as well, causing CKR_OBJECT_HANDLE_INVALID next
		// time they try to sign something. It's also unnecessary to log out explicitly:
		// module.CloseSession will log out once the last session in the application is
		// closed.
		ps.sessionMu.Lock()
		defer ps.sessionMu.Unlock()
		err := ps.module.CloseSession(*ps.session)
		ps.session = nil
		if err != nil {
			return fmt.Errorf("pkcs11key: close session: %s", err)
		}
	}
	return nil
}

func (ps *Key) openSession() (pkcs11.SessionHandle, error) {
	var noSession pkcs11.SessionHandle
	slots, err := ps.module.GetSlotList(true)
	if err != nil {
		return noSession, err
	}

	for _, slot := range slots {
		// Check that token label matches.
		tokenInfo, err := ps.module.GetTokenInfo(slot)
		if err != nil {
			return noSession, err
		}
		if tokenInfo.Label != ps.tokenLabel {
			continue
		}

		// Open session
		session, err := ps.module.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
		if err != nil {
			return session, err
		}

		// Login
		// Note: Logged-in status is application-wide, not per session. But in
		// practice it appears to be okay to login to a token multiple times with the same
		// credentials.
		if err = ps.module.Login(session, pkcs11.CKU_USER, ps.pin); err != nil {
			if err == pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
				// But if the token says we're already logged in, it's ok.
				err = nil
			} else {
				ps.module.CloseSession(session)
				return session, err
			}
		}

		return session, err
	}
	return noSession, fmt.Errorf("no slot found matching token label %q", ps.tokenLabel)
}

// Public returns the public key for the PKCS #11 key.
func (ps *Key) Public() crypto.PublicKey {
	return ps.publicKey
}

// Sign performs a signature using the PKCS #11 key.
func (ps *Key) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	ps.sessionMu.Lock()
	defer ps.sessionMu.Unlock()
	if ps.session == nil {
		return nil, errors.New("pkcs11key: session was nil")
	}

	// When the alwaysAuthenticate bit is true (e.g. on a YubiKey in PIV mode),
	// each Sign has to include a Logout/Login, or the next Sign request will get
	// CKR_USER_NOT_LOGGED_IN. This is very slow, but on the YubiKey it's not possible
	// to clear the CKA_ALWAYS_AUTHENTICATE bit, so this is the only available
	// workaround.
	// Also, since logged in / logged out is application state rather than session
	// state, we take a global lock while we do the logout and login, and during
	// the signing.
	if ps.alwaysAuthenticate {
		modulesMu.Lock()
		defer modulesMu.Unlock()
		if err := ps.module.Logout(*ps.session); err != nil {
			return nil, fmt.Errorf("pkcs11key: logout: %s", err)
		}
		if err = ps.module.Login(*ps.session, pkcs11.CKU_USER, ps.pin); err != nil {
			return nil, fmt.Errorf("pkcs11key: login: %s", err)
		}
	}

	// Verify that the length of the hash is as expected
	hash := opts.HashFunc()
	hashLen := hash.Size()
	if len(msg) != hashLen {
		err = fmt.Errorf("pkcs11key: input size does not match hash function output size: %d vs %d", len(msg), hashLen)
		return
	}

	// Add DigestInfo prefix
	var mechanism []*pkcs11.Mechanism
	var signatureInput []byte
	var isECDSA bool

	switch ps.publicKey.(type) {
	case *rsa.PublicKey:
		if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
			// Signing with RSA-PSS
			mechanism, err = rsaPSSMechanism(hash, pssOpts.SaltLength)
			signatureInput = msg
		} else {
			// Signing with RSA-PKCS1v1.5
			var prefix []byte
			mechanism, prefix, err = rsaPKCS1Mechanism(hash)
			signatureInput = append(prefix, msg...)
		}
		if err != nil {
			return
		}
	case *ecdsa.PublicKey:
		isECDSA = true
		mechanism = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}
		signatureInput = msg
	default:
		return nil, fmt.Errorf("unrecognized key type %T", ps.publicKey)
	}

	// Perform the sign operation
	err = ps.module.SignInit(*ps.session, mechanism, ps.privateKeyHandle)
	if err != nil {
		return nil, fmt.Errorf("pkcs11key: sign init: %s", err)
	}

	signature, err = ps.module.Sign(*ps.session, signatureInput)
	if err != nil {
		return nil, fmt.Errorf("pkcs11key: sign: %s", err)
	}

	// PKCS#11 defines its own signature format for ECDSA signatures,
	// one octet string of even length, containing the r and s values
	// concatenated together. But RFC 5480 defines a different format,
	// an ECDSA signature is a SEQUENCE of two INTEGERs. Per the docs,
	// the crypto.Signer output should match RFC 5480.
	if isECDSA {
		signature, err = ecdsaPKCS11ToRFC5480(signature)
		if err != nil {
			return nil, fmt.Errorf("pkcs11key: sign: %s", err)
		}
	}

	return
}

func rsaPSSMechanism(hash crypto.Hash, saltLength int) (mechanism []*pkcs11.Mechanism, err error) {
	params, ok := hashPSSParams[hash]
	if !ok {
		err = errors.New("pkcs11key: unknown hash function")
		return
	}

	if saltLength == rsa.PSSSaltLengthAuto || saltLength == rsa.PSSSaltLengthEqualsHash {
		saltLength = hash.Size()
	}
	pssParams := pkcs11.NewPSSParams(params.ckmHash, params.ckgMGF, uint(saltLength))

	return []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, pssParams)}, nil
}

func rsaPKCS1Mechanism(hash crypto.Hash) (mechanism []*pkcs11.Mechanism, prefix []byte, err error) {
	prefix, ok := hashPKCS1Prefixes[hash]
	if !ok {
		err = errors.New("pkcs11key: unknown hash function")
		return
	}

	mechanism = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
	return
}

func ecdsaPKCS11ToRFC5480(pkcs11Signature []byte) (rfc5480Signature []byte, err error) {
	mid := len(pkcs11Signature) / 2

	r := &big.Int{}
	s := &big.Int{}

	return asn1.Marshal(rfc5480ECDSASignature{
		R: r.SetBytes(pkcs11Signature[:mid]),
		S: s.SetBytes(pkcs11Signature[mid:]),
	})
}
