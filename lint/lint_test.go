package lint

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestMakeSigner_RSA(t *testing.T) {
	rsaMod, ok := big.NewInt(0).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	test.Assert(t, ok, "failed to set RSA mod")
	realSigner := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: rsaMod,
		},
	}
	lintSigner, err := MakeSigner(realSigner)
	test.AssertNotError(t, err, "MakeSigner failed")
	_, ok = lintSigner.(*rsa.PrivateKey)
	test.Assert(t, ok, "lint signer is not RSA")
}

func TestMakeSigner_ECDSA(t *testing.T) {
	realSigner := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
		},
	}
	lintSigner, err := MakeSigner(realSigner)
	test.AssertNotError(t, err, "MakeSigner failed")
	_, ok := lintSigner.(*ecdsa.PrivateKey)
	test.Assert(t, ok, "lint signer is not ECDSA")
}

func TestMakeSigner_Unsupported(t *testing.T) {
	realSigner := ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
	_, err := MakeSigner(realSigner)
	test.AssertError(t, err, "MakeSigner shouldn't have succeeded")
}
