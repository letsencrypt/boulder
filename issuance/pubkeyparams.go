//go:build !go1.27

package issuance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
)

func pubkeyParams(pubkey any) (x509.PublicKeyAlgorithm, x509.SignatureAlgorithm, error) {
	switch k := pubkey.(type) {
	case *rsa.PublicKey:
		return x509.RSA, x509.SHA256WithRSA, nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return x509.ECDSA, x509.ECDSAWithSHA256, nil
		case elliptic.P384():
			return x509.ECDSA, x509.ECDSAWithSHA384, nil
		default:
			return x509.UnknownPublicKeyAlgorithm, x509.UnknownSignatureAlgorithm,
				fmt.Errorf("unsupported ECDSA curve: %q", k.Curve.Params().Name)
		}
	default:
		return x509.UnknownPublicKeyAlgorithm, x509.UnknownSignatureAlgorithm,
			errors.New("unsupported issuer key type")
	}
}
