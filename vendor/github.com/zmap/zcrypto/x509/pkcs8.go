// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/rsa"
	"github.com/zmap/zcrypto/x509/pkix"

	"crypto/mldsa"
)

// pkcs8 reflects an ASN.1, PKCS#8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

// ParsePKCS8PrivateKey parses an unencrypted private key in PKCS #8, ASN.1 DER form.
//
// It returns a *rsa.PrivateKey, a *ecdsa.PrivateKey, *mldsa44.PrivateKey, *mldsa65.PrivateKey, *mldsa87.PrivateKey or a ed25519.PrivateKey.
// More types might be supported in the future.
//
// This kind of key is commonly encoded in PEM blocks of type "PRIVATE KEY".
func ParsePKCS8PrivateKey(der []byte) (key any, err error) {
	var privKey pkcs8
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		if _, err := asn1.Unmarshal(der, &ecPrivateKey{}); err == nil {
			return nil, errors.New("x509: failed to parse private key (use ParseECPrivateKey instead for this key format)")
		}
		if _, err := asn1.Unmarshal(der, &pkcs1PrivateKey{}); err == nil {
			return nil, errors.New("x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)")
		}
		return nil, err
	}
	switch {
	case privKey.Algo.Algorithm.Equal(oidPublicKeyRSA):
		key, err = ParsePKCS1PrivateKey(privKey.PrivateKey)
		if err != nil {
			return nil, errors.New("x509: failed to parse RSA private key embedded in PKCS#8: " + err.Error())
		}
		return key, nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeyECDSA):
		bytes := privKey.Algo.Parameters.FullBytes
		namedCurveOID := new(asn1.ObjectIdentifier)
		if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
			namedCurveOID = nil
		}
		key, err = parseECPrivateKey(namedCurveOID, privKey.PrivateKey)
		if err != nil {
			return nil, errors.New("x509: failed to parse EC private key embedded in PKCS#8: " + err.Error())
		}
		return key, nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeyMLDSA44):
		if l := len(privKey.Algo.Parameters.FullBytes); l != 0 {
			return nil, errors.New("x509: invalid MLDSA44 private key parameters")
		}
		key, err = ParseMLDSA44PrivateKey(privKey.PrivateKey)
		if err != nil {
			return nil, errors.New("x509: failed to parse MLDSA44 private key embedded in PKCS#8: " + err.Error())
		}
		return key, nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeyMLDSA65):
		if l := len(privKey.Algo.Parameters.FullBytes); l != 0 {
			return nil, errors.New("x509: invalid MLDSA65 private key parameters")
		}
		key, err = ParseMLDSA65PrivateKey(privKey.PrivateKey)
		if err != nil {
			return nil, errors.New("x509: failed to parse MLDSA65 private key embedded in PKCS#8: " + err.Error())
		}
		return key, nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeyMLDSA87):
		if l := len(privKey.Algo.Parameters.FullBytes); l != 0 {
			return nil, errors.New("x509: invalid MLDSA87 private key parameters")
		}
		key, err = ParseMLDSA87PrivateKey(privKey.PrivateKey)
		if err != nil {
			return nil, errors.New("x509: failed to parse MLDSA87 private key embedded in PKCS#8: " + err.Error())
		}
		return key, nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeyEd25519):
		if l := len(privKey.Algo.Parameters.FullBytes); l != 0 {
			return nil, errors.New("x509: invalid Ed25519 private key parameters")
		}
		var curvePrivateKey []byte
		if _, err := asn1.Unmarshal(privKey.PrivateKey, &curvePrivateKey); err != nil {
			return nil, fmt.Errorf("x509: invalid Ed25519 private key: %v", err)
		}
		if l := len(curvePrivateKey); l != ed25519.SeedSize {
			return nil, fmt.Errorf("x509: invalid Ed25519 private key length: %d", l)
		}
		return ed25519.NewKeyFromSeed(curvePrivateKey), nil

	default:
		return nil, fmt.Errorf("x509: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
	}
}

// MarshalPKCS8PrivateKey converts a private key to PKCS #8, ASN.1 DER form.
//
// The following key types are currently supported: *rsa.PrivateKey, *ecdsa.PrivateKey, *mldsa44.PrivateKey, *mldsa65.PrivateKey, *mldsa87.PrivateKey
// and ed25519.PrivateKey. Unsupported key types result in an error.
//
// # Per RFC 9881 specifications, MLDSA private keys should be encoded in seed format when possible
// ML-DSA keys are unable to be encoded in seed format if they are an expanded private key
//
// This kind of key is commonly encoded in PEM blocks of type "PRIVATE KEY".
func MarshalPKCS8PrivateKey(key any) ([]byte, error) {
	var privKey pkcs8

	switch k := key.(type) {
	case *rsa.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm:  oidPublicKeyRSA,
			Parameters: asn1.NullRawValue,
		}
		privKey.PrivateKey = MarshalPKCS1PrivateKey(k)

	case *ecdsa.PrivateKey:
		oid, err := oidFromNamedCurve(k.Curve)
		if err != nil {
			return nil, err
		}

		oidBytes, err := asn1.Marshal(oid)
		if err != nil {
			return nil, errors.New("x509: failed to marshal curve OID: " + err.Error())
		}

		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyECDSA,
			Parameters: asn1.RawValue{
				FullBytes: oidBytes,
			},
		}

		if privKey.PrivateKey, err = marshalECPrivateKeyWithOID(k, nil); err != nil {
			return nil, errors.New("x509: failed to marshal EC private key while building PKCS#8: " + err.Error())
		}

	case *mldsa.PrivateKey:
		switch k.PublicKey().Parameters() {
		case mldsa.MLDSA44():
			privKey.Algo = pkix.AlgorithmIdentifier{
				Algorithm: oidPublicKeyMLDSA44,
			}
		case mldsa.MLDSA65():
			privKey.Algo = pkix.AlgorithmIdentifier{
				Algorithm: oidPublicKeyMLDSA65,
			}
		case mldsa.MLDSA87():
			privKey.Algo = pkix.AlgorithmIdentifier{
				Algorithm: oidPublicKeyMLDSA87,
			}
		default:
			return nil, errors.New("x509: unknown ML-DSA parameter set while marshaling PKCS#8")
		}

		var err error
		privKey.PrivateKey, err = asn1.MarshalWithParams(k.Bytes(), "tag:0")
		if err != nil {
			return nil, fmt.Errorf("x509: failed to marshal private key: %v", err)
		}

	case ed25519.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyEd25519,
		}
		curvePrivateKey, err := asn1.Marshal(k.Seed())
		if err != nil {
			return nil, fmt.Errorf("x509: failed to marshal private key: %v", err)
		}
		privKey.PrivateKey = curvePrivateKey

	default:
		return nil, fmt.Errorf("x509: unknown key type while marshaling PKCS#8: %T", key)
	}

	return asn1.Marshal(privKey)
}
