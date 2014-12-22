// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package anvil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash"
	"math/big"
	"net/url"
	"strings"
)

// Errors

type NotSupportedError string
type MalformedRequestError string
type UnauthorizedError string
type NotFoundError string
type SyntaxError string
type SignatureValidationError string
type CertificateIssuanceError string

func (e NotSupportedError) Error() string        { return string(e) }
func (e MalformedRequestError) Error() string    { return string(e) }
func (e UnauthorizedError) Error() string        { return string(e) }
func (e NotFoundError) Error() string            { return string(e) }
func (e SyntaxError) Error() string              { return string(e) }
func (e SignatureValidationError) Error() string { return string(e) }
func (e CertificateIssuanceError) Error() string { return string(e) }

// Base64 functions

func pad(x string) string {
	switch len(x) % 4 {
	case 2:
		return x + "=="
	case 3:
		return x + "="
	}
	return x
}

func unpad(x string) string {
	return strings.Replace(x, "=", "", -1)
}

func b64enc(x []byte) string {
	return unpad(base64.URLEncoding.EncodeToString(x))
}

func b64dec(x string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(pad(x))
}

// Random stuff

func randomString(length int) string {
	b := make([]byte, length)
	rand.Read(b) // NOTE: Ignoring errors
	return b64enc(b)
}

func newToken() string {
	return randomString(32)
}

// URLs that automatically marshal/unmarshal to JSON strings
type AcmeURL url.URL

func (u *AcmeURL) MarshalJSON() ([]byte, error) {
	uu := url.URL(*u)
	return json.Marshal(uu.String())
}

func (u *AcmeURL) UnmarshalJSON(data []byte) error {
	var str string
	err := json.Unmarshal(data, &str)
	if err != nil {
		return err
	}

	uu, err := url.Parse(str)
	*u = AcmeURL(*uu)
	return err
}

// The missing CertificateRequest.Verify() method
func VerifyCSR(csr *x509.CertificateRequest) error {
	// Compute the hash of the TBSCertificateRequest
	var hashID crypto.Hash
	var hash hash.Hash
	switch csr.SignatureAlgorithm {
	case x509.SHA1WithRSA:
		hashID = crypto.SHA1
		hash = sha1.New()
	case x509.SHA256WithRSA:
		fallthrough
	case x509.ECDSAWithSHA256:
		hashID = crypto.SHA256
		hash = sha256.New()
	case x509.SHA384WithRSA:
		fallthrough
	case x509.ECDSAWithSHA384:
		hashID = crypto.SHA384
		hash = sha512.New384()
	case x509.SHA512WithRSA:
		fallthrough
	case x509.ECDSAWithSHA512:
		hashID = crypto.SHA512
		hash = sha512.New()
	default:
		return errors.New("Unsupported CSR signing algorithm")
	}
	hash.Write(csr.RawTBSCertificateRequest)
	inputHash := hash.Sum(nil)

	// Verify the signature using the public key in the CSR
	switch csr.SignatureAlgorithm {
	case x509.SHA1WithRSA:
		fallthrough
	case x509.SHA256WithRSA:
		fallthrough
	case x509.SHA384WithRSA:
		fallthrough
	case x509.SHA512WithRSA:
		rsaKey := csr.PublicKey.(*rsa.PublicKey)
		return rsa.VerifyPKCS1v15(rsaKey, hashID, inputHash, csr.Signature)
	case x509.ECDSAWithSHA256:
		fallthrough
	case x509.ECDSAWithSHA384:
		fallthrough
	case x509.ECDSAWithSHA512:
		ecKey := csr.PublicKey.(*ecdsa.PublicKey)
		intlen := len(csr.Signature) / 2
		r, s := big.NewInt(0), big.NewInt(0)
		r.SetBytes(csr.Signature[:intlen])
		s.SetBytes(csr.Signature[intlen:])
		if ecdsa.Verify(ecKey, inputHash, r, s) {
			return nil
		} else {
			return errors.New("Invalid ECDSA signature on CSR")
		}
	}

	return errors.New("Unsupported CSR signing algorithm")
}
