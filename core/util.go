// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"math/big"
	"net/url"
	"regexp"
	"strings"

	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"
	blog "github.com/letsencrypt/boulder/log"
)

// Package Variables Variables

// BuildID is set by the compiler (using -ldflags "-X core.BuildID $(git rev-parse --short HEAD)")
// and is used by GetBuildID
var BuildID string

// BuildHost is set by the compiler and is used by GetBuildHost
var BuildHost string

// BuildTime is set by the compiler and is used by GetBuildTime
var BuildTime string

// Errors

// InternalServerError indicates that something has gone wrong unrelated to the
// user's input, and will be considered by the Load Balancer as an indication
// that this Boulder instance may be malfunctioning. Minimally, returning this
// will cause an error page to be generated at the CDN/LB for the client.
// Consequently, you should only use this error when Boulder's internal
// constraints have been violated.
type InternalServerError string

// NotSupportedError indicates a method is not yet supported
type NotSupportedError string

// MalformedRequestError indicates the user data was improper
type MalformedRequestError string

// UnauthorizedError indicates the user did not satisfactorily prove identity
type UnauthorizedError string

// NotFoundError indicates the destination was unknown. Whoa oh oh ohhh.
type NotFoundError string

// LengthRequiredError indicates a POST was sent with no Content-Length.
type LengthRequiredError string

// SyntaxError indicates the user improperly formatted their data.
type SyntaxError string

// SignatureValidationError indicates that the user's signature could not
// be verified, either through adversarial activity, or misconfiguration of
// the user client.
type SignatureValidationError string

// CertificateIssuanceError indicates the certificate failed to be issued
// for some reason.
type CertificateIssuanceError string

// NoSuchRegistrationError indicates that a registration could not be found.
type NoSuchRegistrationError string

// RateLimitedError indicates the user has hit a rate limit
type RateLimitedError string

// TooManyRPCRequestsError indicates an RPC server has hit it's concurrent request
// limit
type TooManyRPCRequestsError string

func (e InternalServerError) Error() string      { return string(e) }
func (e NotSupportedError) Error() string        { return string(e) }
func (e MalformedRequestError) Error() string    { return string(e) }
func (e UnauthorizedError) Error() string        { return string(e) }
func (e NotFoundError) Error() string            { return string(e) }
func (e LengthRequiredError) Error() string      { return string(e) }
func (e SyntaxError) Error() string              { return string(e) }
func (e SignatureValidationError) Error() string { return string(e) }
func (e CertificateIssuanceError) Error() string { return string(e) }
func (e NoSuchRegistrationError) Error() string  { return string(e) }
func (e RateLimitedError) Error() string         { return string(e) }
func (e TooManyRPCRequestsError) Error() string  { return string(e) }

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
	end := len(x)
	for end != 0 && x[end-1] == '=' {
		end--
	}
	return x[:end]
}

// B64enc encodes a byte array as unpadded, URL-safe Base64
func B64enc(x []byte) string {
	return unpad(base64.URLEncoding.EncodeToString(x))
}

// B64dec decodes a byte array from unpadded, URL-safe Base64
func B64dec(x string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(pad(x))
}

// Random stuff

// RandomString returns a randomly generated string of the requested length.
func RandomString(byteLength int) string {
	b := make([]byte, byteLength)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		ohdear := "RandomString entropy failure? " + err.Error()
		logger := blog.GetAuditLogger()
		logger.EmergencyExit(ohdear)
	}
	return B64enc(b)
}

// NewToken produces a random string for Challenges, etc.
func NewToken() string {
	return RandomString(32)
}

var tokenFormat = regexp.MustCompile("^[\\w-]{43}$")

// LooksLikeAToken checks whether a string represents a 32-octet value in
// the URL-safe base64 alphabet.
func LooksLikeAToken(token string) bool {
	return tokenFormat.MatchString(token)
}

// Fingerprints

// Fingerprint256 produces an unpadded, URL-safe Base64-encoded SHA256 digest
// of the data.
func Fingerprint256(data []byte) string {
	d := sha256.New()
	_, _ = d.Write(data) // Never returns an error
	return B64enc(d.Sum(nil))
}

// Thumbprint produces a JWK thumbprint [RFC7638] of a JWK.
// XXX(rlb): This is adapted from a PR to go-jose, but we need it here until
//           that PR is merged and we update to that version.
//           https://github.com/square/go-jose/pull/37
// XXX(rlb): Once that lands, we should replace the digest methods below
//           with this standard thumbprint.
const rsaThumbprintTemplate = `{"e":"%s","kty":"RSA","n":"%s"}`
const ecThumbprintTemplate = `{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`

// Get JOSE name of curve
func curveName(crv elliptic.Curve) (string, error) {
	switch crv {
	case elliptic.P256():
		return "P-256", nil
	case elliptic.P384():
		return "P-384", nil
	case elliptic.P521():
		return "P-521", nil
	default:
		return "", fmt.Errorf("square/go-jose: unsupported/unknown elliptic curve")
	}
}

// Get size of curve in bytes
func curveSize(crv elliptic.Curve) int {
	bits := crv.Params().BitSize

	div := bits / 8
	mod := bits % 8

	if mod == 0 {
		return div
	}

	return div + 1
}

func newFixedSizeBuffer(data []byte, length int) []byte {
	if len(data) > length {
		panic("square/go-jose: invalid call to newFixedSizeBuffer (len(data) > length)")
	}
	pad := make([]byte, length-len(data))
	return append(pad, data...)
}

func ecThumbprintInput(curve elliptic.Curve, x, y *big.Int) (string, error) {
	coordLength := curveSize(curve)
	crv, err := curveName(curve)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(ecThumbprintTemplate, crv,
		B64enc(newFixedSizeBuffer(x.Bytes(), coordLength)),
		B64enc(newFixedSizeBuffer(y.Bytes(), coordLength))), nil
}

func rsaThumbprintInput(n *big.Int, e int) (string, error) {
	return fmt.Sprintf(rsaThumbprintTemplate,
		B64enc(big.NewInt(int64(e)).Bytes()),
		B64enc(n.Bytes())), nil
}

// Thumbprint computes the JWK Thumbprint of a key using the
// indicated hash algorithm.
func Thumbprint(k *jose.JsonWebKey) (string, error) {
	var input string
	var err error
	switch key := k.Key.(type) {
	case *ecdsa.PublicKey:
		input, err = ecThumbprintInput(key.Curve, key.X, key.Y)
	case *ecdsa.PrivateKey:
		input, err = ecThumbprintInput(key.Curve, key.X, key.Y)
	case *rsa.PublicKey:
		input, err = rsaThumbprintInput(key.N, key.E)
	case *rsa.PrivateKey:
		input, err = rsaThumbprintInput(key.N, key.E)
	default:
		return "", fmt.Errorf("square/go-jose: unkown key type")
	}

	if err != nil {
		return "", err
	}

	h := sha256.New()
	h.Write([]byte(input))
	return B64enc(h.Sum(nil)), nil
}

// KeyDigest produces a padded, standard Base64-encoded SHA256 digest of a
// provided public key.
func KeyDigest(key crypto.PublicKey) (string, error) {
	switch t := key.(type) {
	case *jose.JsonWebKey:
		if t == nil {
			return "", fmt.Errorf("Cannot compute digest of nil key")
		}
		return KeyDigest(t.Key)
	case jose.JsonWebKey:
		return KeyDigest(t.Key)
	default:
		keyDER, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			logger := blog.GetAuditLogger()
			logger.Debug(fmt.Sprintf("Problem marshaling public key: %s", err))
			return "", err
		}
		spkiDigest := sha256.Sum256(keyDER)
		return base64.StdEncoding.EncodeToString(spkiDigest[0:32]), nil
	}
}

// KeyDigestEquals determines whether two public keys have the same digest.
func KeyDigestEquals(j, k crypto.PublicKey) bool {
	digestJ, errJ := KeyDigest(j)
	digestK, errK := KeyDigest(k)
	// Keys that don't have a valid digest (due to marshalling problems)
	// are never equal. So, e.g. nil keys are not equal.
	if errJ != nil || errK != nil {
		return false
	}
	return digestJ == digestK
}

// AcmeURL is a URL that automatically marshal/unmarshal to JSON strings
type AcmeURL url.URL

// ParseAcmeURL is just a wrapper around url.Parse that returns an *AcmeURL
func ParseAcmeURL(s string) (*AcmeURL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	return (*AcmeURL)(u), nil
}

func (u *AcmeURL) String() string {
	uu := (*url.URL)(u)
	return uu.String()
}

// PathSegments splits an AcmeURL into segments on the '/' characters
func (u *AcmeURL) PathSegments() (segments []string) {
	segments = strings.Split(u.Path, "/")
	if len(segments) > 0 && len(segments[0]) == 0 {
		segments = segments[1:]
	}
	return
}

// MarshalJSON encodes an AcmeURL for transfer
func (u *AcmeURL) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.String())
}

// UnmarshalJSON decodes an AcmeURL from transfer
func (u *AcmeURL) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	uu, err := url.Parse(str)
	*u = AcmeURL(*uu)
	return err
}

// VerifyCSR verifies that a Certificate Signature Request is well-formed.
//
// Note: this is the missing CertificateRequest.Verify() method
func VerifyCSR(csr *x509.CertificateRequest) error {
	// Compute the hash of the TBSCertificateRequest
	var hashID crypto.Hash
	var hash hash.Hash
	switch csr.SignatureAlgorithm {
	case x509.SHA1WithRSA:
		fallthrough
	case x509.ECDSAWithSHA1:
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
	_, _ = hash.Write(csr.RawTBSCertificateRequest) // Never returns an error
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
	case x509.ECDSAWithSHA1:
		fallthrough
	case x509.ECDSAWithSHA256:
		fallthrough
	case x509.ECDSAWithSHA384:
		fallthrough
	case x509.ECDSAWithSHA512:
		ecKey := csr.PublicKey.(*ecdsa.PublicKey)

		var sig struct{ R, S *big.Int }
		_, err := asn1.Unmarshal(csr.Signature, &sig)
		if err != nil {
			return err
		}

		if ecdsa.Verify(ecKey, inputHash, sig.R, sig.S) {
			return nil
		}

		return errors.New("Invalid ECDSA signature on CSR")
	}

	return errors.New("Unsupported CSR signing algorithm")
}

// SerialToString converts a certificate serial number (big.Int) to a String
// consistently.
func SerialToString(serial *big.Int) string {
	return fmt.Sprintf("%036x", serial)
}

// StringToSerial converts a string into a certificate serial number (big.Int)
// consistently.
func StringToSerial(serial string) (*big.Int, error) {
	var serialNum big.Int
	if !ValidSerial(serial) {
		return &serialNum, errors.New("Invalid serial number")
	}
	_, err := fmt.Sscanf(serial, "%036x", &serialNum)
	return &serialNum, err
}

// ValidSerial tests whether the input string represents a syntactically
// valid serial number, i.e., that it is a valid hex string between 32
// and 36 characters long.
func ValidSerial(serial string) bool {
	// Originally, serial numbers were 32 hex characters long. We later increased
	// them to 36, but we allow the shorter ones because they exist in some
	// production databases.
	if len(serial) < 32 && len(serial) > 36 {
		return false
	}
	_, err := hex.DecodeString(serial)
	if err != nil {
		return false
	}
	return true
}

// GetBuildID identifies what build is running.
func GetBuildID() (retID string) {
	retID = BuildID
	if retID == "" {
		retID = "Unspecified"
	}
	return
}

// GetBuildTime identifies when this build was made
func GetBuildTime() (retID string) {
	retID = BuildTime
	if retID == "" {
		retID = "Unspecified"
	}
	return
}

// GetBuildHost identifies the building host
func GetBuildHost() (retID string) {
	retID = BuildHost
	if retID == "" {
		retID = "Unspecified"
	}
	return
}

// UniqueLowerNames returns the set of all unique names in the input after all
// of them are lowercased. The returned names will be in their lowercased form.
func UniqueLowerNames(names []string) (unique []string) {
	nameMap := make(map[string]int, len(names))
	for _, name := range names {
		nameMap[strings.ToLower(name)] = 1
	}

	unique = make([]string, 0, len(nameMap))
	for name := range nameMap {
		unique = append(unique, name)
	}
	return
}

// LoadCertBundle loads a PEM bundle of certificates from disk
func LoadCertBundle(filename string) ([]*x509.Certificate, error) {
	bundleBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var bundle []*x509.Certificate
	var block *pem.Block
	rest := bundleBytes
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("Block has invalid type: %s", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		bundle = append(bundle, cert)
	}

	if len(bundle) == 0 {
		return nil, fmt.Errorf("Bundle doesn't contain any certificates")
	}

	return bundle, nil
}

// LoadCert loads a PEM certificate specified by filename or returns a error
func LoadCert(filename string) (cert *x509.Certificate, err error) {
	certPEM, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("No data in cert PEM file %s", filename)
	}
	cert, err = x509.ParseCertificate(block.Bytes)
	return
}
