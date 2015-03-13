package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
)

// JWS

type JwsHeader struct {
	Algorithm JoseAlgorithm `json:"alg,omitempty"`
	Nonce     string        `json:"nonce,omitempty"`
	Key       JsonWebKey    `json:"jwk,omitempty"`
}

// rawJsonWebSignature and JsonWebSignature are the same.
// We just use rawJsonWebSignature for the basic parse,
// and JsonWebSignature for the full parse
type rawJsonWebSignature struct {
	signed    bool
	Header    JwsHeader  `json:"header,omitempty"`
	Protected JsonBuffer `json:"protected,omitempty"`
	Payload   JsonBuffer `json:"payload,omitempty"`
	Signature JsonBuffer `json:"signature,omitempty"`
}

type JsonWebSignature rawJsonWebSignature

// No need for special MarshalJSON handling; it's OK for
// elements to remain in the unprotected header, since they'll
// just be overwritten.
// func (jwk JsonWebKey) MarshalJSON() ([]byte, error) {}

// On unmarshal, copy protected header fields to protected
func (jws *JsonWebSignature) UnmarshalJSON(data []byte) error {
	var raw rawJsonWebSignature
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	// Copy over simple fields
	jws.Header = raw.Header
	jws.Protected = raw.Protected
	jws.Payload = raw.Payload
	jws.Signature = raw.Signature

	if len(jws.Protected) > 0 {
		// This overwrites fields in jwk.Header if there is a conflict
		err = json.Unmarshal(jws.Protected, &jws.Header)
		if err != nil {
			return err
		}
	}

	// Check that required fields are present
	if len(jws.Signature) == 0 || len(jws.Payload) == 0 {
		return errors.New("JWS missing required fields")
	}

	return nil
}

func (jws JsonWebSignature) MarshalCompact() ([]byte, error) {
	if !jws.signed {
		return []byte{}, errors.New("Cannot marshal unsigned JWS")
	}

	return []byte(b64enc(jws.Protected) + "." + b64enc(jws.Payload) + "." + b64enc(jws.Signature)), nil
}

func UnmarshalCompact(data []byte) (JsonWebSignature, error) {
	jws := JsonWebSignature{}
	parts := strings.Split(string(data), ".")
	if len(parts) != 3 {
		return jws, errors.New("Mal-formed compact JWS")
	}

	// Decode simple fields
	var err error
	jws.Protected, err = b64dec(parts[0])
	if err != nil {
		return jws, err
	}
	jws.Payload, err = b64dec(parts[1])
	if err != nil {
		return jws, err
	}
	jws.Signature, err = b64dec(parts[2])
	if err != nil {
		return jws, err
	}

	// Populate header from protected
	err = json.Unmarshal(jws.Protected, &jws.Header)
	if err != nil {
		return jws, err
	}

	jws.signed = true
	return jws, nil
}

func prepareInput(jws JsonWebSignature) (crypto.Hash, []byte, error) {
	input := []byte(b64enc(jws.Protected) + "." + b64enc(jws.Payload))
	zeroh := crypto.Hash(0)
	zerob := []byte{}

	// TODO: Check for valid algorithm

	// Hash the payload
	hashAlg := string(jws.Header.Algorithm[2:])
	var hashID crypto.Hash
	var hash hash.Hash
	switch hashAlg {
	case "256":
		hashID = crypto.SHA256
		hash = sha256.New()
	case "384":
		hashID = crypto.SHA384
		hash = sha512.New384()
	case "512":
		hashID = crypto.SHA512
		hash = sha512.New()
	default:
		return zeroh, zerob, errors.New("Invalid hash length " + hashAlg)
	}
	hash.Write(input)
	inputHash := hash.Sum(nil)

	return hashID, inputHash, nil
}

func Sign(alg JoseAlgorithm, privateKey interface{}, payload []byte) (JsonWebSignature, error) {
	zero := JsonWebSignature{}

	// Create a working JWS
	jws := JsonWebSignature{Payload: payload}
	jws.Header.Algorithm = alg

	// Cast the private key to the appropriate type, and
	// add the corresponding public key to the header
	var rsaPriv *rsa.PrivateKey
	var ecPriv *ecdsa.PrivateKey
	switch privateKey := privateKey.(type) {
	case rsa.PrivateKey:
		rsaPriv = &privateKey
		jws.Header.Key = JsonWebKey{KeyType: KeyTypeRSA, Rsa: &rsaPriv.PublicKey}
	case ecdsa.PrivateKey:
		ecPriv = &privateKey
		jws.Header.Key = JsonWebKey{KeyType: KeyTypeEC, Ec: &ecPriv.PublicKey}
	default:
		return zero, errors.New(fmt.Sprintf("Unsupported key type for %+v\n", privateKey))
	}

	// Base64-encode the header -> protected
	// NOTE: This implies that unprotected headers are not supported
	protected, err := json.Marshal(jws.Header)
	if err != nil {
		return zero, err
	}
	jws.Protected = protected

	// Compute the signature input
	hashID, inputHash, err := prepareInput(jws)
	if err != nil {
		return zero, err
	}

	// Sign
	// TODO: Check that key type is compatible
	var sig []byte
	switch jws.Header.Algorithm[:1] {
	case "R":
		if rsaPriv == nil {
			return zero, errors.New(fmt.Sprintf("Algorithm %s requres RSA private key", jws.Header.Algorithm))
		}
		sig, err = rsa.SignPKCS1v15(rand.Reader, rsaPriv, hashID, inputHash)
	case "P":
		if rsaPriv == nil {
			return zero, errors.New(fmt.Sprintf("Algorithm %s requres RSA private key", jws.Header.Algorithm))
		}
		sig, err = rsa.SignPSS(rand.Reader, rsaPriv, hashID, inputHash, nil)
	case "E":
		if ecPriv == nil {
			return zero, errors.New(fmt.Sprintf("Algorithm %s requres EC private key", jws.Header.Algorithm))
		}
		r, s, err := ecdsa.Sign(rand.Reader, ecPriv, inputHash)
		if err == nil {
			// TODO: Pad to appropriate length
			sig = append(r.Bytes(), s.Bytes()...)
		}
	default:
		return zero, errors.New("Invalid signature algorithm " + string(jws.Header.Algorithm[:1]))
	}

	if err != nil {
		return zero, err
	}
	jws.Signature = sig
	jws.signed = true

	return jws, nil
}

func (jws *JsonWebSignature) Verify() error {
	hashID, inputHash, err := prepareInput(*jws)
	if err != nil {
		return err
	}
	sig := jws.Signature

	// Check the signature, branching from the first character in the alg value
	// For example: "RS256" => "R" => PKCS1v15
	switch jws.Header.Algorithm[:1] {
	case "R":
		if jws.Header.Key.Rsa == nil {
			return errors.New(fmt.Sprintf("Algorithm %s requires RSA key", jws.Header.Algorithm))
		}
		return rsa.VerifyPKCS1v15(jws.Header.Key.Rsa, hashID, inputHash, sig)
	case "P":
		if jws.Header.Key.Rsa == nil {
			return errors.New(fmt.Sprintf("Algorithm %s requires RSA key", jws.Header.Algorithm))
		}
		return rsa.VerifyPSS(jws.Header.Key.Rsa, hashID, inputHash, sig, nil)
	case "E":
		if jws.Header.Key.Ec == nil {
			return errors.New(fmt.Sprintf("Algorithm %s requires EC key", jws.Header.Algorithm))
		}
		intlen := len(sig) / 2
		rBytes, sBytes := sig[:intlen], sig[intlen:]
		r, s := big.NewInt(0), big.NewInt(0)
		r.SetBytes(rBytes)
		s.SetBytes(sBytes)
		if ecdsa.Verify(jws.Header.Key.Ec, inputHash, r, s) {
			return nil
		} else {
			return errors.New("ECDSA signature validation failed")
		}
	default:
		return errors.New("Invalid signature algorithm " + string(jws.Header.Algorithm[:1]))
	}
}
