package jose

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
)

// JWK

type rawJsonWebKey struct {
	// Only public key fields, since we only require verification
	Kty string     `json:"kty,omitempty"` // XXX Use an enum
	N   JsonBuffer `json:"n,omitempty"`
	E   JsonBuffer `json:"e,omitempty"`
	Crv string     `json:"crv,omitempty"` // XXX Use an enum
	X   JsonBuffer `json:"x,omitempty"`
	Y   JsonBuffer `json:"y,omitempty"`
}

type rsaThumbprint struct {
	E   string `json:"e,omitempty"`
	Kty string `json:"kty,omitempty"`
	N   string `json:"n,omitempty"`
}

type ecThumbprint struct {
	Crv string `json:"crv,omitempty"`
	Kty string `json:"kty,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type JsonWebKey struct {
	KeyType    JoseKeyType
	Rsa        *rsa.PublicKey
	Ec         *ecdsa.PublicKey
	Thumbprint string
}

func (jwk *JsonWebKey) ComputeThumbprint() {
	var jsonThumbprint []byte
	var err error
	if jwk.Rsa != nil {
		thumbprintStruct := rsaThumbprint{E: B64enc(big.NewInt(int64(jwk.Rsa.E)).Bytes()), Kty: string(jwk.KeyType), N: B64enc(jwk.Rsa.N.Bytes())}
		jsonThumbprint, err = json.Marshal(thumbprintStruct)
		if err != nil {
			return
		}
	} else if jwk.Ec != nil {
		crv, err := curve2name(jwk.Ec.Curve)
		if err != nil {
			return
		}
		thumbprintStruct := ecThumbprint{Crv: crv, Kty: string(jwk.KeyType), X: B64enc(jwk.Ec.X.Bytes()), Y: B64enc(jwk.Ec.Y.Bytes())}
		jsonThumbprint, err = json.Marshal(thumbprintStruct)
		if err != nil {
			return
		}
	}
	tpHash := sha256.Sum256(jsonThumbprint)

	jwk.Thumbprint = B64enc(tpHash[:])
}

// Normal Go == operator compares pointers directly, so it doesn't
// match the semantic of two keys being equivalent
func (jwk1 JsonWebKey) Equals(jwk2 JsonWebKey) bool {
	jwk1.ComputeThumbprint()
	jwk2.ComputeThumbprint()
	return (jwk1.Thumbprint == jwk2.Thumbprint)
}

func (jwk JsonWebKey) MarshalJSON() ([]byte, error) {
	raw := rawJsonWebKey{Kty: string(jwk.KeyType)}
	if jwk.Rsa != nil {
		raw.N = jwk.Rsa.N.Bytes()
		raw.E = big.NewInt(int64(jwk.Rsa.E)).Bytes()
	}
	if jwk.Ec != nil {
		var err error
		raw.Crv, err = curve2name(jwk.Ec.Curve)
		if err != nil {
			return nil, err
		}

		raw.X = jwk.Ec.X.Bytes()
		raw.Y = jwk.Ec.Y.Bytes()
	}

	return json.Marshal(raw)
}

func (jwk *JsonWebKey) UnmarshalJSON(data []byte) error {
	var raw rawJsonWebKey
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	jwk.KeyType = JoseKeyType(raw.Kty)
	switch jwk.KeyType {
	case "RSA":
		jwk.Rsa = &rsa.PublicKey{
			N: raw.N.ToBigInt(),
			E: raw.E.ToInt(),
		}
	case "EC":
		curve, err := name2curve(raw.Crv)
		if err != nil {
			return err
		}

		jwk.Ec = &ecdsa.PublicKey{
			Curve: curve,
			X:     raw.X.ToBigInt(),
			Y:     raw.Y.ToBigInt(),
		}
	}

	jwk.ComputeThumbprint()
	return nil
}
