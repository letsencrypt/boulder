package jose

import (
	"crypto/ecdsa"
	"crypto/rsa"
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

type JsonWebKey struct {
	KeyType    JoseKeyType
	Rsa        *rsa.PublicKey
	Ec         *ecdsa.PublicKey
	Thumbprint string
}

func (jwk *JsonWebKey) ComputeThumbprint() {
	jwk.Thumbprint = string(jwk.KeyType)
	if jwk.Rsa != nil {
		jwk.Thumbprint += b64enc(jwk.Rsa.N.Bytes())
	} else if jwk.Ec != nil {
		jwk.Thumbprint += b64enc(jwk.Ec.X.Bytes()) + b64enc(jwk.Ec.Y.Bytes())
	}
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
