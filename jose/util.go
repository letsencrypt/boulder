package jose

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
)

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

// Buffers that know how to do b64 and bigint
type JsonBuffer json.RawMessage

func (jb JsonBuffer) MarshalJSON() ([]byte, error) {
	str := b64enc(jb)
	return json.Marshal(str)
}

func (jb *JsonBuffer) UnmarshalJSON(data []byte) error {
	var str string
	err := json.Unmarshal(data, &str)
	if err != nil {
		return err
	}

	*jb, err = b64dec(str)
	return err
}

func (jb JsonBuffer) ToBigInt() *big.Int {
	ret := big.NewInt(0)
	ret.SetBytes(jb)
	return ret
}

func (jb JsonBuffer) ToInt() int {
	return int(jb.ToBigInt().Int64())
}

// Utils

func bigint2base64(x *big.Int) string {
	return b64enc(x.Bytes())
}

func int2base64(x int) string {
	b := big.NewInt(int64(x))
	return bigint2base64(b)
}

func base642bigint(x string) (*big.Int, error) {
	data, err := b64dec(x)
	if err != nil {
		return nil, err
	}

	bn := big.NewInt(0)
	bn.SetBytes(data)
	return bn, nil
}

func base642int(x string) (int, error) {
	bn, err := base642bigint(x)
	if err != nil {
		return 0, err
	}

	return int(bn.Int64()), nil
}

func name2curve(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	}

	var dummy elliptic.Curve
	return dummy, errors.New("Unknown elliptic curve " + name)
}

func curve2name(curve elliptic.Curve) (string, error) {
	// XXX DANGER ASSUMES ONE CURVE PER BIT SIZE
	switch curve.Params().BitSize {
	case 256:
		return "P-256", nil
	case 384:
		return "P-384", nil
	case 521:
		return "P-521", nil
	}

	return "", errors.New("Unknown elliptic curve")
}
