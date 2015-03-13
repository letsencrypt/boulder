package jose

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
)

// Base64 Tests

func TestB64Enc(t *testing.T) {
	fmt.Println("--> TestB64Enc")
	in := []byte{0x00, 0xff}
	out := "AP8"
	if x := b64enc(in); x != out {
		t.Errorf("b64enc(%v) = %v, want %v", in, x, out)
	}
}

func TestB64Dec(t *testing.T) {
	fmt.Println("--> TestB64Dec")
	in := "_wA"
	out := []byte{0xFF, 0x00}
	x, err := b64dec(in)
	if (err != nil) || (bytes.Compare(x, out) != 0) {
		t.Errorf("b64dec(%v) = %v, want %v", in, x, out)
	}
}

// JWK Tests (from draft-ietf-jose-cookbook)

func TestRsaJwk(t *testing.T) {
	fmt.Println("--> TestRsaJwk")
	in := `{
    "kty": "RSA",
     "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
     "e": "AQAB"
  }`
	var out JsonWebKey
	err := json.Unmarshal([]byte(in), &out)
	if err != nil {
		t.Errorf("JSON unmarshal error: %+v", err)
		return
	}

	if out.KeyType != "RSA" {
		t.Errorf("Incorrect key type %+v, expecting %+v", out.KeyType, "RSA")
		return
	}

	if out.Rsa == nil {
		t.Errorf("RSA key not present")
		return
	}

	if out.Rsa.E != 0x010001 {
		t.Errorf("Incorrect public exponent %+v, expecting %+v", out.Rsa.E, 0x010001)
		return
	}

	nBytes := []byte{
		0x9f, 0x81, 0x0f, 0xb4, 0x03, 0x82, 0x73, 0xd0, 0x25, 0x91, 0xe4, 0x07, 0x3f, 0x31, 0xd2, 0xb6,
		0x00, 0x1b, 0x82, 0xce, 0xdb, 0x4d, 0x92, 0xf0, 0x50, 0x16, 0x5d, 0x47, 0xcf, 0xca, 0xb8, 0xa3,
		0xc4, 0x1c, 0xb7, 0x78, 0xac, 0x75, 0x53, 0x79, 0x3f, 0x8e, 0xf9, 0x75, 0x76, 0x8d, 0x1a, 0x23,
		0x74, 0xd8, 0x71, 0x25, 0x64, 0xc3, 0xbc, 0xd7, 0x7b, 0x9e, 0xa4, 0x34, 0x54, 0x48, 0x99, 0x40,
		0x7c, 0xff, 0x00, 0x99, 0x92, 0x0a, 0x93, 0x1a, 0x24, 0xc4, 0x41, 0x48, 0x52, 0xab, 0x29, 0xbd,
		0xb0, 0xa9, 0x5c, 0x06, 0x53, 0xf3, 0x6c, 0x60, 0xe6, 0x0b, 0xf9, 0x0b, 0x62, 0x58, 0xdd, 0xa5,
		0x6f, 0x37, 0x04, 0x7b, 0xa5, 0xc2, 0xd1, 0xd0, 0x29, 0xaf, 0x9c, 0x9d, 0x40, 0xba, 0xc7, 0xaa,
		0x41, 0xc7, 0x8a, 0x0d, 0xd1, 0x06, 0x8a, 0xdd, 0x69, 0x9e, 0x80, 0x8f, 0xea, 0x01, 0x1e, 0xa1,
		0x44, 0x1d, 0x8a, 0x4f, 0x7b, 0xb4, 0xe9, 0x7b, 0xe3, 0x9f, 0x55, 0xf1, 0xdd, 0xd4, 0x4e, 0x9c,
		0x4b, 0xa3, 0x35, 0x15, 0x97, 0x03, 0xd4, 0xd3, 0x4b, 0x60, 0x3e, 0x65, 0x14, 0x7a, 0x4f, 0x23,
		0xd6, 0xd3, 0xc0, 0x99, 0x6c, 0x75, 0xed, 0xee, 0x84, 0x6a, 0x82, 0xd1, 0x90, 0xae, 0x10, 0x78,
		0x3c, 0x96, 0x1c, 0xf0, 0x38, 0x7a, 0xed, 0x21, 0x06, 0xd2, 0xd0, 0x55, 0x5b, 0x6f, 0xd9, 0x37,
		0xfa, 0xd5, 0x53, 0x53, 0x87, 0xe0, 0xff, 0x72, 0xff, 0xbe, 0x78, 0x94, 0x14, 0x02, 0xb0, 0xb8,
		0x22, 0xea, 0x2a, 0x74, 0xb6, 0x05, 0x8c, 0x1d, 0xab, 0xf9, 0xb3, 0x4a, 0x76, 0xcb, 0x63, 0xb8,
		0x7f, 0xaa, 0x2c, 0x68, 0x47, 0xb8, 0xe2, 0x83, 0x7f, 0xff, 0x91, 0x18, 0x6e, 0x6b, 0x1c, 0x14,
		0x91, 0x1c, 0xf9, 0x89, 0xa8, 0x90, 0x92, 0xa8, 0x1c, 0xe6, 0x01, 0xdd, 0xac, 0xd3, 0xf9, 0xcf}
	n := big.NewInt(0)
	n.SetBytes(nBytes)
	if out.Rsa.N.Cmp(n) != 0 {
		t.Errorf("Incorrect modulus %+v, expecting %+v", out.Rsa.N, n)
		return
	}
}

func TestEcJwk(t *testing.T) {
	fmt.Println("--> TestEcJwk")
	in := `{
     "kty": "EC",
     "crv": "P-521",
     "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
     "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"
   }`
	var out JsonWebKey
	err := json.Unmarshal([]byte(in), &out)
	if err != nil {
		t.Errorf("JSON unmarshal error: %+v", err)
		return
	}

	if out.KeyType != "EC" {
		t.Errorf("Incorrect key type %+v, expecting %+v", out.KeyType, "RSA")
		return
	}

	if out.Ec == nil {
		t.Errorf("EC key not present")
		return
	}

	if out.Ec.Curve.Params().BitSize != 521 {
		t.Errorf("Incorrect curve size %+v, expecting %+v", out.Ec.Curve.Params().BitSize, 521)
		return
	}

	xBytes := []byte{
		0x00, 0x72, 0x99, 0x2c, 0xb3, 0xac, 0x08, 0xec, 0xf3, 0xe5, 0xc6,
		0x3d, 0xed, 0xec, 0x0d, 0x51, 0xa8, 0xc1, 0xf7, 0x9e, 0xf2, 0xf8,
		0x2f, 0x94, 0xf3, 0xc7, 0x37, 0xbf, 0x5d, 0xe7, 0x98, 0x66, 0x71,
		0xea, 0xc6, 0x25, 0xfe, 0x82, 0x57, 0xbb, 0xd0, 0x39, 0x46, 0x44,
		0xca, 0xaa, 0x3a, 0xaf, 0x8f, 0x27, 0xa4, 0x58, 0x5f, 0xbb, 0xca,
		0xd0, 0xf2, 0x45, 0x76, 0x20, 0x08, 0x5e, 0x5c, 0x8f, 0x42, 0xad}
	x := big.NewInt(0)
	x.SetBytes(xBytes)
	if out.Ec.X.Cmp(x) != 0 {
		t.Errorf("Incorrect X-coordinate %+v, expecting %+v", out.Ec.X, x)
		return
	}

	yBytes := []byte{
		0x01, 0xdc, 0xa6, 0x94, 0x7b, 0xce, 0x88, 0xbc, 0x57, 0x90, 0x48,
		0x5a, 0xc9, 0x74, 0x27, 0x34, 0x2b, 0xc3, 0x5f, 0x88, 0x7d, 0x86,
		0xd6, 0x5a, 0x08, 0x93, 0x77, 0xe2, 0x47, 0xe6, 0x0b, 0xaa, 0x55,
		0xe4, 0xe8, 0x50, 0x1e, 0x2a, 0xda, 0x57, 0x24, 0xac, 0x51, 0xd6,
		0x90, 0x90, 0x08, 0x03, 0x3e, 0xbc, 0x10, 0xac, 0x99, 0x9b, 0x9d,
		0x7f, 0x5c, 0xc2, 0x51, 0x9f, 0x3f, 0xe1, 0xea, 0x1d, 0x94, 0x75}
	y := big.NewInt(0)
	y.SetBytes(yBytes)
	if out.Ec.Y.Cmp(y) != 0 {
		t.Errorf("Incorrect X-coordinate %+v, expecting %+v", out.Ec.Y, y)
		return
	}
}

// JWS Tests (from draft-ietf-jose-cookbook)

func TestRsaJwsVerify(t *testing.T) {
	fmt.Println("--> TestRsaJwsVerify")
	in := `{
     "header": {
      "jwk": {
        "kty": "RSA",
        "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
        "e": "AQAB"
       }
     },
     "payload": "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4",
     "protected": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9",
     "signature": "MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmKZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4JIwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8wW1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluPxUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_fcIe8u9ipH84ogoree7vjbU5y18kDquDg"
   }`

	var out JsonWebSignature
	err := json.Unmarshal([]byte(in), &out)
	if err != nil {
		t.Errorf("JSON unmarshal error: %+v", err)
		return
	}

	err = out.Verify()
	if err != nil {
		t.Errorf("Signature failed verification: %+v", err)
		return
	}
}

func TestRsaPssJwsVerify(t *testing.T) {
	fmt.Println("--> TestRsaPssJwsVerify")
	in := `{
     "header": {
      "jwk": {
        "kty": "RSA",
        "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
        "e": "AQAB"
       }
     },
     "payload": "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4",
     "protected": "eyJhbGciOiJQUzM4NCIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9",
     "signature": "cu22eBqkYDKgIlTpzDXGvaFfz6WGoz7fUDcfT0kkOy42miAh2qyBzk1xEsnk2IpN6-tPid6VrklHkqsGqDqHCdP6O8TTB5dDDItllVo6_1OLPpcbUrhiUSMxbbXUvdvWXzg-UD8biiReQFlfz28zGWVsdiNAUf8ZnyPEgVFn442ZdNqiVJRmBqrYRXe8P_ijQ7p8Vdz0TTrxUeT3lm8d9shnr2lfJT8ImUjvAA2Xez2Mlp8cBE5awDzT0qI0n6uiP1aCN_2_jLAeQTlqRHtfa64QQSUmFAAjVKPbByi7xho0uTOcbH510a6GYmJUAfmWjwZ6oD4ifKo8DYM-X72Eaw"
   }`

	var out JsonWebSignature
	err := json.Unmarshal([]byte(in), &out)
	if err != nil {
		t.Errorf("JSON unmarshal error: %+v", err)
		return
	}

	err = out.Verify()
	if err != nil {
		t.Errorf("Signature failed verification: %+v", err)
		return
	}
}

func TestEcJwsVerify(t *testing.T) {
	fmt.Println("--> TestEcJwsVerify")
	in := `{
     "header": {
      "jwk": {
        "kty": "EC",
        "crv": "P-521",
        "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
        "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"
      }
     },
     "payload": "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4",
     "protected": "eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9",
     "signature": "AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvbu9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2"
   }`

	var out JsonWebSignature
	err := json.Unmarshal([]byte(in), &out)
	if err != nil {
		t.Errorf("JSON unmarshal error: %+v", err)
		return
	}

	err = out.Verify()
	if err != nil {
		t.Errorf("Signature failed verification: %+v", err)
		return
	}
}

func bigIntFromB64(b64 string) *big.Int {
	bytes, _ := b64dec(b64)
	x := big.NewInt(0)
	x.SetBytes(bytes)
	return x
}

func intFromB64(b64 string) int {
	return int(bigIntFromB64(b64).Int64())
}

func TestRsaJwsSign(t *testing.T) {
	fmt.Println("--> TestRsaJwsSign")
	n := bigIntFromB64("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw")
	e := intFromB64("AQAB")
	d := bigIntFromB64("bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ")
	p := bigIntFromB64("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc")
	q := bigIntFromB64("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc")
	priv := rsa.PrivateKey{
		rsa.PublicKey{N: n, E: e},
		d,
		[]*big.Int{p, q},
		rsa.PrecomputedValues{},
	}

	payload, _ := b64dec("It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.")

	jws, err := Sign(RSAPKCS1WithSHA256, priv, payload)
	if err != nil {
		t.Errorf("Signature generation failed: %+v", err)
		return
	}

	err = jws.Verify()
	if err != nil {
		t.Errorf("Signature failed verification: %+v", err)
		return
	}
}

func TestRsaPssJwsSign(t *testing.T) {
	fmt.Println("--> TestRsaPssJwsSign")
	n := bigIntFromB64("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw")
	e := intFromB64("AQAB")
	d := bigIntFromB64("bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ")
	p := bigIntFromB64("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc")
	q := bigIntFromB64("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc")
	priv := rsa.PrivateKey{
		rsa.PublicKey{N: n, E: e},
		d,
		[]*big.Int{p, q},
		rsa.PrecomputedValues{},
	}

	payload, _ := b64dec("It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.")

	jws, err := Sign(RSAPSSWithSHA256, priv, payload)
	if err != nil {
		t.Errorf("Signature generation failed: %+v", err)
		return
	}

	err = jws.Verify()
	if err != nil {
		t.Errorf("Signature failed verification: %+v", err)
		return
	}
}

func TestEcJwsSign(t *testing.T) {
	fmt.Println("--> TestEcJwsSign")
	x := bigIntFromB64("AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt")
	y := bigIntFromB64("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1")
	d := bigIntFromB64("AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt")

	priv := ecdsa.PrivateKey{ecdsa.PublicKey{elliptic.P521(), x, y}, d}

	payload, _ := b64dec("It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.")

	jws, err := Sign(ECDSAWithSHA512, priv, payload)
	if err != nil {
		t.Errorf("Signature generation failed: %+v", err)
		return
	}

	err = jws.Verify()
	if err != nil {
		// XXX: This sometimes failes, haven't debugged
		t.Errorf("Signature failed verification: %+v", err)
		return
	}
}

func TestJwsCompact(t *testing.T) {
	fmt.Println("--> TestJwsCompact")
	payload := []byte{0, 0, 0, 0}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
	}

	jws, err := Sign(RSAPSSWithSHA256, *priv, payload)
	if err != nil {
		t.Errorf("Signature generation failed: %+v", err)
		return
	}

	compact, err := jws.MarshalCompact()
	if err != nil {
		t.Errorf("Failed to marshal compact: %+v", err)
	}

	jws2, err := UnmarshalCompact(compact)
	if err != nil {
		t.Errorf("Failed to unmarshal compact: %+v", err)
	}

	err = jws2.Verify()
	if err != nil {
		t.Errorf("Signature failed verification: %+v", err)
		return
	}

}

// Testing node.js generated JWS
func TestRsaNodeJwsVerify(t *testing.T) {
	fmt.Println("--> TestRsaNodeJwsVerify")
	in := `{
    "header": {
        "alg": "RS256",
        "jwk": {
            "kty": "RSA",
            "n": "q_X8f1LAnSxsB-_MQ64XaigtXEljPAZZlJlep5NJrOzSH4m55GEXMbzmATzi-_WFulAqajfK_LY33hByxoXdrQ",
            "e": "AQAB"
        }
    },
    "protected": "eyJub25jZSI6IlJVUEZVVVZWX1d0bW8ycTVrcXgwUlEifQ",
    "payload": "aGVsbG8sIHdvcmxkIQ",
    "signature": "aGK0GWcCgvXzOZKR0Wn4YiKYUgtFKWFlDHcXL5T5CA5x5oyZrPovnJEyfU1IDHtQp0ZD-EbT05tSVMoeY48qHQ"
  }`

	var out JsonWebSignature
	err := json.Unmarshal([]byte(in), &out)
	if err != nil {
		t.Errorf("JSON unmarshal error: %+v", err)
		return
	}

	err = out.Verify()
	if err != nil {
		t.Errorf("Signature failed verification: %+v", err)
		return
	}
}
