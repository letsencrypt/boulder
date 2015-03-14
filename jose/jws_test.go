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
	bytes, _ := B64dec(b64)
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

	payload, _ := B64dec("It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.")

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

	payload, _ := B64dec("It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.")

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

	payload, _ := B64dec("It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.")

	jws, err := Sign(ECDSAWithSHA512, priv, payload)
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

func TestConcatRS(t *testing.T) {
	r, s := big.NewInt(0), big.NewInt(0)

	r.SetBytes([]byte{1, 2})
	s.SetBytes([]byte{3})
	if c := concatRS(r, s); !bytes.Equal(c, []byte{1, 2, 0, 3}) {
		t.Errorf("Couldn't concat %v and %v: %v", r.Bytes(), s.Bytes(), c)
	}

	s.SetBytes([]byte{3, 4})
	if c := concatRS(r, s); !bytes.Equal(c, []byte{1, 2, 3, 4}) {
		t.Errorf("Couldn't concat %v and %v: %v", r.Bytes(), s.Bytes(), c)
	}

	s.SetBytes([]byte{3, 4, 5})
	if c := concatRS(r, s); !bytes.Equal(c, []byte{0, 1, 2, 3, 4, 5}) {
		t.Errorf("Couldn't concat %v and %v: %v", r.Bytes(), s.Bytes(), c)
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
