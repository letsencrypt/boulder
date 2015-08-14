// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sa

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/test"

	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"
)

const JWK1JSON = `{
  "kty": "RSA",
  "n": "vuc785P8lBj3fUxyZchF_uZw6WtbxcorqgTyq-qapF5lrO1U82Tp93rpXlmctj6fyFHBVVB5aXnUHJ7LZeVPod7Wnfl8p5OyhlHQHC8BnzdzCqCMKmWZNX5DtETDId0qzU7dPzh0LP0idt5buU7L9QNaabChw3nnaL47iu_1Di5Wp264p2TwACeedv2hfRDjDlJmaQXuS8Rtv9GnRWyC9JBu7XmGvGDziumnJH7Hyzh3VNu-kSPQD3vuAFgMZS6uUzOztCkT0fpOalZI6hqxtWLvXUMj-crXrn-Maavz8qRhpAyp5kcYk3jiHGgQIi7QSK2JIdRJ8APyX9HlmTN5AQ",
  "e": "AQAB"
}`

func bigIntFromB64(b64 string) *big.Int {
	bytes, _ := base64.URLEncoding.DecodeString(b64)
	x := big.NewInt(0)
	x.SetBytes(bytes)
	return x
}

func intFromB64(b64 string) int {
	return int(bigIntFromB64(b64).Int64())
}

var n = bigIntFromB64("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw==")
var e = intFromB64("AQAB")
var d = bigIntFromB64("bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ==")
var p = bigIntFromB64("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc=")
var q = bigIntFromB64("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc=")

var TheKey = rsa.PrivateKey{
	PublicKey: rsa.PublicKey{N: n, E: e},
	D:         d,
	Primes:    []*big.Int{p, q},
}

func TestAcmeIdentifier(t *testing.T) {
	tc := BoulderTypeConverter{}

	ai := core.AcmeIdentifier{Type: "data1", Value: "data2"}
	out := core.AcmeIdentifier{}

	marshaledI, err := tc.ToDb(ai)
	test.AssertNotError(t, err, "Could not ToDb")

	scanner, ok := tc.FromDb(&out)
	test.Assert(t, ok, "FromDb failed")
	if !ok {
		t.FailNow()
		return
	}

	marshaled := marshaledI.(string)
	err = scanner.Binder(&marshaled, &out)
	test.AssertMarshaledEquals(t, ai, out)
}

func TestJsonWebKey(t *testing.T) {
	tc := BoulderTypeConverter{}

	var jwk, out jose.JsonWebKey
	json.Unmarshal([]byte(JWK1JSON), &jwk)

	marshaledI, err := tc.ToDb(jwk)
	test.AssertNotError(t, err, "Could not ToDb")

	scanner, ok := tc.FromDb(&out)
	test.Assert(t, ok, "FromDb failed")
	if !ok {
		t.FailNow()
		return
	}

	marshaled := marshaledI.(string)
	err = scanner.Binder(&marshaled, &out)
	test.AssertMarshaledEquals(t, jwk, out)
}

func TestAcmeStatus(t *testing.T) {
	tc := BoulderTypeConverter{}

	var as, out core.AcmeStatus
	as = "core.AcmeStatus"

	marshaledI, err := tc.ToDb(as)
	test.AssertNotError(t, err, "Could not ToDb")

	scanner, ok := tc.FromDb(&out)
	test.Assert(t, ok, "FromDb failed")
	if !ok {
		t.FailNow()
		return
	}

	marshaled := marshaledI.(string)
	err = scanner.Binder(&marshaled, &out)
	test.AssertMarshaledEquals(t, as, out)
}

func TestOCSPStatus(t *testing.T) {
	tc := BoulderTypeConverter{}

	var os, out core.OCSPStatus
	os = "core.OCSPStatus"

	marshaledI, err := tc.ToDb(os)
	test.AssertNotError(t, err, "Could not ToDb")

	scanner, ok := tc.FromDb(&out)
	test.Assert(t, ok, "FromDb failed")
	if !ok {
		t.FailNow()
		return
	}

	marshaled := marshaledI.(string)
	err = scanner.Binder(&marshaled, &out)
	test.AssertMarshaledEquals(t, os, out)
}

func TestAcmeURLSlice(t *testing.T) {
	tc := BoulderTypeConverter{}
	var au, out []*core.AcmeURL

	marshaledI, err := tc.ToDb(au)
	test.AssertNotError(t, err, "Could not ToDb")

	scanner, ok := tc.FromDb(&out)
	test.Assert(t, ok, "FromDb failed")
	if !ok {
		t.FailNow()
		return
	}

	marshaled := marshaledI.(string)
	err = scanner.Binder(&marshaled, &out)
	test.AssertMarshaledEquals(t, au, out)
}

func TestAcmeURL(t *testing.T) {
	tc := BoulderTypeConverter{}
	var au, out *core.AcmeURL
	au = &core.AcmeURL{}

	marshaledI, err := tc.ToDb(au)
	test.AssertNotError(t, err, "Could not ToDb")

	scanner, ok := tc.FromDb(&out)
	test.Assert(t, ok, "FromDb failed")
	if !ok {
		t.FailNow()
		return
	}

	marshaled := marshaledI.(string)
	err = scanner.Binder(&marshaled, &out)
	test.AssertMarshaledEquals(t, au, out)

	aURL, _ := core.ParseAcmeURL("http://www.example.com/stuff?things=10")
	*au = *aURL
	marshaledI, err = tc.ToDb(au)
	test.AssertNotError(t, err, "Could not ToDb")

	scanner, ok = tc.FromDb(&out)
	test.Assert(t, ok, "FromDb failed")
	if !ok {
		t.FailNow()
		return
	}

	marshaled = marshaledI.(string)
	err = scanner.Binder(&marshaled, &out)
	test.AssertMarshaledEquals(t, au, out)
}

func TestJsonWebSignature(t *testing.T) {
	tc := BoulderTypeConverter{}

	var out *jose.JsonWebSignature
	validationPayload, _ := json.Marshal(map[string]interface{}{
		"type":  "type",
		"token": "token",
	})
	signer, _ := jose.NewSigner(jose.RS256, &TheKey)
	jws, _ := signer.Sign(validationPayload, "")

	marshaledI, err := tc.ToDb(jws)
	test.AssertNotError(t, err, "Could not ToDb")

	scanner, ok := tc.FromDb(&out)
	test.Assert(t, ok, "FromDb failed")
	if !ok {
		t.FailNow()
		return
	}

	marshaled := marshaledI.([]byte)
	err = scanner.Binder(&marshaled, &out)
	test.AssertMarshaledEquals(t, jws, out)
}
