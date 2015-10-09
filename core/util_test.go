// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net/url"
	"sort"
	"testing"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"
	"github.com/letsencrypt/boulder/test"
)

// challenges.go
func TestNewToken(t *testing.T) {
	token := NewToken()
	fmt.Println(token)
	tokenLength := int(math.Ceil(32 * 8 / 6.0)) // 32 bytes, b64 encoded
	test.AssertIntEquals(t, len(token), tokenLength)
	collider := map[string]bool{}
	// Test for very blatant RNG failures:
	// Try 2^20 birthdays in a 2^72 search space...
	// our naive collision probability here is  2^-32...
	for i := 0; i < 1000000; i++ {
		token = NewToken()[:12] // just sample a portion
		test.Assert(t, !collider[token], "Token collision!")
		collider[token] = true
	}
	return
}

func TestLooksLikeAToken(t *testing.T) {
	test.Assert(t, !LooksLikeAToken("R-UL_7MrV3tUUjO9v5ym2srK3dGGCwlxbVyKBdwLOS"), "Accepted short token")
	test.Assert(t, !LooksLikeAToken("R-UL_7MrV3tUUjO9v5ym2srK3dGGCwlxbVyKBdwLOS%"), "Accepted invalid token")
	test.Assert(t, LooksLikeAToken("R-UL_7MrV3tUUjO9v5ym2srK3dGGCwlxbVyKBdwLOSU"), "Rejected valid token")
}

func TestSerialUtils(t *testing.T) {
	serial := SerialToString(big.NewInt(100000000000000000))
	test.AssertEquals(t, serial, "00000000000000000000016345785d8a0000")

	serialNum, err := StringToSerial("00000000000000000000016345785d8a0000")
	test.AssertNotError(t, err, "Couldn't convert serial number to *big.Int")
	test.AssertBigIntEquals(t, serialNum, big.NewInt(100000000000000000))

	badSerial, err := StringToSerial("doop!!!!000")
	test.AssertEquals(t, fmt.Sprintf("%v", err), "Invalid serial number")
	fmt.Println(badSerial)
}

func TestBuildID(t *testing.T) {
	test.AssertEquals(t, "Unspecified", GetBuildID())
}

const JWK1JSON = `{
  "kty": "RSA",
  "n": "vuc785P8lBj3fUxyZchF_uZw6WtbxcorqgTyq-qapF5lrO1U82Tp93rpXlmctj6fyFHBVVB5aXnUHJ7LZeVPod7Wnfl8p5OyhlHQHC8BnzdzCqCMKmWZNX5DtETDId0qzU7dPzh0LP0idt5buU7L9QNaabChw3nnaL47iu_1Di5Wp264p2TwACeedv2hfRDjDlJmaQXuS8Rtv9GnRWyC9JBu7XmGvGDziumnJH7Hyzh3VNu-kSPQD3vuAFgMZS6uUzOztCkT0fpOalZI6hqxtWLvXUMj-crXrn-Maavz8qRhpAyp5kcYk3jiHGgQIi7QSK2JIdRJ8APyX9HlmTN5AQ",
  "e": "AQAB"
}`
const JWK1Digest = `ul04Iq07ulKnnrebv2hv3yxCGgVvoHs8hjq2tVKx3mc=`
const JWK1Thumbprint = `-kVpHjJCDNQQk-j9BGMpzHAVCiOqvoTRZB-Ov4CAiM4`
const JWK2JSON = `{
  "kty":"RSA",
  "n":"yTsLkI8n4lg9UuSKNRC0UPHsVjNdCYk8rGXIqeb_rRYaEev3D9-kxXY8HrYfGkVt5CiIVJ-n2t50BKT8oBEMuilmypSQqJw0pCgtUm-e6Z0Eg3Ly6DMXFlycyikegiZ0b-rVX7i5OCEZRDkENAYwFNX4G7NNCwEZcH7HUMUmty9dchAqDS9YWzPh_dde1A9oy9JMH07nRGDcOzIh1rCPwc71nwfPPYeeS4tTvkjanjeigOYBFkBLQuv7iBB4LPozsGF1XdoKiIIi-8ye44McdhOTPDcQp3xKxj89aO02pQhBECv61rmbPinvjMG9DYxJmZvjsKF4bN2oy0DxdC1jDw",
  "e":"AQAB"
}`

func TestKeyThumbprint(t *testing.T) {
	var jwk jose.JsonWebKey
	json.Unmarshal([]byte(JWK1JSON), &jwk)
	thumbprint, err := Thumbprint(&jwk)

	test.AssertNotError(t, err, "Failed to compute JWK digest")
	test.AssertEquals(t, thumbprint, JWK1Thumbprint)
}

func TestKeyDigest(t *testing.T) {
	// Test with JWK (value, reference, and direct)
	var jwk jose.JsonWebKey
	json.Unmarshal([]byte(JWK1JSON), &jwk)
	digest, err := KeyDigest(jwk)
	test.Assert(t, err == nil && digest == JWK1Digest, "Failed to digest JWK by value")
	digest, err = KeyDigest(&jwk)
	test.Assert(t, err == nil && digest == JWK1Digest, "Failed to digest JWK by reference")
	digest, err = KeyDigest(jwk.Key)
	test.Assert(t, err == nil && digest == JWK1Digest, "Failed to digest bare key")

	// Test with unknown key type
	digest, err = KeyDigest(struct{}{})
	test.Assert(t, err != nil, "Should have rejected unknown key type")
}

func TestKeyDigestEquals(t *testing.T) {
	var jwk1, jwk2 jose.JsonWebKey
	json.Unmarshal([]byte(JWK1JSON), &jwk1)
	json.Unmarshal([]byte(JWK2JSON), &jwk2)

	test.Assert(t, KeyDigestEquals(jwk1, jwk1), "Key digests for same key should match")
	test.Assert(t, !KeyDigestEquals(jwk1, jwk2), "Key digests for different keys should not match")
	test.Assert(t, !KeyDigestEquals(jwk1, struct{}{}), "Unknown key types should not match anything")
	test.Assert(t, !KeyDigestEquals(struct{}{}, struct{}{}), "Unknown key types should not match anything")
}

func TestAcmeURL(t *testing.T) {
	s := "http://example.invalid"
	u, _ := url.Parse(s)
	a := (*AcmeURL)(u)
	test.AssertEquals(t, s, a.String())
}

func TestUniqueLowerNames(t *testing.T) {
	u := UniqueLowerNames([]string{"foobar.com", "fooBAR.com", "baz.com", "foobar.com", "bar.com", "bar.com"})
	sort.Strings(u)
	test.AssertDeepEquals(t, []string{"bar.com", "baz.com", "foobar.com"}, u)
}
