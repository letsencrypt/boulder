// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net"
	"testing"

	"github.com/square/go-jose"

	"github.com/letsencrypt/boulder/test"
)

func TestRegistrationUpdate(t *testing.T) {
	oldURL, _ := ParseAcmeURL("http://old.invalid")
	newURL, _ := ParseAcmeURL("http://new.invalid")
	reg := Registration{
		ID:        1,
		Contact:   []*AcmeURL{oldURL},
		Agreement: "",
	}
	update := Registration{
		Contact:   []*AcmeURL{newURL},
		Agreement: "totally!",
	}

	reg.MergeUpdate(update)
	test.Assert(t, len(reg.Contact) == 1 && reg.Contact[0] == update.Contact[0], "Contact was not updated %v != %v")
	test.Assert(t, reg.Agreement == update.Agreement, "Agreement was not updated")
}

var testKey1, _ = rsa.GenerateKey(rand.Reader, 2048)
var testKey2, _ = rsa.GenerateKey(rand.Reader, 2048)

func TestKeyAuthorization(t *testing.T) {
	jwk1 := &jose.JsonWebKey{Key: testKey1.Public()}
	jwk2 := &jose.JsonWebKey{Key: testKey2.Public()}

	ka1, err := NewKeyAuthorization("99DrlWuy-4Nc82olAy0cK7Shnm4uV32pJovyucGEWME", jwk1)
	test.AssertNotError(t, err, "Failed to create a new key authorization")
	ka2, err := NewKeyAuthorization("Iy2_-2OA8lyD0lwhmD8dD3TIL3wlNpiUhLTXPJG5qOM", jwk2)
	test.AssertNotError(t, err, "Failed to create a new key authorization")

	test.Assert(t, ka1.Match(ka1.Token, jwk1), "Authorized key should match itself")
	test.Assert(t, !ka1.Match(ka1.Token, jwk2), "Authorized key should not match a different key")
	test.Assert(t, !ka1.Match(ka2.Token, jwk1), "Authorized key should not match a different token")
	test.Assert(t, !ka1.Match(ka2.Token, jwk2), "Authorized key should not match a completely different key")
}

func TestRecordSanityCheckOnUnsupportChallengeType(t *testing.T) {
	rec := []ValidationRecord{
		{
			URL:               "http://localhost/test",
			Hostname:          "localhost",
			Port:              "80",
			AddressesResolved: []net.IP{{127, 0, 0, 1}},
			AddressUsed:       net.IP{127, 0, 0, 1},
		},
	}

	chall := Challenge{Type: "obsoletedChallenge", ValidationRecord: rec}
	test.Assert(t, !chall.RecordsSane(), "Record with unsupported challenge type should not be sane")
}

func TestChallengeSanityCheck(t *testing.T) {
	// Make a temporary account key
	var accountKey *jose.JsonWebKey
	err := json.Unmarshal([]byte(`{
    "kty":"RSA",
    "n":"yNWVhtYEKJR21y9xsHV-PD_bYwbXSeNuFal46xYxVfRL5mqha7vttvjB_vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K_klBYN8oYvTwwmeSkAz6ut7ZxPv-nZaT5TJhGk0NT2kh_zSpdriEJ_3vW-mqxYbbBmpvHqsa1_zx9fSuHYctAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV-mzfMyboQjujPh7aNJxAWSq4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF-w8hOTI3XXohUdu29Se26k2B0PolDSuj0GIQU6-W9TdLXSjBb2SpQ",
    "e":"AQAB"
  }`), &accountKey)
	test.AssertNotError(t, err, "Error unmarshaling JWK")

	ka, err := NewKeyAuthorization("KQqLsiS5j0CONR_eUXTUSUDNVaHODtc-0pD6ACif7U4", accountKey)
	const badKeyAuthorization = "aaaa.aaaa"
	test.AssertNotError(t, err, "Error creating key authorization")

	types := []string{ChallengeTypeHTTP01, ChallengeTypeTLSSNI01, ChallengeTypeDNS01}
	for _, challengeType := range types {
		chall := Challenge{
			Type:       challengeType,
			Status:     StatusInvalid,
			AccountKey: accountKey,
		}
		test.Assert(t, !chall.IsSaneForClientOffer(), "IsSane should be false")

		chall.Status = StatusPending
		test.Assert(t, !chall.IsSaneForClientOffer(), "IsSane should be false")

		chall.Token = ka.Token
		test.Assert(t, chall.IsSaneForClientOffer(), "IsSane should be true")

		chall.ProvidedKeyAuthorization = ka.String()
		test.Assert(t, chall.IsSaneForValidation(), "IsSane should be true")

		chall.ProvidedKeyAuthorization = badKeyAuthorization
		test.Assert(t, !chall.IsSaneForValidation(), "IsSane should be false")
	}

	chall := Challenge{Type: "bogus", Status: StatusPending}
	test.Assert(t, !chall.IsSane(false), "IsSane should be false")
	test.Assert(t, !chall.IsSane(true), "IsSane should be false")
}

func TestJSONBufferUnmarshal(t *testing.T) {
	testStruct := struct {
		Buffer JSONBuffer
	}{}

	notValidBase64 := []byte(`{"Buffer":"!!!!"}`)
	err := json.Unmarshal(notValidBase64, &testStruct)
	test.Assert(t, err != nil, "Should have choked on invalid base64")
}
