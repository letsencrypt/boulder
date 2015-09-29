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

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"

	"github.com/letsencrypt/boulder/test"
)

func TestProblemDetails(t *testing.T) {
	pd := &ProblemDetails{
		Type:   MalformedProblem,
		Detail: "Wat? o.O"}
	test.AssertEquals(t, pd.Error(), "urn:acme:error:malformed :: Wat? o.O")
}

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
var testKey3, _ = rsa.GenerateKey(rand.Reader, 2048)

func TestAuthorizedKeys(t *testing.T) {
	ak1 := AuthorizedKey{
		Token: "99DrlWuy-4Nc82olAy0cK7Shnm4uV32pJovyucGEWME",
		Key:   &jose.JsonWebKey{Key: testKey1.Public()},
	}
	ak2 := AuthorizedKey{
		Token: "Iy2_-2OA8lyD0lwhmD8dD3TIL3wlNpiUhLTXPJG5qOM",
		Key:   &jose.JsonWebKey{Key: testKey2.Public()},
	}

	test.Assert(t, ak1.Match(ak1.Token, ak1.Key), "Authorized key should match itself")
	test.Assert(t, !ak1.Match(ak1.Token, ak2.Key), "Authorized key should not match a different key")
	test.Assert(t, !ak1.Match(ak2.Token, ak1.Key), "Authorized key should not match a different token")
	test.Assert(t, !ak1.Match(ak2.Token, ak2.Key), "Authorized key should not match a completely different key")

	test.Assert(t, ak1.MatchAuthorizedKey(ak1), "Authorized key should match itself")
	test.Assert(t, !ak1.MatchAuthorizedKey(ak2), "Authorized key should not match a completely different key")
}

func TestRecordSanityCheck(t *testing.T) {
	rec := []ValidationRecord{
		ValidationRecord{
			URL:               "http://localhost/test",
			Hostname:          "localhost",
			Port:              "80",
			AddressesResolved: []net.IP{net.IP{127, 0, 0, 1}},
			AddressUsed:       net.IP{127, 0, 0, 1},
		},
	}

	chall := Challenge{Type: ChallengeTypeSimpleHTTP, ValidationRecord: rec}
	test.Assert(t, chall.RecordsSane(), "Record should be sane")
	chall.ValidationRecord[0].URL = ""
	test.Assert(t, !chall.RecordsSane(), "Record should not be sane")

	chall = Challenge{Type: ChallengeTypeDVSNI, ValidationRecord: rec}
	chall.ValidationRecord[0].URL = ""
	test.Assert(t, chall.RecordsSane(), "Record should be sane")
	chall.ValidationRecord[0].Hostname = ""
	test.Assert(t, !chall.RecordsSane(), "Record should not be sane")

	chall.ValidationRecord = append(chall.ValidationRecord, rec...)
	test.Assert(t, !chall.RecordsSane(), "Record should not be sane")
}

//-----BEGIN TO DELETE-----
func TestChallengeSanityCheck_Legacy(t *testing.T) {
	// Make a temporary account key
	var accountKey *jose.JsonWebKey
	err := json.Unmarshal([]byte(`{
    "kty":"RSA",
    "n":"yNWVhtYEKJR21y9xsHV-PD_bYwbXSeNuFal46xYxVfRL5mqha7vttvjB_vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K_klBYN8oYvTwwmeSkAz6ut7ZxPv-nZaT5TJhGk0NT2kh_zSpdriEJ_3vW-mqxYbbBmpvHqsa1_zx9fSuHYctAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV-mzfMyboQjujPh7aNJxAWSq4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF-w8hOTI3XXohUdu29Se26k2B0PolDSuj0GIQU6-W9TdLXSjBb2SpQ",
    "e":"AQAB"
  }`), &accountKey)
	test.AssertNotError(t, err, "Error unmarshaling JWK")

	types := []string{ChallengeTypeSimpleHTTP, ChallengeTypeDVSNI}
	for _, challengeType := range types {
		chall := Challenge{
			Type:       challengeType,
			Status:     StatusInvalid,
			AccountKey: accountKey,
		}
		test.Assert(t, !chall.IsSane(false), "IsSane should be false")
		chall.Status = StatusPending
		test.Assert(t, !chall.IsSane(false), "IsSane should be false")
		chall.Token = ""
		test.Assert(t, !chall.IsSane(false), "IsSane should be false")
		chall.Token = "notlongenough"
		test.Assert(t, !chall.IsSane(false), "IsSane should be false")
		chall.Token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ+PCt92wr+o!"
		test.Assert(t, !chall.IsSane(false), "IsSane should be false")
		chall.Token = "KQqLsiS5j0CONR_eUXTUSUDNVaHODtc-0pD6ACif7U4"
		test.Assert(t, chall.IsSane(false), "IsSane should be true")

		// Post-completion tests differ by type
		if challengeType == ChallengeTypeSimpleHTTP {
			tls := true
			chall.TLS = &tls
			chall.ValidationRecord = []ValidationRecord{ValidationRecord{
				URL:               "",
				Hostname:          "localhost",
				Port:              "80",
				AddressesResolved: []net.IP{net.IP{127, 0, 0, 1}},
				AddressUsed:       net.IP{127, 0, 0, 1},
			}}
			test.Assert(t, chall.IsSane(true), "IsSane should be true")
		} else if challengeType == ChallengeTypeDVSNI {
			chall.Validation = new(jose.JsonWebSignature)
			if challengeType == ChallengeTypeDVSNI {
				chall.ValidationRecord = []ValidationRecord{ValidationRecord{
					Hostname:          "localhost",
					Port:              "80",
					AddressesResolved: []net.IP{net.IP{127, 0, 0, 1}},
					AddressUsed:       net.IP{127, 0, 0, 1},
				}}
			} else {
				chall.ValidationRecord = []ValidationRecord{}
			}
			test.Assert(t, chall.IsSane(true), "IsSane should be true")
		}
	}

	chall := Challenge{Type: "bogus", Status: StatusPending}
	test.Assert(t, !chall.IsSane(false), "IsSane should be false")
	test.Assert(t, !chall.IsSane(true), "IsSane should be false")
}

//-----END TO DELETE-----

func TestChallengeSanityCheck(t *testing.T) {
	// Make a temporary account key
	var accountKey *jose.JsonWebKey
	err := json.Unmarshal([]byte(`{
    "kty":"RSA",
    "n":"yNWVhtYEKJR21y9xsHV-PD_bYwbXSeNuFal46xYxVfRL5mqha7vttvjB_vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K_klBYN8oYvTwwmeSkAz6ut7ZxPv-nZaT5TJhGk0NT2kh_zSpdriEJ_3vW-mqxYbbBmpvHqsa1_zx9fSuHYctAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV-mzfMyboQjujPh7aNJxAWSq4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF-w8hOTI3XXohUdu29Se26k2B0PolDSuj0GIQU6-W9TdLXSjBb2SpQ",
    "e":"AQAB"
  }`), &accountKey)
	test.AssertNotError(t, err, "Error unmarshaling JWK")

	ak := AuthorizedKey{
		Token: "KQqLsiS5j0CONR_eUXTUSUDNVaHODtc-0pD6ACif7U4",
		Key:   accountKey,
	}
	jsonAK, err := json.Marshal(ak)
	test.AssertNotError(t, err, "Error marshaling authorized key")

	types := []string{ChallengeTypeHTTP01, ChallengeTypeTLSSNI01, ChallengeTypeDNS01}
	for _, challengeType := range types {
		chall := Challenge{
			Type:       challengeType,
			Status:     StatusInvalid,
			AccountKey: accountKey,
		}
		test.Assert(t, !chall.IsSane(false), "IsSane should be false")

		chall.Status = StatusPending
		test.Assert(t, !chall.IsSane(false), "IsSane should be false")

		chall.AuthorizedKey = jsonAK
		test.Assert(t, chall.IsSane(false), "IsSane should be true")

		chall.Token = ak.Token
		test.Assert(t, chall.IsSane(true), "IsSane should be true")
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
