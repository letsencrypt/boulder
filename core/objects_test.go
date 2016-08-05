package core

import (
	"crypto/rsa"
	"encoding/json"
	"math/big"
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
		Contact:   &[]*AcmeURL{oldURL},
		Agreement: "",
	}
	update := Registration{
		Contact:   &[]*AcmeURL{newURL},
		Agreement: "totally!",
	}

	changed := reg.MergeUpdate(update)
	test.AssertEquals(t, changed, true)
	test.Assert(t, len(*reg.Contact) == 1 && (*reg.Contact)[0] == (*update.Contact)[0], "Contact was not updated %v != %v")
	test.Assert(t, reg.Agreement == update.Agreement, "Agreement was not updated")

	// Make sure that a `MergeUpdate` call with a nil entry doesn't produce an
	// error and results in a change to the base reg.
	nilUpdate := Registration{
		Contact:   &[]*AcmeURL{nil},
		Agreement: "totally!",
	}
	changed = reg.MergeUpdate(nilUpdate)
	test.AssertEquals(t, changed, true)
}

func TestRegistrationContactUpdate(t *testing.T) {
	contactURL, _ := ParseAcmeURL("mailto://example@example.com")
	fullReg := Registration{
		ID:        1,
		Contact:   &[]*AcmeURL{contactURL},
		Agreement: "totally!",
	}

	// Test that a registration contact can be removed by updating with an empty
	// Contact slice.
	reg := fullReg
	var contactRemoveUpdate Registration
	contactRemoveJSON := []byte(`
	{
		"key": {
			"e": "AQAB",
			"kty": "RSA",
			"n": "tSwgy3ORGvc7YJI9B2qqkelZRUC6F1S5NwXFvM4w5-M0TsxbFsH5UH6adigV0jzsDJ5imAechcSoOhAh9POceCbPN1sTNwLpNbOLiQQ7RD5mY_"
		},
		"id": 1,
		"contact": [],
		"agreement": "totally!"
	}
	`)
	err := json.Unmarshal(contactRemoveJSON, &contactRemoveUpdate)
	test.AssertNotError(t, err, "Failed to unmarshal contactRemoveJSON")
	changed := reg.MergeUpdate(contactRemoveUpdate)
	test.AssertEquals(t, changed, true)
	test.Assert(t, len(*reg.Contact) == 0, "Contact was not deleted in update")

	// Test that a registration contact isn't changed when an update is performed
	// with no Contact field
	reg = fullReg
	var contactSameUpdate Registration
	contactSameJSON := []byte(`
	{
		"key": {
			"e": "AQAB",
			"kty": "RSA",
			"n": "tSwgy3ORGvc7YJI9B2qqkelZRUC6F1S5NwXFvM4w5-M0TsxbFsH5UH6adigV0jzsDJ5imAechcSoOhAh9POceCbPN1sTNwLpNbOLiQQ7RD5mY_"
		},
		"id": 1,
		"agreement": "totally!"
	}
	`)
	err = json.Unmarshal(contactSameJSON, &contactSameUpdate)
	test.AssertNotError(t, err, "Failed to unmarshal contactSameJSON")
	changed = reg.MergeUpdate(contactSameUpdate)
	test.AssertEquals(t, changed, false)
	test.Assert(t, len(*reg.Contact) == 1, "len(Contact) was updated unexpectedly")
	test.Assert(t, (*reg.Contact)[0].String() == "mailto://example@example.com", "Contact was changed unexpectedly")
}

func TestExpectedKeyAuthorization(t *testing.T) {
	ch := Challenge{Token: "hi"}
	jwk1 := &jose.JsonWebKey{Key: &rsa.PublicKey{N: big.NewInt(1234), E: 1234}}
	jwk2 := &jose.JsonWebKey{Key: &rsa.PublicKey{N: big.NewInt(5678), E: 5678}}

	ka1, err := ch.ExpectedKeyAuthorization(jwk1)
	test.AssertNotError(t, err, "Failed to calculate expected key authorization 1")
	ka2, err := ch.ExpectedKeyAuthorization(jwk2)
	test.AssertNotError(t, err, "Failed to calculate expected key authorization 2")

	expected1 := "hi.sIMEyhkWCCSYqDqZqPM1bKkvb5T9jpBOb7_w5ZNorF4"
	expected2 := "hi.FPoiyqWPod2T0fKqkPI1uXPYUsRK1DSyzsQsv0oMuGg"
	if ka1 != expected1 {
		t.Errorf("Incorrect ka1. Expected [%s], got [%s]", expected1, ka1)
	}
	if ka2 != expected2 {
		t.Errorf("Incorrect ka2. Expected [%s], got [%s]", expected2, ka2)
	}
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

	types := []string{ChallengeTypeHTTP01, ChallengeTypeTLSSNI01, ChallengeTypeDNS01}
	for _, challengeType := range types {
		chall := Challenge{
			Type:   challengeType,
			Status: StatusInvalid,
		}
		test.Assert(t, !chall.IsSaneForClientOffer(), "IsSane should be false")

		chall.Status = StatusPending
		test.Assert(t, !chall.IsSaneForClientOffer(), "IsSane should be false")

		chall.Token = "KQqLsiS5j0CONR_eUXTUSUDNVaHODtc-0pD6ACif7U4"
		test.Assert(t, chall.IsSaneForClientOffer(), "IsSane should be true")

		chall.ProvidedKeyAuthorization = chall.Token + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		test.Assert(t, chall.IsSaneForValidation(), "IsSane should be true")

		chall.ProvidedKeyAuthorization = "aaaa.aaaa"
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
