package core

import (
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"net"
	"testing"

	"gopkg.in/square/go-jose.v1"

	"github.com/letsencrypt/boulder/test"
)

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

	types := []string{ChallengeTypeHTTP01, ChallengeTypeTLSSNI01, ChallengeTypeTLSSNI02, ChallengeTypeDNS01}
	for _, challengeType := range types {
		chall := Challenge{
			Type:   challengeType,
			Status: StatusInvalid,
		}
		test.AssertError(t, chall.CheckConsistencyForClientOffer(), "CheckConsistencyForClientOffer didn't return an error")

		chall.Status = StatusPending
		test.AssertError(t, chall.CheckConsistencyForClientOffer(), "CheckConsistencyForClientOffer didn't return an error")

		chall.Token = "KQqLsiS5j0CONR_eUXTUSUDNVaHODtc-0pD6ACif7U4"
		test.AssertNotError(t, chall.CheckConsistencyForClientOffer(), "CheckConsistencyForClientOffer returned an error")

		chall.ProvidedKeyAuthorization = chall.Token + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		test.AssertNotError(t, chall.CheckConsistencyForValidation(), "CheckConsistencyForValidation returned an error")

		chall.ProvidedKeyAuthorization = "aaaa.aaaa"
		test.AssertError(t, chall.CheckConsistencyForValidation(), "CheckConsistencyForValidation didn't return an error")
	}

	chall := Challenge{Type: "bogus", Status: StatusPending}
	test.AssertError(t, chall.CheckConsistencyForClientOffer(), "CheckConsistencyForClientOffer didn't return an error")
	test.AssertError(t, chall.CheckConsistencyForValidation(), "CheckConsistencyForValidation didn't return an error")
}

func TestJSONBufferUnmarshal(t *testing.T) {
	testStruct := struct {
		Buffer JSONBuffer
	}{}

	notValidBase64 := []byte(`{"Buffer":"!!!!"}`)
	err := json.Unmarshal(notValidBase64, &testStruct)
	test.Assert(t, err != nil, "Should have choked on invalid base64")
}
