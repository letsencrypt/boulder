package core

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/letsencrypt/boulder/test"
)

// challenges.go

var accountKeyJSON = `{
  "kty":"RSA",
  "n":"yNWVhtYEKJR21y9xsHV-PD_bYwbXSeNuFal46xYxVfRL5mqha7vttvjB_vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K_klBYN8oYvTwwmeSkAz6ut7ZxPv-nZaT5TJhGk0NT2kh_zSpdriEJ_3vW-mqxYbbBmpvHqsa1_zx9fSuHYctAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV-mzfMyboQjujPh7aNJxAWSq4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF-w8hOTI3XXohUdu29Se26k2B0PolDSuj0GIQU6-W9TdLXSjBb2SpQ",
  "e":"AQAB"
}`

func TestChallenges(t *testing.T) {
	var accountKey *jose.JSONWebKey
	err := json.Unmarshal([]byte(accountKeyJSON), &accountKey)
	if err != nil {
		t.Errorf("Error unmarshaling JWK: %v", err)
	}

	token := NewToken()
	http01 := HTTPChallenge01(token)
	test.AssertNotError(t, http01.CheckPending(), "CheckPending returned an error")

	dns01 := DNSChallenge01(token)
	test.AssertNotError(t, dns01.CheckPending(), "CheckPending returned an error")

	dnsAccount01 := DNSAccountChallenge01(token)
	test.AssertNotError(t, dnsAccount01.CheckPending(), "CheckPending returned an error")

	dnsPersist01 := DNSPersistChallenge01()
	test.AssertNotError(t, dnsPersist01.CheckPending(), "CheckPending returned an error")

	tlsalpn01 := TLSALPNChallenge01(token)
	test.AssertNotError(t, tlsalpn01.CheckPending(), "CheckPending returned an error")

	test.Assert(t, ChallengeTypeHTTP01.IsValid(), "Refused valid challenge")
	test.Assert(t, ChallengeTypeDNS01.IsValid(), "Refused valid challenge")
	test.Assert(t, ChallengeTypeTLSALPN01.IsValid(), "Refused valid challenge")
	test.Assert(t, ChallengeTypeDNSAccount01.IsValid(), "Refused valid challenge")
	test.Assert(t, ChallengeTypeDNSPersist01.IsValid(), "Refused valid challenge")
	test.Assert(t, !AcmeChallenge("nonsense-71").IsValid(), "Accepted invalid challenge")
}

// util.go

func TestRandomString(t *testing.T) {
	byteLength := 256
	b64 := RandomString(byteLength)
	bin, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		t.Errorf("Error in base64 decode: %v", err)
	}
	if len(bin) != byteLength {
		t.Errorf("Improper length: %v", len(bin))
	}

	token := NewToken()
	if len(token) != 43 {
		t.Errorf("Improper length for token: %v %v", len(token), token)
	}
}

func TestFingerprint(t *testing.T) {
	in := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	out := []byte{55, 71, 8, 255, 247, 113, 157, 213,
		151, 158, 200, 117, 213, 108, 210, 40,
		111, 109, 60, 247, 236, 49, 122, 59,
		37, 99, 42, 171, 40, 236, 55, 187}

	digest := Fingerprint256(in)
	if digest != base64.RawURLEncoding.EncodeToString(out) {
		t.Errorf("Incorrect SHA-256 fingerprint: %v", digest)
	}
}

func TestErrOnLimitReader(t *testing.T) {
	// test a read where the limit is larger than the source
	strReader := strings.NewReader("foo bar baz bot")
	lmr := ErrOnLimitReader(strReader, 21)

	strOut01, err := io.ReadAll(lmr)

	// should return no err, and the full source
	test.AssertNotError(t, err, "unexpectedly errored")
	test.AssertEquals(t, string(strOut01), "foo bar baz bot")

	// test a read where the limit exactly matches source size
	strReader = strings.NewReader("foo bar baz bot")
	lmr = ErrOnLimitReader(strReader, 15)

	strOut02, err := io.ReadAll(lmr)

	// should return an error, and the full source
	test.AssertError(t, err, "unexpectedly succeeded")
	test.AssertEquals(t, err, ErrReaderLimitReached)
	test.AssertEquals(t, string(strOut02), "foo bar baz bot")

	// test a read where the limit is lower than the source
	strReader = strings.NewReader("foo bar baz bot")
	lmr = ErrOnLimitReader(strReader, 9)

	strOut03, err := io.ReadAll(lmr)

	// should return an error, and a partial read result
	test.AssertError(t, err, "unexpectedly succeeded")
	test.AssertEquals(t, err, ErrReaderLimitReached)
	test.AssertEquals(t, string(strOut03), "foo bar b")

}
