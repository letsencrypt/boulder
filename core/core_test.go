package core

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"gopkg.in/square/go-jose.v2"

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
	test.AssertNotError(t, http01.CheckConsistencyForClientOffer(), "CheckConsistencyForClientOffer returned an error")

	dns01 := DNSChallenge01(token)
	test.AssertNotError(t, dns01.CheckConsistencyForClientOffer(), "CheckConsistencyForClientOffer returned an error")

	tlsalpn01 := TLSALPNChallenge01(token)
	test.AssertNotError(t, tlsalpn01.CheckConsistencyForClientOffer(), "CheckConsistencyForClientOffer returned an error")

	test.Assert(t, ChallengeTypeHTTP01.IsValid(), "Refused valid challenge")
	test.Assert(t, ChallengeTypeDNS01.IsValid(), "Refused valid challenge")
	test.Assert(t, ChallengeTypeTLSALPN01.IsValid(), "Refused valid challenge")
	test.Assert(t, !AcmeChallenge("nonsense-71").IsValid(), "Accepted invalid challenge")
}

// objects.go

var testCertificateRequestBadCSR = []byte(`{"csr":"AAAA"}`)
var testCertificateRequestGood = []byte(`{
  "csr": "MIHRMHgCAQAwFjEUMBIGA1UEAxMLZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQWUlnRrm5ErSVkTzBTk3isg1hNydfyY4NM1P_N1S-ZeD39HMrYJsQkUh2tKvy3ztfmEqWpekvO4WRktSa000BPoAAwCgYIKoZIzj0EAwMDSQAwRgIhAIZIBwu4xOUD_4dJuGgceSKaoXTFBQKA3BFBNVJvbpdsAiEAlfq3Dq_8dnYbtmyDdXgopeKkSV5_76VSpcog-wkwEwo"
}`)

func TestCertificateRequest(t *testing.T) {

	// Good
	var goodCR CertificateRequest
	err := json.Unmarshal(testCertificateRequestGood, &goodCR)
	if err != nil {
		t.Errorf("Error unmarshaling good certificate request: %v", err)
	}
	if err = goodCR.CSR.CheckSignature(); err != nil {
		t.Errorf("Valid CSR in CertificateRequest failed to verify: %v", err)
	}

	// Bad CSR
	var badCR CertificateRequest
	err = json.Unmarshal(testCertificateRequestBadCSR, &badCR)
	if err == nil {
		t.Errorf("Unexpectedly accepted certificate request with bad CSR")
	}

	// Marshal
	jsonCR, err := json.Marshal(goodCR)
	if err != nil {
		t.Errorf("Failed to marshal good certificate request: %v", err)
	}
	err = json.Unmarshal(jsonCR, &goodCR)
	if err != nil {
		t.Errorf("Marshalled certificate request failed to unmarshal: %v", err)
	}
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
