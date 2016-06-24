package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/letsencrypt/boulder/test"
	"github.com/square/go-jose"
)

// challenges.go

var accountKeyJSON = `{
  "kty":"RSA",
  "n":"yNWVhtYEKJR21y9xsHV-PD_bYwbXSeNuFal46xYxVfRL5mqha7vttvjB_vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K_klBYN8oYvTwwmeSkAz6ut7ZxPv-nZaT5TJhGk0NT2kh_zSpdriEJ_3vW-mqxYbbBmpvHqsa1_zx9fSuHYctAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV-mzfMyboQjujPh7aNJxAWSq4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF-w8hOTI3XXohUdu29Se26k2B0PolDSuj0GIQU6-W9TdLXSjBb2SpQ",
  "e":"AQAB"
}`

func TestChallenges(t *testing.T) {
	var accountKey *jose.JsonWebKey
	err := json.Unmarshal([]byte(accountKeyJSON), &accountKey)
	if err != nil {
		t.Errorf("Error unmarshaling JWK: %v", err)
	}

	http01 := HTTPChallenge01()
	if !http01.IsSane(false) {
		t.Errorf("New http-01 challenge is not sane: %v", http01)
	}

	tlssni01 := TLSSNIChallenge01()
	if !tlssni01.IsSane(false) {
		t.Errorf("New tls-sni-01 challenge is not sane: %v", tlssni01)
	}

	dns01 := DNSChallenge01()
	if !dns01.IsSane(false) {
		t.Errorf("New dns-01 challenge is not sane: %v", dns01)
	}

	test.Assert(t, ValidChallenge(ChallengeTypeHTTP01), "Refused valid challenge")
	test.Assert(t, ValidChallenge(ChallengeTypeTLSSNI01), "Refused valid challenge")
	test.Assert(t, ValidChallenge(ChallengeTypeDNS01), "Refused valid challenge")
	test.Assert(t, !ValidChallenge("nonsense-71"), "Accepted invalid challenge")
}

// objects.go

var testCertificateRequestBadCSR = []byte(`{"csr":"AAAA"}`)
var testCertificateRequestGood = []byte(`{
  "csr": "MIHRMHgCAQAwFjEUMBIGA1UEAxMLZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQWUlnRrm5ErSVkTzBTk3isg1hNydfyY4NM1P_N1S-ZeD39HMrYJsQkUh2tKvy3ztfmEqWpekvO4WRktSa000BPoAAwCgYIKoZIzj0EAwMDSQAwRgIhAIZIBwu4xOUD_4dJuGgceSKaoXTFBQKA3BFBNVJvbpdsAiEAlfq3Dq_8dnYbtmyDdXgopeKkSV5_76VSpcog-wkwEwo"
}`)
var testCertificateRequestBadASN1 = []byte(`{"csr":"MIICWjCCAUICADAWMRQwEgYDVQQDEwtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMpwCSKfLhKC3SnvLNpVayAEyAHVixkusgProAPZRBH0VAog_r4JOfoJez7ABiZ2ZIXXA2gg65_05HkGNl9ww-sa0EY8eCty_8WcHxqzafUnyXOJZuLMPJjaJ2oiBv_3BM7PZgpFzyNZ0_0ZuRKdFGtEY-vX9GXZUV0A3sxZMOpce0lhHAiBk_vNARJyM2-O-cZ7WjzZ7R1T9myAyxtsFhWy3QYvIwiKVVF3lDp3KXlPZ_7wBhVIBcVSk0bzhseotyUnKg-aL5qZIeB1ci7IT5qA_6C1_bsCSJSbQ5gnQwIQ0iaUV_SgUBpKNqYbmnSdZmDxvvW8FzhuL6JSDLfBR2kCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQBxxkchTXfjv07aSWU9brHnRziNYOLvsSNiOWmWLNlZg9LKdBy6j1xwM8IQRCfTOVSkbuxVV-kU5p-Cg9UF_UGoerl3j8SiupurTovK9-L_PdX0wTKbK9xkh7OUq88jp32Rw0eAT87gODJRD-M1NXlTvm-j896e60hUmL-DIe3iPbFl8auUS-KROAWjci-LJZYVdomm9Iw47E-zr4Hg27EdZhvCZvSyPMK8ioys9mNg5TthHB6ExepKP1YW3HpQa1EdUVYWGEvyVL4upQZOxuEA1WJqHv6iVDzsQqkl5kkahK87NKTPS59k1TFetjw2GLnQ09-g_L7kT8dpq3Bk5Wo="}`)

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

	// Bad ASN.1 CSR
	var badASN1CR CertificateRequest
	err = json.Unmarshal(testCertificateRequestBadASN1, &badASN1CR)
	test.AssertError(t, err, "json.Unmarshal didn't fail")
	test.AssertEquals(t, err.Error(), "CSR generated using a pre-1.0.2 OpenSSL with a client that doesn't properly specify the CSR version")

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

func TestErrors(t *testing.T) {
	testMessage := "test"
	errors := []error{
		NotSupportedError(testMessage),
		MalformedRequestError(testMessage),
		UnauthorizedError(testMessage),
		NotFoundError(testMessage),
		SignatureValidationError(testMessage),
	}

	for i, err := range errors {
		if msg := err.Error(); msg != testMessage {
			t.Errorf("Error %d returned unexpected message %v", i, msg)
		}
	}
}

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

func TestURL(t *testing.T) {
	scheme := "https"
	host := "example.com"
	path := "/acme/test"
	query := "foo"
	jsonURL := fmt.Sprintf(`{"URL":"%s://%s%s?%s"}`, scheme, host, path, query)
	badJSON := `{"URL":666}`

	url := struct{ URL *AcmeURL }{URL: &AcmeURL{}}
	err := json.Unmarshal([]byte(jsonURL), &url)
	if err != nil {
		t.Errorf("Error in json unmarshal: %v", err)
	}
	if url.URL.Scheme != scheme || url.URL.Host != host ||
		url.URL.Path != path || url.URL.RawQuery != query {
		t.Errorf("Improper URL contents: %v", url.URL)
	}
	if s := url.URL.PathSegments(); len(s) != 2 {
		t.Errorf("Path segments failed to parse properly: %v", s)
	}

	err = json.Unmarshal([]byte(badJSON), &url)
	if err == nil {
		t.Errorf("Failed to catch bad JSON")
	}

	marshaledURL, err := json.Marshal(url)
	if err != nil {
		t.Errorf("Error in json marshal: %v", err)
	}
	if string(marshaledURL) != jsonURL {
		t.Errorf("Expected marshaled url %#v, got %#v", jsonURL, string(marshaledURL))
	}
}
