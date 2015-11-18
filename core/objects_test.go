// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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

// TODO(https://github.com/letsencrypt/boulder/issues/894): Delete this test
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
	test.AssertNotError(t, err, "Error creating key authorization")

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

		chall.Token = ka.Token
		test.Assert(t, chall.IsSane(false), "IsSane should be true")

		chall.KeyAuthorization = &ka
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

func TestVerifySignature(t *testing.T) {
	// Based on an actual submission to the aviator log
	sigBytes, err := base64.StdEncoding.DecodeString("BAMASDBGAiEAknaySJVdB3FqG9bUKHgyu7V9AdEabpTc71BELUp6/iECIQDObrkwlQq6Azfj5XOA5E12G/qy/WuRn97z7qMSXXc82Q==")
	if err != nil {
		return
	}
	testReciept := SignedCertificateTimestamp{
		SCTVersion: sctVersionOne,
		Timestamp:  1423696705756,
		Signature:  sigBytes,
	}

	aviatorPkBytes, err := base64.StdEncoding.DecodeString("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1/TMabLkDpCjiupacAlP7xNi0I1JYP8bQFAHDG1xhtolSY1l4QgNRzRrvSe8liE+NPWHdjGxfx3JhTsN9x8/6Q==")
	test.AssertNotError(t, err, "Couldn't parse aviator public key")
	aviatorPk, err := x509.ParsePKIXPublicKey(aviatorPkBytes)
	test.AssertNotError(t, err, "Couldn't parse aviator public key bytes")
	leafPEM, _ := pem.Decode([]byte(testLeaf))
	pk := aviatorPk.(*ecdsa.PublicKey)
	err = testReciept.VerifySignature(leafPEM.Bytes, pk)
	test.AssertNotError(t, err, "Signature validation failed")
}

var testLeaf = `-----BEGIN CERTIFICATE-----
MIIHAjCCBeqgAwIBAgIQfwAAAQAAAUtRVNy9a8fMcDANBgkqhkiG9w0BAQsFADBa
MQswCQYDVQQGEwJVUzESMBAGA1UEChMJSWRlblRydXN0MRcwFQYDVQQLEw5UcnVz
dElEIFNlcnZlcjEeMBwGA1UEAxMVVHJ1c3RJRCBTZXJ2ZXIgQ0EgQTUyMB4XDTE1
MDIwMzIxMjQ1MVoXDTE4MDIwMjIxMjQ1MVowfzEYMBYGA1UEAxMPbGV0c2VuY3J5
cHQub3JnMSkwJwYDVQQKEyBJTlRFUk5FVCBTRUNVUklUWSBSRVNFQVJDSCBHUk9V
UDEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzETMBEGA1UECBMKQ2FsaWZvcm5pYTEL
MAkGA1UEBhMCVVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDGE6T8
LcmS6g8lH/1Y5orXeZOva4gthrS+VmJUWlz3K4Er5q8CmVFTmD/rYL6tA31JYCAi
p2bVQ8z/PgWYGosuMzox2OO9MqnLwTTG074sCHTZi4foFb6KacS8xVu25u8RRBd8
1WJNlw736FO0pJUkkE3gDSPz1QTpw3gc6n7SyppaFr40D5PpK3PPoNCPfoz2bFtH
m2KRsUH924LRfitUZdI68kxJP7QG1SAbdZxA/qDcfvDSgCYW5WNmMKS4v+GHuMkJ
gBe20tML+hItmF5S9mYm/GbkFLG8YwWZrytUZrSjxmuL9nj3MaBrAPQw3/T582ry
KM8+z188kbnA7A+BAgMBAAGjggOdMIIDmTAOBgNVHQ8BAf8EBAMCBaAwggInBgNV
HSAEggIeMIICGjCCAQsGCmCGSAGG+S8ABgMwgfwwQAYIKwYBBQUHAgEWNGh0dHBz
Oi8vc2VjdXJlLmlkZW50cnVzdC5jb20vY2VydGlmaWNhdGVzL3BvbGljeS90cy8w
gbcGCCsGAQUFBwICMIGqGoGnVGhpcyBUcnVzdElEIFNlcnZlciBDZXJ0aWZpY2F0
ZSBoYXMgYmVlbiBpc3N1ZWQgaW4gYWNjb3JkYW5jZSB3aXRoIElkZW5UcnVzdCdz
IFRydXN0SUQgQ2VydGlmaWNhdGUgUG9saWN5IGZvdW5kIGF0IGh0dHBzOi8vc2Vj
dXJlLmlkZW50cnVzdC5jb20vY2VydGlmaWNhdGVzL3BvbGljeS90cy8wggEHBgZn
gQwBAgIwgfwwQAYIKwYBBQUHAgEWNGh0dHBzOi8vc2VjdXJlLmlkZW50cnVzdC5j
b20vY2VydGlmaWNhdGVzL3BvbGljeS90cy8wgbcGCCsGAQUFBwICMIGqGoGnVGhp
cyBUcnVzdElEIFNlcnZlciBDZXJ0aWZpY2F0ZSBoYXMgYmVlbiBpc3N1ZWQgaW4g
YWNjb3JkYW5jZSB3aXRoIElkZW5UcnVzdCdzIFRydXN0SUQgQ2VydGlmaWNhdGUg
UG9saWN5IGZvdW5kIGF0IGh0dHBzOi8vc2VjdXJlLmlkZW50cnVzdC5jb20vY2Vy
dGlmaWNhdGVzL3BvbGljeS90cy8wHQYDVR0OBBYEFNLAuFI2ugD0U24OgEPtX6+p
/xJQMEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly92YWxpZGF0aW9uLmlkZW50cnVz
dC5jb20vY3JsL3RydXN0aWRjYWE1Mi5jcmwwgYQGCCsGAQUFBwEBBHgwdjAwBggr
BgEFBQcwAYYkaHR0cDovL2NvbW1lcmNpYWwub2NzcC5pZGVudHJ1c3QuY29tMEIG
CCsGAQUFBzAChjZodHRwOi8vdmFsaWRhdGlvbi5pZGVudHJ1c3QuY29tL2NlcnRz
L3RydXN0aWRjYWE1Mi5wN2MwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MB8GA1UdIwQYMBaAFKJWJDzQ1BW56L94oxMQWEguFlThMC8GA1UdEQQoMCaCD2xl
dHNlbmNyeXB0Lm9yZ4ITd3d3LmxldHNlbmNyeXB0Lm9yZzANBgkqhkiG9w0BAQsF
AAOCAQEAgEmnzpYncB/E5SCHa5cnGorvNNE6Xsp3YXK9fJBT2++chQTkyFYpE12T
TR+cb7CTdRiYErNHXV8Hl/XTK8mxGxK8KXM9zUDlfrl7yBnyGTl2Sk8qJwA2kGuu
X9KA1o3MFkKMD809ITAlvPoQpml1Ke0aFo4NLO/LJKnJpkyF8L+JQrkfLNHpKYn3
PvnyJnurVTXDOIwQw8HVXbw6UKAad87e1hKGLYOpsaaKCLaNw1vg8uI+O9mv1MC6
FTfP1pSlr11s+Ih4YancuJud41rT8lXCUbDs1Uws9pPdVzLt8zk5M0vbHmTCljbg
UC5XkUmEvadMfgWslIQD0r6+BRRS+A==
-----END CERTIFICATE-----`
