// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package wfe

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/jose"

	"github.com/letsencrypt/boulder/ra"
	"github.com/letsencrypt/boulder/test"
)

func makeBody(s string) io.ReadCloser {
	return ioutil.NopCloser(strings.NewReader(s))
}

func TestIndex(t *testing.T) {
	wfe := NewWebFrontEndImpl()
	// panic: http: multiple registrations for / [recovered]
	//wfe.HandlePaths()
	wfe.NewReg = "/acme/new-reg"
	responseWriter := httptest.NewRecorder()

	url, _ := url.Parse("/")
	wfe.Index(responseWriter, &http.Request{
		URL: url,
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.AssertNotEquals(t, responseWriter.Body.String(), "404 page not found\n")
	test.Assert(t, strings.Contains(responseWriter.Body.String(), wfe.NewReg),
		"new-reg not found")

	responseWriter.Body.Reset()
	url, _ = url.Parse("/foo")
	wfe.Index(responseWriter, &http.Request{
		URL: url,
	})
	//test.AssertEquals(t, responseWriter.Code, http.StatusNotFound)
	test.AssertEquals(t, responseWriter.Body.String(), "404 page not found\n")

}

// TODO: Write additional test cases for:
//  - RA returns with a cert success
//  - RA returns with a failure
func TestIssueCertificate(t *testing.T) {
	// TODO: Use a mock RA so we can test various conditions of authorized, not authorized, etc.
	ra := ra.NewRegistrationAuthorityImpl()
	wfe := NewWebFrontEndImpl()
	wfe.RA = &ra
	responseWriter := httptest.NewRecorder()

	// GET instead of POST should be rejected
	wfe.NewCertificate(responseWriter, &http.Request{
		Method: "GET",
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"detail\":\"Method not allowed\"}")

	// POST, but no body.
	responseWriter.Body.Reset()
	wfe.NewCertificate(responseWriter, &http.Request{
		Method: "POST",
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"detail\":\"Unable to read/verify body\"}")

	// POST, but body that isn't valid JWS
	responseWriter.Body.Reset()
	wfe.NewCertificate(responseWriter, &http.Request{
		Method: "POST",
		Body:   makeBody("hi"),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"detail\":\"Unable to read/verify body\"}")

	// POST, Properly JWS-signed, but payload is "foo", not base64-encoded JSON.
	responseWriter.Body.Reset()
	wfe.NewCertificate(responseWriter, &http.Request{
		Method: "POST",
		Body: makeBody(`
{
    "header": {
        "alg": "RS256",
        "jwk": {
            "e": "AQAB",
            "kty": "RSA",
            "n": "tSwgy3ORGvc7YJI9B2qqkelZRUC6F1S5NwXFvM4w5-M0TsxbFsH5UH6adigV0jzsDJ5imAechcSoOhAh9POceCbPN1sTNwLpNbOLiQQ7RD5mY_pSUHWXNmS9R4NZ3t2fQAzPeW7jOfF0LKuJRGkekx6tXP1uSnNibgpJULNc4208dgBaCHo3mvaE2HV2GmVl1yxwWX5QZZkGQGjNDZYnjFfa2DKVvFs0QbAk21ROm594kAxlRlMMrvqlf24Eq4ERO0ptzpZgm_3j_e4hGRD39gJS7kAzK-j2cacFQ5Qi2Y6wZI2p-FCq_wiYsfEAIkATPBiLKl_6d_Jfcvs_impcXQ"
        }
    },
    "payload": "Zm9vCg",
    "signature": "hRt2eYqBd_MyMRNIh8PEIACoFtmBi7BHTLBaAhpSU6zyDAFdEBaX7us4VB9Vo1afOL03Q8iuoRA0AT4akdV_mQTAQ_jhTcVOAeXPr0tB8b8Q11UPQ0tXJYmU4spAW2SapJIvO50ntUaqU05kZd0qw8-noH1Lja-aNnU-tQII4iYVvlTiRJ5g8_CADsvJqOk6FcHuo2mG643TRnhkAxUtazvHyIHeXMxydMMSrpwUwzMtln4ZJYBNx4QGEq6OhpAD_VSp-w8Lq5HOwGQoNs0bPxH1SGrArt67LFQBfjlVr94E1sn26p4vigXm83nJdNhWAMHHE9iV67xN-r29LT-FjA"
}
		`),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"detail\":\"Error unmarshaling certificate request\"}")

	// Same signed body, but payload modified by one byte, breaking signature.
	// should fail JWS verification.
	responseWriter.Body.Reset()
	wfe.NewCertificate(responseWriter, &http.Request{
		Method: "POST",
		Body: makeBody(`
			{
					"header": {
							"alg": "RS256",
							"jwk": {
									"e": "AQAB",
									"kty": "RSA",
									"n": "vd7rZIoTLEe-z1_8G1FcXSw9CQFEJgV4g9V277sER7yx5Qjz_Pkf2YVth6wwwFJEmzc0hoKY-MMYFNwBE4hQHw"
							}
					},
					"payload": "xm9vCg",
					"signature": "RjUQ679fxJgeAJlxqgvDP_sfGZnJ-1RgWF2qmcbnBWljs6h1qp63pLnJOl13u81bP_bCSjaWkelGG8Ymx_X-aQ"
			}
    `),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"detail\":\"Unable to read/verify body\"}")

	// Valid, signed JWS body, payload is '{}'
	responseWriter.Body.Reset()
	wfe.NewCertificate(responseWriter, &http.Request{
		Method: "POST",
		Body: makeBody(`
			{
					"header": {
							"alg": "RS256",
							"jwk": {
									"e": "AQAB",
									"kty": "RSA",
									"n": "tSwgy3ORGvc7YJI9B2qqkelZRUC6F1S5NwXFvM4w5-M0TsxbFsH5UH6adigV0jzsDJ5imAechcSoOhAh9POceCbPN1sTNwLpNbOLiQQ7RD5mY_pSUHWXNmS9R4NZ3t2fQAzPeW7jOfF0LKuJRGkekx6tXP1uSnNibgpJULNc4208dgBaCHo3mvaE2HV2GmVl1yxwWX5QZZkGQGjNDZYnjFfa2DKVvFs0QbAk21ROm594kAxlRlMMrvqlf24Eq4ERO0ptzpZgm_3j_e4hGRD39gJS7kAzK-j2cacFQ5Qi2Y6wZI2p-FCq_wiYsfEAIkATPBiLKl_6d_Jfcvs_impcXQ"
							}
					},
					"payload": "e30K",
					"signature": "JXYA_pin91Bc5oz5I6dqCNNWDrBaYTB31EnWorrj4JEFRaidafC9mpLDLLA9jR9kX_Vy2bA5b6pPpXVKm0w146a0L551OdL8JrrLka9q6LypQdDLLQa76XD03hSBOFcC-Oo5FLPa3WRWS1fQ37hYAoLxtS3isWXMIq_4Onx5bq8bwKyu-3E3fRb_lzIZ8hTIWwcblCTOfufUe6AoK4m6MfBjz0NGhyyk4lEZZw6Sttm2VuZo3xmWoRTJEyJG5AOJ6fkNJ9iQQ1kVhMr0ZZ7NVCaOZAnxrwv2sCjY6R3f4HuEVe1yzT75Mq2IuXq-tadGyFujvUxF6BWHCulbEnss7g"
			}
		`),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"detail\":\"Error unmarshaling certificate request\"}")

	// Valid, signed JWS body, payload has a legit CSR but no authorizations:
	// {
	//   "csr": "MIICU...",
	//   "authorizations: []
	// }
	// Payload was created by: openssl  req -new -nodes -subj /CN=foo
	responseWriter.Body.Reset()
	wfe.NewCertificate(responseWriter, &http.Request{
		Method: "POST",
		Body: makeBody(`
			{
					"header": {
							"alg": "RS256",
							"jwk": {
									"e": "AQAB",
									"kty": "RSA",
									"n": "tSwgy3ORGvc7YJI9B2qqkelZRUC6F1S5NwXFvM4w5-M0TsxbFsH5UH6adigV0jzsDJ5imAechcSoOhAh9POceCbPN1sTNwLpNbOLiQQ7RD5mY_pSUHWXNmS9R4NZ3t2fQAzPeW7jOfF0LKuJRGkekx6tXP1uSnNibgpJULNc4208dgBaCHo3mvaE2HV2GmVl1yxwWX5QZZkGQGjNDZYnjFfa2DKVvFs0QbAk21ROm594kAxlRlMMrvqlf24Eq4ERO0ptzpZgm_3j_e4hGRD39gJS7kAzK-j2cacFQ5Qi2Y6wZI2p-FCq_wiYsfEAIkATPBiLKl_6d_Jfcvs_impcXQ"
							}
					},
					"payload": "ICAgIHsKICAgICAgImNzciI6ICJNSUlDVXpDQ0FUc0NBUUF3RGpFTU1Bb0dBMVVFQXd3RFptOXZNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQTNVV2NlMlBZOXk4bjRCN2pPazNEWFpudTJwVWdMcXM3YTVEelJCeG5QcUw3YXhpczZ0aGpTQkkyRk83dzVDVWpPLW04WGpELUdZV2dmWGViWjNhUVZsQmlZcWR4WjNVRzZSRHdFYkJDZUtvN3Y4Vy1VVWZFU05OQ1hGODc0ZGRoSm1FdzBSRjBZV1NBRWN0QVlIRUdvUEZ6NjlnQ3FsNnhYRFBZMU9scE1BcmtJSWxxOUVaV3dUMDgxZWt5SnYwR1lSZlFpZ0NNSzRiMWdrRnZLc0hqYTktUTV1MWIwQVp5QS1tUFR1Nno1RVdrQjJvbmhBWHdXWFg5MHNmVWU4RFNldDlyOUd4TWxuM2xnWldUMXpoM1JNWklMcDBVaGgzTmJYbkE4SkludWtoYTNIUE84V2dtRGQ0SzZ1QnpXc28wQTZmcDVOcFgyOFpwS0F3TTVpUWx0UUlEQVFBQm9BQXdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBRkdKVjNPY2doSkVadk9faEd0SWRhUm5zdTZlWDNDZXFTMGJZY0VFemE4dml6bGo0eDA5bnRNSDNRb29xUE9qOHN1dWwwdkQ3NUhaVHB6NkZIRTdTeUxlTktRQkdOR3AxUE1XbVhzRnFENnhVUkN5TUh2Q1pvSHlucENyN0Q1SHR6SXZ1OWZBVjdYUks3cUJLWGZSeGJ2MjFxMHlzTVduZndrYlMyd3JzMXdBelBQZzRpR0pxOHVWSXRybGNGTDhidUpMenh2S2EzbHVfT2p4TlhqemRFdDNWVmtvLUFLUzFzd2tZRWhzR3dLZDhaek5icEYySVEtb2tYZ1JfWmVjeVc4dDgzcFYtdzMzR2hETDl3NlJMUk1nU001YW9qeThyaTdZSW9JdmMzLTlrbGJ3Mmt3WTVvTTJsbWhvSU9HVTEwVGtFeW4xOG15eV81R1VFR2hOelBBPSIsCiAgICAgICJhdXRob3JpemF0aW9ucyI6IFtdCiAgICB9Cg",
					"signature": "PxtFtDXR74ZDgZUWsNaMFpFAhJrYtCYpl3-vr9SCwuWIxB9hZCnLWB5JFwNuC9CtTSYXqDJhzPs4-Bzh345HdwO-ifu1EIVxmc3bAszYS-cxA0lDzr8wJ0ldX0WvADshRWaeFYWJja7ggW03k5JZiNa9AigKIvkGBS2YWpEpCo954cdCEmIL3UOdVjN9aXRT7zzC9wczv4-hYDR-6uP_8J6ATUXJ-UJaTnMi3R0cwtHIcTBZgtgGspoCbtgv-3KaAGNkm5AY062xO5_GbefWwuD2hd8AjKyoTLdfQtwadu6Q3Zl6ZzW_eAfQVDnoblgSt19Gtm4HP4Rf_GosGjRMog"
			}
		`),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		// TODO: I think this is wrong. The CSR in the payload above was created by openssl and should be valid.
		"{\"detail\":\"Error creating new cert: Invalid signature on CSR\"}")
}

type MockRegistrationAuthority struct{}

func (ra *MockRegistrationAuthority) NewRegistration(reg core.Registration, jwk jose.JsonWebKey) (core.Registration, error) {
	return reg, nil
}

func (ra *MockRegistrationAuthority) NewAuthorization(authz core.Authorization, jwk jose.JsonWebKey) (core.Authorization, error) {
	return authz, nil
}

func (ra *MockRegistrationAuthority) NewCertificate(req core.CertificateRequest, jwk jose.JsonWebKey) (core.Certificate, error) {
	return core.Certificate{}, nil
}

func (ra *MockRegistrationAuthority) UpdateRegistration(reg core.Registration, updated core.Registration) (core.Registration, error) {
	return reg, nil
}

func (ra *MockRegistrationAuthority) UpdateAuthorization(authz core.Authorization, foo int, challenge core.Challenge) (core.Authorization, error) {
	return authz, nil
}

func (ra *MockRegistrationAuthority) RevokeCertificate(cert x509.Certificate) error {
	return nil
}

func (ra *MockRegistrationAuthority) OnValidationUpdate(authz core.Authorization) {
}

func TestChallenge(t *testing.T) {
	wfe := NewWebFrontEndImpl()
	wfe.RA = &MockRegistrationAuthority{}
	wfe.HandlePaths()
	responseWriter := httptest.NewRecorder()

	var key jose.JsonWebKey
	err := json.Unmarshal([]byte(`{
						"e": "AQAB",
						"kty": "RSA",
						"n": "tSwgy3ORGvc7YJI9B2qqkelZRUC6F1S5NwXFvM4w5-M0TsxbFsH5UH6adigV0jzsDJ5imAechcSoOhAh9POceCbPN1sTNwLpNbOLiQQ7RD5mY_pSUHWXNmS9R4NZ3t2fQAzPeW7jOfF0LKuJRGkekx6tXP1uSnNibgpJULNc4208dgBaCHo3mvaE2HV2GmVl1yxwWX5QZZkGQGjNDZYnjFfa2DKVvFs0QbAk21ROm594kAxlRlMMrvqlf24Eq4ERO0ptzpZgm_3j_e4hGRD39gJS7kAzK-j2cacFQ5Qi2Y6wZI2p-FCq_wiYsfEAIkATPBiLKl_6d_Jfcvs_impcXQ"
							}`), &key)
	test.AssertNotError(t, err, "Could not unmarshal testing key")

	challengeURL, _ := url.Parse("/acme/authz/asdf?challenge=foo")
	authz := core.Authorization{
		ID: "asdf",
		Identifier: core.AcmeIdentifier{
			Type:  "dns",
			Value: "letsencrypt.org",
		},
		Challenges: []core.Challenge{
			core.Challenge{
				Type: "dns",
				URI:  core.AcmeURL(*challengeURL),
			},
		},
		Key: key,
	}

	wfe.Challenge(authz, responseWriter, &http.Request{
		Method: "POST",
		URL:    challengeURL,
		Body: makeBody(`
			{
					"header": {
							"alg": "RS256",
							"jwk": {
									"e": "AQAB",
									"kty": "RSA",
									"n": "tSwgy3ORGvc7YJI9B2qqkelZRUC6F1S5NwXFvM4w5-M0TsxbFsH5UH6adigV0jzsDJ5imAechcSoOhAh9POceCbPN1sTNwLpNbOLiQQ7RD5mY_pSUHWXNmS9R4NZ3t2fQAzPeW7jOfF0LKuJRGkekx6tXP1uSnNibgpJULNc4208dgBaCHo3mvaE2HV2GmVl1yxwWX5QZZkGQGjNDZYnjFfa2DKVvFs0QbAk21ROm594kAxlRlMMrvqlf24Eq4ERO0ptzpZgm_3j_e4hGRD39gJS7kAzK-j2cacFQ5Qi2Y6wZI2p-FCq_wiYsfEAIkATPBiLKl_6d_Jfcvs_impcXQ"
							}
					},
					"payload": "e30K",
					"signature": "JXYA_pin91Bc5oz5I6dqCNNWDrBaYTB31EnWorrj4JEFRaidafC9mpLDLLA9jR9kX_Vy2bA5b6pPpXVKm0w146a0L551OdL8JrrLka9q6LypQdDLLQa76XD03hSBOFcC-Oo5FLPa3WRWS1fQ37hYAoLxtS3isWXMIq_4Onx5bq8bwKyu-3E3fRb_lzIZ8hTIWwcblCTOfufUe6AoK4m6MfBjz0NGhyyk4lEZZw6Sttm2VuZo3xmWoRTJEyJG5AOJ6fkNJ9iQQ1kVhMr0ZZ7NVCaOZAnxrwv2sCjY6R3f4HuEVe1yzT75Mq2IuXq-tadGyFujvUxF6BWHCulbEnss7g"
			}
		`),
	})

	test.AssertEquals(
		t, responseWriter.Header().Get("Location"),
		"/acme/authz/asdf?challenge=foo")
	test.AssertEquals(
		t, responseWriter.Header().Get("Link"),
		"</acme/authz/asdf>;rel=\"up\"")
	test.AssertEquals(
		t, responseWriter.Body.String(),
		"{\"type\":\"dns\",\"uri\":\"/acme/authz/asdf?challenge=foo\"}")
}

func TestRegistration(t *testing.T) {
	wfe := NewWebFrontEndImpl()
	wfe.RA = &MockRegistrationAuthority{}
	wfe.Stats, _ = statsd.NewNoopClient()
	responseWriter := httptest.NewRecorder()

	// GET instead of POST should be rejected
	wfe.NewRegistration(responseWriter, &http.Request{
		Method: "GET",
	})
	test.AssertEquals(t, responseWriter.Body.String(), "{\"detail\":\"Method not allowed\"}")

	// POST, but no body.
	responseWriter.Body.Reset()
	wfe.NewRegistration(responseWriter, &http.Request{
		Method: "POST",
	})
	test.AssertEquals(t, responseWriter.Body.String(), "{\"detail\":\"Unable to read/verify body\"}")

	// POST, but body that isn't valid JWS
	responseWriter.Body.Reset()
	wfe.NewRegistration(responseWriter, &http.Request{
		Method: "POST",
		Body:   makeBody("hi"),
	})
	test.AssertEquals(t, responseWriter.Body.String(), "{\"detail\":\"Unable to read/verify body\"}")

	// POST, Properly JWS-signed, but payload is "foo", not base64-encoded JSON.
	responseWriter.Body.Reset()
	wfe.NewRegistration(responseWriter, &http.Request{
		Method: "POST",
		Body: makeBody(`
{
    "header": {
        "alg": "RS256",
        "jwk": {
            "e": "AQAB",
            "kty": "RSA",
            "n": "tSwgy3ORGvc7YJI9B2qqkelZRUC6F1S5NwXFvM4w5-M0TsxbFsH5UH6adigV0jzsDJ5imAechcSoOhAh9POceCbPN1sTNwLpNbOLiQQ7RD5mY_pSUHWXNmS9R4NZ3t2fQAzPeW7jOfF0LKuJRGkekx6tXP1uSnNibgpJULNc4208dgBaCHo3mvaE2HV2GmVl1yxwWX5QZZkGQGjNDZYnjFfa2DKVvFs0QbAk21ROm594kAxlRlMMrvqlf24Eq4ERO0ptzpZgm_3j_e4hGRD39gJS7kAzK-j2cacFQ5Qi2Y6wZI2p-FCq_wiYsfEAIkATPBiLKl_6d_Jfcvs_impcXQ"
        }
    },
    "payload": "Zm9vCg",
    "signature": "hRt2eYqBd_MyMRNIh8PEIACoFtmBi7BHTLBaAhpSU6zyDAFdEBaX7us4VB9Vo1afOL03Q8iuoRA0AT4akdV_mQTAQ_jhTcVOAeXPr0tB8b8Q11UPQ0tXJYmU4spAW2SapJIvO50ntUaqU05kZd0qw8-noH1Lja-aNnU-tQII4iYVvlTiRJ5g8_CADsvJqOk6FcHuo2mG643TRnhkAxUtazvHyIHeXMxydMMSrpwUwzMtln4ZJYBNx4QGEq6OhpAD_VSp-w8Lq5HOwGQoNs0bPxH1SGrArt67LFQBfjlVr94E1sn26p4vigXm83nJdNhWAMHHE9iV67xN-r29LT-FjA"
}
		`),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"detail\":\"Error unmarshaling JSON\"}")

	// Same signed body, but payload modified by one byte, breaking signature.
	// should fail JWS verification.
	responseWriter.Body.Reset()
	wfe.NewRegistration(responseWriter, &http.Request{
		Method: "POST",
		Body: makeBody(`
			{
					"header": {
							"alg": "RS256",
							"jwk": {
									"e": "AQAB",
									"kty": "RSA",
									"n": "vd7rZIoTLEe-z1_8G1FcXSw9CQFEJgV4g9V277sER7yx5Qjz_Pkf2YVth6wwwFJEmzc0hoKY-MMYFNwBE4hQHw"
							}
					},
					"payload": "xm9vCg",
					"signature": "RjUQ679fxJgeAJlxqgvDP_sfGZnJ-1RgWF2qmcbnBWljs6h1qp63pLnJOl13u81bP_bCSjaWkelGG8Ymx_X-aQ"
			}
    	`),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"detail\":\"Unable to read/verify body\"}")

	key, _ := rsa.GenerateKey(rand.Reader, 512)
	jws, err := jose.Sign(jose.RSAPSSWithSHA256, *key, []byte("{\"contact\":[\"tel:123456789\"]}"))
	fmt.Println(err)
	requestPayload, _ := json.Marshal(jws)

	responseWriter.Body.Reset()
	wfe.NewRegistration(responseWriter, &http.Request{
		Method: "POST",
		Body: makeBody(string(requestPayload)),
	})

	var reg core.Registration
	err = json.Unmarshal([]byte(responseWriter.Body.String()), &reg)
	test.AssertNotError(t, err, "Couldn't unmarshal returned registration object")
	uu := url.URL(reg.Contact[0])
	test.AssertEquals(t, uu.String(), "tel:123456789")
}

func TestAuthorization(t *testing.T) {
	wfe := NewWebFrontEndImpl()
	wfe.RA = &MockRegistrationAuthority{}
	wfe.Stats, _ = statsd.NewNoopClient()
	responseWriter := httptest.NewRecorder()

	// GET instead of POST should be rejected
	wfe.NewAuthorization(responseWriter, &http.Request{
		Method: "GET",
	})
	test.AssertEquals(t, responseWriter.Body.String(), "{\"detail\":\"Method not allowed\"}")

	// POST, but no body.
	responseWriter.Body.Reset()
	wfe.NewAuthorization(responseWriter, &http.Request{
		Method: "POST",
	})
	test.AssertEquals(t, responseWriter.Body.String(), "{\"detail\":\"Unable to read/verify body\"}")

	// POST, but body that isn't valid JWS
	responseWriter.Body.Reset()
	wfe.NewAuthorization(responseWriter, &http.Request{
		Method: "POST",
		Body:   makeBody("hi"),
	})
	test.AssertEquals(t, responseWriter.Body.String(), "{\"detail\":\"Unable to read/verify body\"}")

	// POST, Properly JWS-signed, but payload is "foo", not base64-encoded JSON.
	responseWriter.Body.Reset()
	wfe.NewAuthorization(responseWriter, &http.Request{
		Method: "POST",
		Body: makeBody(`
{
    "header": {
        "alg": "RS256",
        "jwk": {
            "e": "AQAB",
            "kty": "RSA",
            "n": "tSwgy3ORGvc7YJI9B2qqkelZRUC6F1S5NwXFvM4w5-M0TsxbFsH5UH6adigV0jzsDJ5imAechcSoOhAh9POceCbPN1sTNwLpNbOLiQQ7RD5mY_pSUHWXNmS9R4NZ3t2fQAzPeW7jOfF0LKuJRGkekx6tXP1uSnNibgpJULNc4208dgBaCHo3mvaE2HV2GmVl1yxwWX5QZZkGQGjNDZYnjFfa2DKVvFs0QbAk21ROm594kAxlRlMMrvqlf24Eq4ERO0ptzpZgm_3j_e4hGRD39gJS7kAzK-j2cacFQ5Qi2Y6wZI2p-FCq_wiYsfEAIkATPBiLKl_6d_Jfcvs_impcXQ"
        }
    },
    "payload": "Zm9vCg",
    "signature": "hRt2eYqBd_MyMRNIh8PEIACoFtmBi7BHTLBaAhpSU6zyDAFdEBaX7us4VB9Vo1afOL03Q8iuoRA0AT4akdV_mQTAQ_jhTcVOAeXPr0tB8b8Q11UPQ0tXJYmU4spAW2SapJIvO50ntUaqU05kZd0qw8-noH1Lja-aNnU-tQII4iYVvlTiRJ5g8_CADsvJqOk6FcHuo2mG643TRnhkAxUtazvHyIHeXMxydMMSrpwUwzMtln4ZJYBNx4QGEq6OhpAD_VSp-w8Lq5HOwGQoNs0bPxH1SGrArt67LFQBfjlVr94E1sn26p4vigXm83nJdNhWAMHHE9iV67xN-r29LT-FjA"
}
		`),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"detail\":\"Error unmarshaling JSON\"}")

	// Same signed body, but payload modified by one byte, breaking signature.
	// should fail JWS verification.
	responseWriter.Body.Reset()
	wfe.NewAuthorization(responseWriter, &http.Request{
		Method: "POST",
		Body: makeBody(`
			{
					"header": {
							"alg": "RS256",
							"jwk": {
									"e": "AQAB",
									"kty": "RSA",
									"n": "vd7rZIoTLEe-z1_8G1FcXSw9CQFEJgV4g9V277sER7yx5Qjz_Pkf2YVth6wwwFJEmzc0hoKY-MMYFNwBE4hQHw"
							}
					},
					"payload": "xm9vCg",
					"signature": "RjUQ679fxJgeAJlxqgvDP_sfGZnJ-1RgWF2qmcbnBWljs6h1qp63pLnJOl13u81bP_bCSjaWkelGG8Ymx_X-aQ"
			}
    	`),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		"{\"detail\":\"Unable to read/verify body\"}")

	key, _ := rsa.GenerateKey(rand.Reader, 512)
	jws, err := jose.Sign(jose.RSAPSSWithSHA256, *key, []byte("{\"identifier\":{\"type\":\"dns\",\"value\":\"test.com\"}}"))
	fmt.Println(err)
	requestPayload, _ := json.Marshal(jws)
	
	responseWriter.Body.Reset()
	wfe.NewAuthorization(responseWriter, &http.Request{
		Method: "POST",
		Body: makeBody(string(requestPayload)),
	})
}
