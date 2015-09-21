// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package wfe

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log/syslog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"

	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/ra"
	"github.com/letsencrypt/boulder/test"
)

const (
	agreementURL = "http://example.invalid/terms"

	test1KeyPublicJSON = `
	{
		"kty":"RSA",
		"n":"yNWVhtYEKJR21y9xsHV-PD_bYwbXSeNuFal46xYxVfRL5mqha7vttvjB_vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K_klBYN8oYvTwwmeSkAz6ut7ZxPv-nZaT5TJhGk0NT2kh_zSpdriEJ_3vW-mqxYbbBmpvHqsa1_zx9fSuHYctAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV-mzfMyboQjujPh7aNJxAWSq4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF-w8hOTI3XXohUdu29Se26k2B0PolDSuj0GIQU6-W9TdLXSjBb2SpQ",
		"e":"AQAB"
	}`

	test1KeyPrivatePEM = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAyNWVhtYEKJR21y9xsHV+PD/bYwbXSeNuFal46xYxVfRL5mqh
a7vttvjB/vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K/klBYN8oYvTwwmeSkAz
6ut7ZxPv+nZaT5TJhGk0NT2kh/zSpdriEJ/3vW+mqxYbbBmpvHqsa1/zx9fSuHYc
tAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV+mzfMyboQjujPh7aNJxAWS
q4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF+w8hOTI3XXohUdu
29Se26k2B0PolDSuj0GIQU6+W9TdLXSjBb2SpQIDAQABAoIBAHw58SXYV/Yp72Cn
jjFSW+U0sqWMY7rmnP91NsBjl9zNIe3C41pagm39bTIjB2vkBNR8ZRG7pDEB/QAc
Cn9Keo094+lmTArjL407ien7Ld+koW7YS8TyKADYikZo0vAK3qOy14JfQNiFAF9r
Bw61hG5/E58cK5YwQZe+YcyBK6/erM8fLrJEyw4CV49wWdq/QqmNYU1dx4OExAkl
KMfvYXpjzpvyyTnZuS4RONfHsO8+JTyJVm+lUv2x+bTce6R4W++UhQY38HakJ0x3
XRfXooRv1Bletu5OFlpXfTSGz/5gqsfemLSr5UHncsCcFMgoFBsk2t/5BVukBgC7
PnHrAjkCgYEA887PRr7zu3OnaXKxylW5U5t4LzdMQLpslVW7cLPD4Y08Rye6fF5s
O/jK1DNFXIoUB7iS30qR7HtaOnveW6H8/kTmMv/YAhLO7PAbRPCKxxcKtniEmP1x
ADH0tF2g5uHB/zeZhCo9qJiF0QaJynvSyvSyJFmY6lLvYZsAW+C+PesCgYEA0uCi
Q8rXLzLpfH2NKlLwlJTi5JjE+xjbabgja0YySwsKzSlmvYJqdnE2Xk+FHj7TCnSK
KUzQKR7+rEk5flwEAf+aCCNh3W4+Hp9MmrdAcCn8ZsKmEW/o7oDzwiAkRCmLw/ck
RSFJZpvFoxEg15riT37EjOJ4LBZ6SwedsoGA/a8CgYEA2Ve4sdGSR73/NOKZGc23
q4/B4R2DrYRDPhEySnMGoPCeFrSU6z/lbsUIU4jtQWSaHJPu4n2AfncsZUx9WeSb
OzTCnh4zOw33R4N4W8mvfXHODAJ9+kCc1tax1YRN5uTEYzb2dLqPQtfNGxygA1DF
BkaC9CKnTeTnH3TlKgK8tUcCgYB7J1lcgh+9ntwhKinBKAL8ox8HJfkUM+YgDbwR
sEM69E3wl1c7IekPFvsLhSFXEpWpq3nsuMFw4nsVHwaGtzJYAHByhEdpTDLXK21P
heoKF1sioFbgJB1C/Ohe3OqRLDpFzhXOkawOUrbPjvdBM2Erz/r11GUeSlpNazs7
vsoYXQKBgFwFM1IHmqOf8a2wEFa/a++2y/WT7ZG9nNw1W36S3P04K4lGRNRS2Y/S
snYiqxD9nL7pVqQP2Qbqbn0yD6d3G5/7r86F7Wu2pihM8g6oyMZ3qZvvRIBvKfWo
eROL1ve1vmQF3kjrMPhhK2kr6qdWnTE5XlPllVSZFQenSTzj98AO
-----END RSA PRIVATE KEY-----
`

	test2KeyPublicJSON = `{
		"kty":"RSA",
		"n":"qnARLrT7Xz4gRcKyLdydmCr-ey9OuPImX4X40thk3on26FkMznR3fRjs66eLK7mmPcBZ6uOJseURU6wAaZNmemoYx1dMvqvWWIyiQleHSD7Q8vBrhR6uIoO4jAzJZR-ChzZuSDt7iHN-3xUVspu5XGwXU_MVJZshTwp4TaFx5elHIT_ObnTvTOU3Xhish07AbgZKmWsVbXh5s-CrIicU4OexJPgunWZ_YJJueOKmTvnLlTV4MzKR2oZlBKZ27S0-SfdV_QDx_ydle5oMAyKVtlAV35cyPMIsYNwgUGBCdY_2Uzi5eX0lTc7MPRwz6qR1kip-i59VcGcUQgqHV6Fyqw",
		"e":"AQAB"
	}`

	test2KeyPrivatePEM = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqnARLrT7Xz4gRcKyLdydmCr+ey9OuPImX4X40thk3on26FkM
znR3fRjs66eLK7mmPcBZ6uOJseURU6wAaZNmemoYx1dMvqvWWIyiQleHSD7Q8vBr
hR6uIoO4jAzJZR+ChzZuSDt7iHN+3xUVspu5XGwXU/MVJZshTwp4TaFx5elHIT/O
bnTvTOU3Xhish07AbgZKmWsVbXh5s+CrIicU4OexJPgunWZ/YJJueOKmTvnLlTV4
MzKR2oZlBKZ27S0+SfdV/QDx/ydle5oMAyKVtlAV35cyPMIsYNwgUGBCdY/2Uzi5
eX0lTc7MPRwz6qR1kip+i59VcGcUQgqHV6FyqwIDAQABAoIBAG5m8Xpj2YC0aYtG
tsxmX9812mpJFqFOmfS+f5N0gMJ2c+3F4TnKz6vE/ZMYkFnehAT0GErC4WrOiw68
F/hLdtJM74gQ0LGh9dKeJmz67bKqngcAHWW5nerVkDGIBtzuMEsNwxofDcIxrjkr
G0b7AHMRwXqrt0MI3eapTYxby7+08Yxm40mxpSsW87FSaI61LDxUDpeVkn7kolSN
WifVat7CpZb/D2BfGAQDxiU79YzgztpKhbynPdGc/OyyU+CNgk9S5MgUX2m9Elh3
aXrWh2bT2xzF+3KgZdNkJQcdIYVoGq/YRBxlGXPYcG4Do3xKhBmH79Io2BizevZv
nHkbUGECgYEAydjb4rl7wYrElDqAYpoVwKDCZAgC6o3AKSGXfPX1Jd2CXgGR5Hkl
ywP0jdSLbn2v/jgKQSAdRbYuEiP7VdroMb5M6BkBhSY619cH8etoRoLzFo1GxcE8
Y7B598VXMq8TT+TQqw/XRvM18aL3YDZ3LSsR7Gl2jF/sl6VwQAaZToUCgYEA2Cn4
fG58ME+M4IzlZLgAIJ83PlLb9ip6MeHEhUq2Dd0In89nss7Acu0IVg8ES88glJZy
4SjDLGSiuQuoQVo9UBq/E5YghdMJFp5ovwVfEaJ+ruWqOeujvWzzzPVyIWSLXRQa
N4kedtfrlqldMIXywxVru66Q1NOGvhDHm/Q8+28CgYEAkhLCbn3VNed7A9qidrkT
7OdqRoIVujEDU8DfpKtK0jBP3EA+mJ2j4Bvoq4uZrEiBSPS9VwwqovyIstAfX66g
Qv95IK6YDwfvpawUL9sxB3ZU/YkYIp0JWwun+Mtzo1ZYH4V0DZfVL59q9of9hj9k
V+fHfNOF22jAC67KYUtlPxECgYEAwF6hj4L3rDqvQYrB/p8tJdrrW+B7dhgZRNkJ
fiGd4LqLGUWHoH4UkHJXT9bvWNPMx88YDz6qapBoq8svAnHfTLFwyGp7KP1FAkcZ
Kp4KG/SDTvx+QCtvPX1/fjAUUJlc2QmxxyiU3uiK9Tpl/2/FOk2O4aiZpX1VVUIz
kZuKxasCgYBiVRkEBk2W4Ia0B7dDkr2VBrz4m23Y7B9cQLpNAapiijz/0uHrrCl8
TkLlEeVOuQfxTadw05gzKX0jKkMC4igGxvEeilYc6NR6a4nvRulG84Q8VV9Sy9Ie
wk6Oiadty3eQqSBJv0HnpmiEdQVffIK5Pg4M8Dd+aOBnEkbopAJOuA==
-----END RSA PRIVATE KEY-----
`
)

type MockRegistrationAuthority struct{}

func (ra *MockRegistrationAuthority) NewRegistration(reg core.Registration) (core.Registration, error) {
	return reg, nil
}

func (ra *MockRegistrationAuthority) NewAuthorization(authz core.Authorization, regID int64) (core.Authorization, error) {
	authz.RegistrationID = regID
	authz.ID = "bkrPh2u0JUf18-rVBZtOOWWb3GuIiliypL-hBM9Ak1Q"
	return authz, nil
}

func (ra *MockRegistrationAuthority) NewCertificate(req core.CertificateRequest, regID int64) (core.Certificate, error) {
	return core.Certificate{}, nil
}

func (ra *MockRegistrationAuthority) UpdateRegistration(reg core.Registration, updated core.Registration) (core.Registration, error) {
	return reg, nil
}

func (ra *MockRegistrationAuthority) UpdateAuthorization(authz core.Authorization, foo int, challenge core.Challenge) (core.Authorization, error) {
	return authz, nil
}

func (ra *MockRegistrationAuthority) RevokeCertificateWithReg(cert x509.Certificate, reason core.RevocationCode, reg int64) error {
	return nil
}

func (ra *MockRegistrationAuthority) AdministrativelyRevokeCertificate(cert x509.Certificate, reason core.RevocationCode, user string) error {
	return nil
}

func (ra *MockRegistrationAuthority) OnValidationUpdate(authz core.Authorization) error {
	return nil
}

type MockCA struct{}

func (ca *MockCA) IssueCertificate(csr x509.CertificateRequest, regID int64) (core.Certificate, error) {
	// Return a basic certificate so NewCertificate can continue
	certPtr, err := core.LoadCert("test/not-an-example.com.crt")
	if err != nil {
		return core.Certificate{}, err
	}
	return core.Certificate{
		DER: certPtr.Raw,
	}, nil
}

func (ca *MockCA) GenerateOCSP(xferObj core.OCSPSigningRequest) (ocsp []byte, err error) {
	return
}

func (ca *MockCA) RevokeCertificate(serial string, reasonCode core.RevocationCode) (err error) {
	return
}

type MockPA struct{}

func (pa *MockPA) ChallengesFor(identifier core.AcmeIdentifier) (challenges []core.Challenge, combinations [][]int) {
	return
}

func (pa *MockPA) WillingToIssue(id core.AcmeIdentifier) error {
	return nil
}

func makeBody(s string) io.ReadCloser {
	return ioutil.NopCloser(strings.NewReader(s))
}

func signRequest(t *testing.T, req string, nonceService *core.NonceService) string {
	accountKeyJSON := []byte(`{"kty":"RSA","n":"z2NsNdHeqAiGdPP8KuxfQXat_uatOK9y12SyGpfKw1sfkizBIsNxERjNDke6Wp9MugN9srN3sr2TDkmQ-gK8lfWo0v1uG_QgzJb1vBdf_hH7aejgETRGLNJZOdaKDsyFnWq1WGJq36zsHcd0qhggTk6zVwqczSxdiWIAZzEakIUZ13KxXvoepYLY0Q-rEEQiuX71e4hvhfeJ4l7m_B-awn22UUVvo3kCqmaRlZT-36vmQhDGoBsoUo1KBEU44jfeK5PbNRk7vDJuH0B7qinr_jczHcvyD-2TtPzKaCioMtNh_VZbPNDaG67sYkQlC15-Ff3HPzKKJW2XvkVG91qMvQ","e":"AQAB","d":"BhAmDbzBAbCeHbU0Xhzi_Ar4M0eTMOEQPnPXMSfW6bc0SRW938JO_-z1scEvFY8qsxV_C0Zr7XHVZsmHz4dc9BVmhiSan36XpuOS85jLWaY073e7dUVN9-l-ak53Ys9f6KZB_v-BmGB51rUKGB70ctWiMJ1C0EzHv0h6Moog-LCd_zo03uuZD5F5wtnPrAB3SEM3vRKeZHzm5eiGxNUsaCEzGDApMYgt6YkQuUlkJwD8Ky2CkAE6lLQSPwddAfPDhsCug-12SkSIKw1EepSHz86ZVfJEnvY-h9jHIdI57mR1v7NTCDcWqy6c6qIzxwh8n2X94QTbtWT3vGQ6HXM5AQ","p":"2uhvZwNS5i-PzeI9vGx89XbdsVmeNjVxjH08V3aRBVY0dzUzwVDYk3z7sqBIj6de53Lx6W1hjmhPIqAwqQgjIKH5Z3uUCinGguKkfGDL3KgLCzYL2UIvZMvTzr9NWLc0AHMZdee5utxWKCGnZBOqy1Rd4V-6QrqjEDBvanoqA60","q":"8odNkMEiriaDKmvwDv-vOOu3LaWbu03yB7VhABu-hK5Xx74bHcvDP2HuCwDGGJY2H-xKdMdUPs0HPwbfHMUicD2vIEUDj6uyrMMZHtbcZ3moh3-WESg3TaEaJ6vhwcWXWG7Wc46G-HbCChkuVenFYYkoi68BAAjloqEUl1JBT1E"}`)
	var accountKey jose.JsonWebKey
	err := json.Unmarshal(accountKeyJSON, &accountKey)
	test.AssertNotError(t, err, "Failed to unmarshal key")
	signer, err := jose.NewSigner("RS256", &accountKey)
	test.AssertNotError(t, err, "Failed to make signer")
	nonce, err := nonceService.Nonce()
	test.AssertNotError(t, err, "Failed to make nonce")
	result, err := signer.Sign([]byte(req), nonce)
	test.AssertNotError(t, err, "Failed to sign req")
	ret := result.FullSerialize()
	return ret
}

func setupWFE(t *testing.T) WebFrontEndImpl {
	wfe, err := NewWebFrontEndImpl()
	test.AssertNotError(t, err, "Unable to create WFE")

	wfe.NewReg = wfe.BaseURL + NewRegPath
	wfe.RegBase = wfe.BaseURL + RegPath
	wfe.NewAuthz = wfe.BaseURL + NewAuthzPath
	wfe.AuthzBase = wfe.BaseURL + AuthzPath
	wfe.ChallengeBase = wfe.BaseURL + ChallengePath
	wfe.NewCert = wfe.BaseURL + NewCertPath
	wfe.CertBase = wfe.BaseURL + CertPath
	wfe.SubscriberAgreementURL = agreementURL
	wfe.log.SyslogWriter = mocks.NewSyslogWriter()

	wfe.RA = &MockRegistrationAuthority{}
	wfe.SA = &mocks.MockSA{}
	wfe.Stats, _ = statsd.NewNoopClient()
	wfe.SubscriberAgreementURL = agreementURL

	return wfe
}

// makePostRequest creates an http.Request with method POST, the provided body,
// and the correct Content-Length.
func makePostRequest(body string) *http.Request {
	return &http.Request{
		Method:     "POST",
		RemoteAddr: "1.1.1.1",
		Header: map[string][]string{
			"Content-Length": []string{fmt.Sprintf("%d", len(body))},
		},
		Body: makeBody(body),
	}
}

func makePostRequestWithPath(path string, body string) *http.Request {
	request := makePostRequest(body)
	request.URL = mustParseURL(path)
	return request
}

func mustParseURL(s string) *url.URL {
	if u, err := url.Parse(s); err != nil {
		panic("Cannot parse URL " + s)
	} else {
		return u
	}
}

func sortHeader(s string) string {
	a := strings.Split(s, ", ")
	sort.Sort(sort.StringSlice(a))
	return strings.Join(a, ", ")
}

func TestHandleFunc(t *testing.T) {
	wfe := setupWFE(t)
	var mux *http.ServeMux
	var rw *httptest.ResponseRecorder
	var stubCalled bool
	runWrappedHandler := func(req *http.Request, allowed ...string) {
		mux = http.NewServeMux()
		rw = httptest.NewRecorder()
		stubCalled = false
		wfe.HandleFunc(mux, "/test", func(http.ResponseWriter, *http.Request) {
			stubCalled = true
		}, allowed...)
		req.URL = mustParseURL("/test")
		mux.ServeHTTP(rw, req)
	}

	// Plain requests (no CORS)
	type testCase struct {
		allowed       []string
		reqMethod     string
		shouldSucceed bool
	}
	var lastNonce string
	for _, c := range []testCase{
		{[]string{"GET", "POST"}, "GET", true},
		{[]string{"GET", "POST"}, "POST", true},
		{[]string{"GET"}, "", false},
		{[]string{"GET"}, "POST", false},
		{[]string{"GET"}, "OPTIONS", false},     // TODO, #469
		{[]string{"GET"}, "MAKE-COFFEE", false}, // 405, or 418?
	} {
		runWrappedHandler(&http.Request{Method: c.reqMethod}, c.allowed...)
		test.AssertEquals(t, stubCalled, c.shouldSucceed)
		if c.shouldSucceed {
			test.AssertEquals(t, rw.Code, http.StatusOK)
		} else {
			test.AssertEquals(t, rw.Code, http.StatusMethodNotAllowed)
			test.AssertEquals(t, sortHeader(rw.Header().Get("Allow")), strings.Join(c.allowed, ", "))
			test.AssertEquals(t,
				rw.Body.String(),
				`{"type":"urn:acme:error:malformed","detail":"Method not allowed"}`)
		}
		nonce := rw.Header().Get("Replay-Nonce")
		test.AssertNotEquals(t, nonce, lastNonce)
		lastNonce = nonce
	}

	// Disallowed method returns error JSON in body
	runWrappedHandler(&http.Request{Method: "PUT"}, "GET", "POST")
	test.AssertEquals(t, rw.Header().Get("Content-Type"), "application/problem+json")
	test.AssertEquals(t, rw.Body.String(), `{"type":"urn:acme:error:malformed","detail":"Method not allowed"}`)
	test.AssertEquals(t, sortHeader(rw.Header().Get("Allow")), "GET, POST")

	// Disallowed method special case: response to HEAD has got no body
	runWrappedHandler(&http.Request{Method: "HEAD"}, "GET", "POST")
	test.AssertEquals(t, stubCalled, false)
	test.AssertEquals(t, rw.Body.String(), "")
	test.AssertEquals(t, sortHeader(rw.Header().Get("Allow")), "GET, POST")
}

func TestStandardHeaders(t *testing.T) {
	wfe := setupWFE(t)
	mux, err := wfe.Handler()
	test.AssertNotError(t, err, "Problem setting up HTTP handlers")

	cases := []struct {
		path    string
		allowed []string
	}{
		{wfe.NewReg, []string{"POST"}},
		{wfe.RegBase, []string{"POST"}},
		{wfe.NewAuthz, []string{"POST"}},
		{wfe.AuthzBase, []string{"GET"}},
		{wfe.ChallengeBase, []string{"GET", "POST"}},
		{wfe.NewCert, []string{"POST"}},
		{wfe.CertBase, []string{"GET"}},
		{wfe.SubscriberAgreementURL, []string{"GET"}},
	}

	for _, c := range cases {
		responseWriter := httptest.NewRecorder()
		mux.ServeHTTP(responseWriter, &http.Request{
			Method: "BOGUS",
			URL:    mustParseURL(c.path),
		})
		acao := responseWriter.Header().Get("Access-Control-Allow-Origin")
		nonce := responseWriter.Header().Get("Replay-Nonce")
		allow := responseWriter.Header().Get("Allow")
		test.Assert(t, responseWriter.Code == http.StatusMethodNotAllowed, "Bogus method allowed")
		test.Assert(t, acao == "*", "Bad CORS header")
		test.Assert(t, len(nonce) > 0, "Bad Replay-Nonce header")
		test.Assert(t, len(allow) > 0 && allow == strings.Join(c.allowed, ", "), "Bad Allow header")
	}
}

func TestIndexPOST(t *testing.T) {
	wfe := setupWFE(t)
	responseWriter := httptest.NewRecorder()
	url, _ := url.Parse("/")
	wfe.Index(responseWriter, &http.Request{
		Method: "POST",
		URL:    url,
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusMethodNotAllowed)
}

func TestPOST404(t *testing.T) {
	wfe := setupWFE(t)
	responseWriter := httptest.NewRecorder()
	url, _ := url.Parse("/foobar")
	wfe.Index(responseWriter, &http.Request{
		Method: "POST",
		URL:    url,
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusNotFound)
}

func TestIndex(t *testing.T) {
	wfe := setupWFE(t)
	wfe.IndexCacheDuration = time.Second * 10

	responseWriter := httptest.NewRecorder()

	url, _ := url.Parse("/")
	wfe.Index(responseWriter, &http.Request{
		Method: "GET",
		URL:    url,
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.AssertNotEquals(t, responseWriter.Body.String(), "404 page not found\n")
	test.Assert(t, strings.Contains(responseWriter.Body.String(), DirectoryPath),
		"directory path not found")
	test.AssertEquals(t, responseWriter.Header().Get("Cache-Control"), "public, max-age=10")

	responseWriter.Body.Reset()
	responseWriter.Header().Del("Cache-Control")
	url, _ = url.Parse("/foo")
	wfe.Index(responseWriter, &http.Request{
		URL: url,
	})
	//test.AssertEquals(t, responseWriter.Code, http.StatusNotFound)
	test.AssertEquals(t, responseWriter.Body.String(), "404 page not found\n")
	test.AssertEquals(t, responseWriter.Header().Get("Cache-Control"), "")
}

func TestDirectory(t *testing.T) {
	wfe := setupWFE(t)
	wfe.BaseURL = "http://localhost:4300"
	mux, err := wfe.Handler()
	test.AssertNotError(t, err, "Problem setting up HTTP handlers")

	responseWriter := httptest.NewRecorder()

	url, _ := url.Parse("/directory")
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "GET",
		URL:    url,
	})
	test.AssertEquals(t, responseWriter.Header().Get("Content-Type"), "application/json")
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.AssertEquals(t, responseWriter.Body.String(), `{"new-authz":"http://localhost:4300/acme/new-authz","new-cert":"http://localhost:4300/acme/new-cert","new-reg":"http://localhost:4300/acme/new-reg","revoke-cert":"http://localhost:4300/acme/revoke-cert"}`)
}

// TODO: Write additional test cases for:
//  - RA returns with a failure
func TestIssueCertificate(t *testing.T) {
	wfe := setupWFE(t)
	mux, err := wfe.Handler()
	test.AssertNotError(t, err, "Problem setting up HTTP handlers")
	mockLog := wfe.log.SyslogWriter.(*mocks.MockSyslogWriter)

	// The mock CA we use always returns the same test certificate, with a Not
	// Before of 2015-09-22. Since we're currently using a real RA instead of a
	// mock (see below), that date would trigger failures for excessive
	// backdating. So we set the fakeClock's time to a time that matches that test
	// certificate.
	fakeClock := clock.NewFake()
	testTime := time.Date(2015, 9, 9, 22, 56, 0, 0, time.UTC)
	fakeClock.Add(fakeClock.Now().Sub(testTime))

	// TODO: Use a mock RA so we can test various conditions of authorized, not
	// authorized, etc.
	ra := ra.NewRegistrationAuthorityImpl(fakeClock, wfe.log)
	ra.SA = &mocks.MockSA{}
	ra.CA = &MockCA{}
	ra.PA = &MockPA{}
	wfe.SA = &mocks.MockSA{}
	wfe.RA = &ra
	wfe.Stats, _ = statsd.NewNoopClient()
	responseWriter := httptest.NewRecorder()

	// GET instead of POST should be rejected
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(NewCertPath),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"Method not allowed"}`)

	// POST, but no body.
	responseWriter.Body.Reset()
	wfe.NewCertificate(responseWriter, &http.Request{
		Method: "POST",
		Header: map[string][]string{
			"Content-Length": []string{"0"},
		},
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"Unable to read/verify body :: No body on POST"}`)

	// POST, but body that isn't valid JWS
	responseWriter.Body.Reset()
	wfe.NewCertificate(responseWriter, makePostRequest("hi"))
	test.AssertEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"Unable to read/verify body :: Parse error reading JWS"}`)

	// POST, Properly JWS-signed, but payload is "foo", not base64-encoded JSON.
	responseWriter.Body.Reset()
	wfe.NewCertificate(responseWriter,
		makePostRequest(signRequest(t, "foo", &wfe.nonceService)))
	test.AssertEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"Unable to read/verify body :: Request payload did not parse as JSON"}`)

	// Valid, signed JWS body, payload is '{}'
	responseWriter.Body.Reset()
	wfe.NewCertificate(responseWriter,
		makePostRequest(
			signRequest(t, "{}", &wfe.nonceService)))
	test.AssertEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"Unable to read/verify body :: Request payload does not specify a resource"}`)

	// Valid, signed JWS body, payload is '{"resource":"new-cert"}'
	responseWriter.Body.Reset()
	wfe.NewCertificate(responseWriter,
		makePostRequest(signRequest(t, `{"resource":"new-cert"}`, &wfe.nonceService)))
	test.AssertEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"Error unmarshaling certificate request"}`)

	// Valid, signed JWS body, payload has a invalid signature on CSR and no authorizations:
	// alias b64url="base64 -w0 | sed -e 's,+,-,g' -e 's,/,_,g'"
	// openssl req -outform der -new -nodes -key wfe/test/178.key -subj /CN=foo.com | \
	// sed 's/foo.com/fob.com/' | b64url
	responseWriter.Body.Reset()
	wfe.NewCertificate(responseWriter,
		makePostRequest(signRequest(t, `{
      "resource":"new-cert",
      "csr": "MIICVzCCAT8CAQAwEjEQMA4GA1UEAwwHZm9iLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKzHhqcMSTVjBu61vufGVmIYM4mMbWXgndHOUWnIqSKcNtFtPQ465tcZRT5ITIZWXGjsmgDrj31qvG3t5qLwyaF5hsTvFHK72nLMAQhdgM6481Qe9yaoaulWpkGr_9LVz4jQ9pGAaLVamXGpSxV-ipTOo79Sev4aZE8ksD9atEfWtcOD9w8_zj74vpWjTAHN49Q88chlChVqakn0zSfHPfS-jF8g0UTddBuF0Ti3sZChjxzbo6LwZ4182xX7XPnOLav3AGj0Su7j5XMl3OpenOrlWulWJeZIHq5itGW321j306XiGdbrdWH4K7JygICFds6oolwQRGBY6yinAtCgkTcCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQBxPiHOtKuBxtvecMNtLkTSuTyEkusQGnjoFDaKe5oqwGYQgy0YBii2-BbaPmqS4ZaDc-vDz_RLeKH5ZiH-NliYR1V_CRtpFLQi18g_2pLQnZLVO3ENs-SM37nU_nBGn9O93t2bkssoM3fZmtgp3R2W7I_wvx7Z8oWKa4boTeBAg_q9Gmi6QskZBddK7A4S_vOR0frU6QSPK_ksPhvovp9fwb6CVKrlJWf556UwRPWgbkW39hvTxK2KHhrUEg3oawNkWde2jZtnZ9e-9zpw8-_5O0X7-YN0ucbFTfQybce_ReuLlGepiHT5bvVavBZoIvqw1XOgSMvGgZFU8tAWMBlj"
    }`, &wfe.nonceService)))
	test.AssertEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:acme:error:unauthorized","detail":"Error creating new cert :: Invalid signature on CSR"}`)

	// Valid, signed JWS body, payload has a valid CSR but no authorizations:
	// openssl req -outform der -new -nodes -key wfe/test/178.key -subj /CN=meep.com | b64url
	mockLog.Clear()
	responseWriter.Body.Reset()
	wfe.NewCertificate(responseWriter,
		makePostRequest(signRequest(t, `{
			"resource":"new-cert",
			"csr": "MIICWDCCAUACAQAwEzERMA8GA1UEAwwIbWVlcC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCaqzue57mgXEoGTZZoVkkCZraebWgXI8irX2BgQB1A3iZa9onxGPMcWQMxhSuUisbEJi4UkMcVST12HX01rUwhj41UuBxJvI1w4wvdstssTAaa9c9tsQ5-UED2bFRL1MsyBdbmCF_-pu3i-ZIYqWgiKbjVBe3nlAVbo77zizwp3Y4Tp1_TBOwTAuFkHePmkNT63uPm9My_hNzsSm1o-Q519Cf7ry-JQmOVgz_jIgFVGFYJ17EV3KUIpUuDShuyCFATBQspgJSN2DoXRUlQjXXkNTj23OxxdT_cVLcLJjytyG6e5izME2R2aCkDBWIc1a4_sRJ0R396auPXG6KhJ7o_AgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEALu046p76aKgvoAEHFINkMTgKokPXf9mZ4IZx_BKz-qs1MPMxVtPIrQDVweBH6tYT7Hfj2naLry6SpZ3vUNP_FYeTFWgW1V03LiqacX-QQgbEYtn99Dt3ScGyzb7EH833ztb3vDJ_-ha_CJplIrg-kHBBrlLFWXhh-I9K1qLRTNpbhZ18ooFde4Sbhkw9o9fKivGhx9aYr7ZbjRsNtKit_DsG1nwEXz53TMJ2vB9IQY29coJv_n5NFLkvBfzbG5faRNiFcimPYBO2jFdaA2mWzfxltLtwMF_dBwzTXDpMo3TVT9zEdV8YpsWqr63igqGDZVpKenlkqvRTeGJVayVuMA"
		}`, &wfe.nonceService)))
	test.AssertEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:acme:error:unauthorized","detail":"Error creating new cert :: Authorizations for these names not found or expired: meep.com"}`)
	assertCsrLogged(t, mockLog)

	mockLog.Clear()
	responseWriter.Body.Reset()
	// openssl req -outform der -new -nodes -key wfe/test/178.key -subj /CN=not-an-example.com | b64url
	wfe.NewCertificate(responseWriter,
		makePostRequest(signRequest(t, `{
			"resource":"new-cert",
			"csr": "MIICYjCCAUoCAQAwHTEbMBkGA1UEAwwSbm90LWFuLWV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmqs7nue5oFxKBk2WaFZJAma2nm1oFyPIq19gYEAdQN4mWvaJ8RjzHFkDMYUrlIrGxCYuFJDHFUk9dh19Na1MIY-NVLgcSbyNcOML3bLbLEwGmvXPbbEOflBA9mxUS9TLMgXW5ghf_qbt4vmSGKloIim41QXt55QFW6O-84s8Kd2OE6df0wTsEwLhZB3j5pDU-t7j5vTMv4Tc7EptaPkOdfQn-68viUJjlYM_4yIBVRhWCdexFdylCKVLg0obsghQEwULKYCUjdg6F0VJUI115DU49tzscXU_3FS3CyY8rchunuYszBNkdmgpAwViHNWuP7ESdEd_emrj1xuioSe6PwIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAE_T1nWU38XVYL28hNVSXU0rW5IBUKtbvr0qAkD4kda4HmQRTYkt-LNSuvxoZCC9lxijjgtJi-OJe_DCTdZZpYzewlVvcKToWSYHYQ6Wm1-fxxD_XzphvZOujpmBySchdiz7QSVWJmVZu34XD5RJbIcrmj_cjRt42J1hiTFjNMzQu9U6_HwIMmliDL-soFY2RTvvZf-dAFvOUQ-Wbxt97eM1PbbmxJNWRhbAmgEpe9PWDPTpqV5AK56VAa991cQ1P8ZVmPss5hvwGWhOtpnpTZVHN3toGNYFKqxWPboirqushQlfKiFqT9rpRgM3-mFjOHidGqsKEkTdmfSVlVEk3oo="
		}`, &wfe.nonceService)))
	assertCsrLogged(t, mockLog)
	cert, err := core.LoadCert("test/not-an-example.com.crt")
	test.AssertNotError(t, err, "Could not load cert")
	test.AssertEquals(t,
		responseWriter.Body.String(),
		string(cert.Raw))
	test.Assert(
		t, strings.HasPrefix(responseWriter.Header().Get("Location"), "/acme/cert"),
		"Missing Location header on certificate issuance.")
	test.AssertEquals(
		t, responseWriter.Header().Get("Link"),
		`</acme/issuer-cert>;rel="up"`)
	test.AssertEquals(
		t, responseWriter.Header().Get("Content-Type"),
		"application/pkix-cert")
	reqlogs := mockLog.GetAllMatching(`Certificate request - successful`)
	test.AssertEquals(t, len(reqlogs), 1)
	test.AssertEquals(t, reqlogs[0].Priority, syslog.LOG_NOTICE)
	test.AssertContains(t, reqlogs[0].Message, `[AUDIT] `)
	test.AssertContains(t, reqlogs[0].Message, `"CommonName":"not-an-example.com",`)
}

func TestChallenge(t *testing.T) {
	wfe := setupWFE(t)

	wfe.RA = &MockRegistrationAuthority{}
	wfe.SA = &mocks.MockSA{}
	responseWriter := httptest.NewRecorder()

	var key jose.JsonWebKey
	err := json.Unmarshal([]byte(`
		{
			"e": "AQAB",
			"kty": "RSA",
			"n": "tSwgy3ORGvc7YJI9B2qqkelZRUC6F1S5NwXFvM4w5-M0TsxbFsH5UH6adigV0jzsDJ5imAechcSoOhAh9POceCbPN1sTNwLpNbOLiQQ7RD5mY_pSUHWXNmS9R4NZ3t2fQAzPeW7jOfF0LKuJRGkekx6tXP1uSnNibgpJULNc4208dgBaCHo3mvaE2HV2GmVl1yxwWX5QZZkGQGjNDZYnjFfa2DKVvFs0QbAk21ROm594kAxlRlMMrvqlf24Eq4ERO0ptzpZgm_3j_e4hGRD39gJS7kAzK-j2cacFQ5Qi2Y6wZI2p-FCq_wiYsfEAIkATPBiLKl_6d_Jfcvs_impcXQ"
		}
	`), &key)
	test.AssertNotError(t, err, "Could not unmarshal testing key")

	challengeURL := "/acme/challenge/valid/23"
	wfe.Challenge(responseWriter,
		makePostRequestWithPath(challengeURL,
			signRequest(t, `{"resource":"challenge"}`, &wfe.nonceService)))

	test.AssertEquals(t, responseWriter.Code, 202)
	test.AssertEquals(
		t, responseWriter.Header().Get("Location"),
		challengeURL)
	test.AssertEquals(
		t, responseWriter.Header().Get("Link"),
		`</acme/authz/valid>;rel="up"`)
	test.AssertEquals(
		t, responseWriter.Body.String(),
		`{"type":"dns","uri":"/acme/challenge/valid/23"}`)
}

func TestNewRegistration(t *testing.T) {
	wfe := setupWFE(t)
	mux, err := wfe.Handler()
	test.AssertNotError(t, err, "Problem setting up HTTP handlers")

	wfe.RA = &MockRegistrationAuthority{}
	wfe.SA = &mocks.MockSA{}
	wfe.Stats, _ = statsd.NewNoopClient()
	wfe.SubscriberAgreementURL = agreementURL

	key, err := jose.LoadPrivateKey([]byte(test2KeyPrivatePEM))
	test.AssertNotError(t, err, "Failed to load key")
	rsaKey, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	signer, err := jose.NewSigner("RS256", rsaKey)
	test.AssertNotError(t, err, "Failed to make signer")
	nonce, err := wfe.nonceService.Nonce()
	test.AssertNotError(t, err, "Unable to create nonce")
	result, err := signer.Sign([]byte("foo"), nonce)

	nonce, err = wfe.nonceService.Nonce()
	test.AssertNotError(t, err, "Unable to create nonce")
	fooBody, err := signer.Sign([]byte("foo"), nonce)
	test.AssertNotError(t, err, "Unable to sign")

	nonce, err = wfe.nonceService.Nonce()
	test.AssertNotError(t, err, "Unable to create nonce")
	wrongAgreementBody, err := signer.Sign(
		[]byte(`{"resource":"new-reg","contact":["tel:123456789"],"agreement":"https://letsencrypt.org/im-bad"}`),
		nonce)
	test.AssertNotError(t, err, "Unable to sign")

	type newRegErrorTest struct {
		r        *http.Request
		respBody string
	}
	regErrTests := []newRegErrorTest{
		// GET instead of POST should be rejected
		{
			&http.Request{
				Method: "GET",
				URL:    mustParseURL(NewRegPath),
			},
			`{"type":"urn:acme:error:malformed","detail":"Method not allowed"}`,
		},

		// POST, but no body.
		{
			&http.Request{
				Method: "POST",
				URL:    mustParseURL(NewRegPath),
				Header: map[string][]string{
					"Content-Length": []string{"0"},
				},
			},
			`{"type":"urn:acme:error:malformed","detail":"Unable to read/verify body :: No body on POST"}`,
		},

		// POST, but body that isn't valid JWS
		{
			makePostRequestWithPath(NewRegPath, "hi"),
			`{"type":"urn:acme:error:malformed","detail":"Unable to read/verify body :: Parse error reading JWS"}`,
		},

		// POST, Properly JWS-signed, but payload is "foo", not base64-encoded JSON.
		{
			makePostRequestWithPath(NewRegPath, fooBody.FullSerialize()),
			`{"type":"urn:acme:error:malformed","detail":"Unable to read/verify body :: Request payload did not parse as JSON"}`,
		},

		// Same signed body, but payload modified by one byte, breaking signature.
		// should fail JWS verification.
		{
			makePostRequestWithPath(NewRegPath, `
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
			`{"type":"urn:acme:error:malformed","detail":"Unable to read/verify body :: JWS verification error"}`,
		},
		{
			makePostRequestWithPath(NewRegPath, wrongAgreementBody.FullSerialize()),
			`{"type":"urn:acme:error:malformed","detail":"Provided agreement URL [https://letsencrypt.org/im-bad] does not match current agreement URL [` + agreementURL + `]"}`,
		},
	}
	for _, rt := range regErrTests {
		responseWriter := httptest.NewRecorder()
		mux.ServeHTTP(responseWriter, rt.r)
		test.AssertEquals(t, responseWriter.Body.String(), rt.respBody)
	}

	responseWriter := httptest.NewRecorder()
	nonce, err = wfe.nonceService.Nonce()
	test.AssertNotError(t, err, "Unable to create nonce")
	result, err = signer.Sign([]byte(`{"resource":"new-reg","contact":["tel:123456789"],"agreement":"`+agreementURL+`"}`), nonce)
	wfe.NewRegistration(responseWriter,
		makePostRequest(result.FullSerialize()))

	test.AssertEquals(t, responseWriter.Body.String(), `{"id":0,"key":{"kty":"RSA","n":"qnARLrT7Xz4gRcKyLdydmCr-ey9OuPImX4X40thk3on26FkMznR3fRjs66eLK7mmPcBZ6uOJseURU6wAaZNmemoYx1dMvqvWWIyiQleHSD7Q8vBrhR6uIoO4jAzJZR-ChzZuSDt7iHN-3xUVspu5XGwXU_MVJZshTwp4TaFx5elHIT_ObnTvTOU3Xhish07AbgZKmWsVbXh5s-CrIicU4OexJPgunWZ_YJJueOKmTvnLlTV4MzKR2oZlBKZ27S0-SfdV_QDx_ydle5oMAyKVtlAV35cyPMIsYNwgUGBCdY_2Uzi5eX0lTc7MPRwz6qR1kip-i59VcGcUQgqHV6Fyqw","e":"AQAB"},"contact":["tel:123456789"],"agreement":"http://example.invalid/terms"}`)
	var reg core.Registration
	err = json.Unmarshal([]byte(responseWriter.Body.String()), &reg)
	test.AssertNotError(t, err, "Couldn't unmarshal returned registration object")
	test.Assert(t, len(reg.Contact) >= 1, "No contact field in registration")
	test.AssertEquals(t, reg.Contact[0].String(), "tel:123456789")

	test.AssertEquals(
		t, responseWriter.Header().Get("Location"),
		"/acme/reg/0")
	links := responseWriter.Header()["Link"]
	test.AssertEquals(t, contains(links, "</acme/new-authz>;rel=\"next\""), true)
	test.AssertEquals(t, contains(links, "<"+agreementURL+">;rel=\"terms-of-service\""), true)

	test.AssertEquals(
		t, responseWriter.Header().Get("Link"),
		`</acme/new-authz>;rel="next"`)

	key, err = jose.LoadPrivateKey([]byte(test1KeyPrivatePEM))
	test.AssertNotError(t, err, "Failed to load key")
	rsaKey, ok = key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	signer, err = jose.NewSigner("RS256", rsaKey)
	test.AssertNotError(t, err, "Failed to make signer")

	// Reset the body and status code
	responseWriter = httptest.NewRecorder()
	// POST, Valid JSON, Key already in use
	nonce, err = wfe.nonceService.Nonce()
	test.AssertNotError(t, err, "Unable to create nonce")
	result, err = signer.Sign([]byte(`{"resource":"new-reg","contact":["tel:123456789"],"agreement":"`+agreementURL+`"}`), nonce)

	wfe.NewRegistration(responseWriter,
		makePostRequest(result.FullSerialize()))
	test.AssertEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"Registration key is already in use"}`)
	test.AssertEquals(
		t, responseWriter.Header().Get("Location"),
		"/acme/reg/1")
	test.AssertEquals(t, responseWriter.Code, 409)
}

func makeRevokeRequestJSON() ([]byte, error) {
	certPemBytes, err := ioutil.ReadFile("test/238.crt")
	if err != nil {
		return nil, err
	}
	certBlock, _ := pem.Decode(certPemBytes)
	if err != nil {
		return nil, err
	}
	revokeRequest := struct {
		Resource       string          `json:"resource"`
		CertificateDER core.JSONBuffer `json:"certificate"`
	}{
		Resource:       "revoke-cert",
		CertificateDER: certBlock.Bytes,
	}
	revokeRequestJSON, err := json.Marshal(revokeRequest)
	if err != nil {
		return nil, err
	}
	return revokeRequestJSON, nil
}

// Valid revocation request for existing, non-revoked cert, signed with cert
// key.
func TestRevokeCertificateCertKey(t *testing.T) {
	keyPemBytes, err := ioutil.ReadFile("test/238.key")
	test.AssertNotError(t, err, "Failed to load key")
	key, err := jose.LoadPrivateKey(keyPemBytes)
	test.AssertNotError(t, err, "Failed to load key")
	rsaKey, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	signer, err := jose.NewSigner("RS256", rsaKey)
	test.AssertNotError(t, err, "Failed to make signer")

	revokeRequestJSON, err := makeRevokeRequestJSON()
	test.AssertNotError(t, err, "Failed to make revokeRequestJSON")

	wfe := setupWFE(t)
	responseWriter := httptest.NewRecorder()

	nonce, err := wfe.nonceService.Nonce()
	test.AssertNotError(t, err, "Unable to create nonce")
	result, _ := signer.Sign(revokeRequestJSON, nonce)
	wfe.RevokeCertificate(responseWriter,
		makePostRequest(result.FullSerialize()))
	test.AssertEquals(t, responseWriter.Code, 200)
	test.AssertEquals(t, responseWriter.Body.String(), "")
}

// Valid revocation request for existing, non-revoked cert, signed with account
// key.
func TestRevokeCertificateAccountKey(t *testing.T) {
	revokeRequestJSON, err := makeRevokeRequestJSON()
	test.AssertNotError(t, err, "Failed to make revokeRequestJSON")

	wfe := setupWFE(t)
	responseWriter := httptest.NewRecorder()

	test1JWK, err := jose.LoadPrivateKey([]byte(test1KeyPrivatePEM))
	test.AssertNotError(t, err, "Failed to load key")
	test1Key, ok := test1JWK.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	accountKeySigner, err := jose.NewSigner("RS256", test1Key)
	test.AssertNotError(t, err, "Failed to make signer")
	nonce, err := wfe.nonceService.Nonce()
	test.AssertNotError(t, err, "Unable to create nonce")
	result, _ := accountKeySigner.Sign(revokeRequestJSON, nonce)
	wfe.RevokeCertificate(responseWriter,
		makePostRequest(result.FullSerialize()))
	test.AssertEquals(t, responseWriter.Code, 200)
	test.AssertEquals(t, responseWriter.Body.String(), "")
}

// A revocation request signed by an unauthorized key.
func TestRevokeCertificateWrongKey(t *testing.T) {
	wfe := setupWFE(t)
	nonce, err := wfe.nonceService.Nonce()
	test.AssertNotError(t, err, "Unable to create nonce")
	responseWriter := httptest.NewRecorder()
	test2JWK, err := jose.LoadPrivateKey([]byte(test2KeyPrivatePEM))
	test.AssertNotError(t, err, "Failed to load key")
	test2Key, ok := test2JWK.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	accountKeySigner2, err := jose.NewSigner("RS256", test2Key)
	test.AssertNotError(t, err, "Failed to make signer")
	nonce, err = wfe.nonceService.Nonce()
	test.AssertNotError(t, err, "Unable to create nonce")
	revokeRequestJSON, err := makeRevokeRequestJSON()
	test.AssertNotError(t, err, "Unable to create revoke request")

	result, _ := accountKeySigner2.Sign(revokeRequestJSON, nonce)
	wfe.RevokeCertificate(responseWriter,
		makePostRequest(result.FullSerialize()))
	test.AssertEquals(t, responseWriter.Code, 403)
	test.AssertEquals(t, responseWriter.Body.String(),
		`{"type":"urn:acme:error:unauthorized","detail":"Revocation request must be signed by private key of cert to be revoked, or by the account key of the account that issued it."}`)
}

// Valid revocation request for already-revoked cert
func TestRevokeCertificateAlreadyRevoked(t *testing.T) {
	keyPemBytes, err := ioutil.ReadFile("test/178.key")
	test.AssertNotError(t, err, "Failed to load key")
	key, err := jose.LoadPrivateKey(keyPemBytes)
	test.AssertNotError(t, err, "Failed to load key")
	rsaKey, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	signer, err := jose.NewSigner("RS256", rsaKey)
	test.AssertNotError(t, err, "Failed to make signer")

	certPemBytes, err := ioutil.ReadFile("test/178.crt")
	test.AssertNotError(t, err, "Failed to load cert")
	certBlock, _ := pem.Decode(certPemBytes)
	test.Assert(t, certBlock != nil, "Failed to decode PEM")
	revokeRequest := struct {
		Resource       string          `json:"resource"`
		CertificateDER core.JSONBuffer `json:"certificate"`
	}{
		Resource:       "revoke-cert",
		CertificateDER: certBlock.Bytes,
	}
	revokeRequestJSON, err := json.Marshal(revokeRequest)
	test.AssertNotError(t, err, "Failed to marshal request")

	// POST, Properly JWS-signed, but payload is "foo", not base64-encoded JSON.
	wfe := setupWFE(t)

	wfe.RA = &MockRegistrationAuthority{}
	wfe.SA = &mocks.MockSA{}
	wfe.Stats, _ = statsd.NewNoopClient()
	wfe.SubscriberAgreementURL = agreementURL
	responseWriter := httptest.NewRecorder()
	responseWriter.Body.Reset()
	nonce, err := wfe.nonceService.Nonce()
	test.AssertNotError(t, err, "Unable to create nonce")
	result, _ := signer.Sign(revokeRequestJSON, nonce)
	wfe.RevokeCertificate(responseWriter,
		makePostRequest(result.FullSerialize()))
	test.AssertEquals(t, responseWriter.Code, 409)
	test.AssertEquals(t, responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"Certificate already revoked"}`)
}

func TestAuthorization(t *testing.T) {
	wfe := setupWFE(t)
	mux, err := wfe.Handler()
	test.AssertNotError(t, err, "Problem setting up HTTP handlers")

	wfe.RA = &MockRegistrationAuthority{}
	wfe.SA = &mocks.MockSA{}
	wfe.Stats, _ = statsd.NewNoopClient()
	responseWriter := httptest.NewRecorder()

	// GET instead of POST should be rejected
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(NewAuthzPath),
	})
	test.AssertEquals(t, responseWriter.Body.String(), `{"type":"urn:acme:error:malformed","detail":"Method not allowed"}`)

	// POST, but no body.
	responseWriter.Body.Reset()
	wfe.NewAuthorization(responseWriter, &http.Request{
		Method: "POST",
		Header: map[string][]string{
			"Content-Length": []string{"0"},
		},
	})
	test.AssertEquals(t, responseWriter.Body.String(), `{"type":"urn:acme:error:malformed","detail":"Unable to read/verify body :: No body on POST"}`)

	// POST, but body that isn't valid JWS
	responseWriter.Body.Reset()
	wfe.NewAuthorization(responseWriter, makePostRequest("hi"))
	test.AssertEquals(t, responseWriter.Body.String(), `{"type":"urn:acme:error:malformed","detail":"Unable to read/verify body :: Parse error reading JWS"}`)

	// POST, Properly JWS-signed, but payload is "foo", not base64-encoded JSON.
	responseWriter.Body.Reset()
	wfe.NewAuthorization(responseWriter,
		makePostRequest(signRequest(t, "foo", &wfe.nonceService)))
	test.AssertEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"Unable to read/verify body :: Request payload did not parse as JSON"}`)

	// Same signed body, but payload modified by one byte, breaking signature.
	// should fail JWS verification.
	responseWriter.Body.Reset()
	wfe.NewAuthorization(responseWriter, makePostRequest(`
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
		`))
	test.AssertEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"Unable to read/verify body :: JWS verification error"}`)

	responseWriter.Body.Reset()
	wfe.NewAuthorization(responseWriter,
		makePostRequest(signRequest(t, `{"resource":"new-authz","identifier":{"type":"dns","value":"test.com"}}`, &wfe.nonceService)))

	test.AssertEquals(
		t, responseWriter.Header().Get("Location"),
		"/acme/authz/bkrPh2u0JUf18-rVBZtOOWWb3GuIiliypL-hBM9Ak1Q")
	test.AssertEquals(
		t, responseWriter.Header().Get("Link"),
		`</acme/new-cert>;rel="next"`)

	test.AssertEquals(t, responseWriter.Body.String(), `{"identifier":{"type":"dns","value":"test.com"}}`)

	var authz core.Authorization
	err = json.Unmarshal([]byte(responseWriter.Body.String()), &authz)
	test.AssertNotError(t, err, "Couldn't unmarshal returned authorization object")
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func TestRegistration(t *testing.T) {
	wfe := setupWFE(t)
	mux, err := wfe.Handler()
	test.AssertNotError(t, err, "Problem setting up HTTP handlers")

	wfe.RA = &MockRegistrationAuthority{}
	wfe.SA = &mocks.MockSA{}
	wfe.Stats, _ = statsd.NewNoopClient()
	wfe.SubscriberAgreementURL = agreementURL
	responseWriter := httptest.NewRecorder()

	// Test invalid method
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "MAKE-COFFEE",
		URL:    mustParseURL(RegPath),
		Body:   makeBody("invalid"),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"Method not allowed"}`)
	responseWriter.Body.Reset()

	// Test GET proper entry returns 405
	mux.ServeHTTP(responseWriter, &http.Request{
		Method: "GET",
		URL:    mustParseURL(RegPath),
	})
	test.AssertEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"Method not allowed"}`)
	responseWriter.Body.Reset()

	// Test POST invalid JSON
	wfe.Registration(responseWriter, makePostRequestWithPath("/2", "invalid"))
	test.AssertEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"Unable to read/verify body :: Parse error reading JWS"}`)
	responseWriter.Body.Reset()

	key, err := jose.LoadPrivateKey([]byte(test2KeyPrivatePEM))
	test.AssertNotError(t, err, "Failed to load key")
	rsaKey, ok := key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	signer, err := jose.NewSigner("RS256", rsaKey)
	test.AssertNotError(t, err, "Failed to make signer")

	// Test POST valid JSON but key is not registered
	nonce, err := wfe.nonceService.Nonce()
	test.AssertNotError(t, err, "Unable to create nonce")
	result, err := signer.Sign([]byte(`{"resource":"reg","agreement":"`+agreementURL+`"}`), nonce)
	test.AssertNotError(t, err, "Unable to sign")
	wfe.Registration(responseWriter,
		makePostRequestWithPath("/2", result.FullSerialize()))
	test.AssertEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:acme:error:unauthorized","detail":"No registration exists matching provided key"}`)
	responseWriter.Body.Reset()

	key, err = jose.LoadPrivateKey([]byte(test1KeyPrivatePEM))
	test.AssertNotError(t, err, "Failed to load key")
	rsaKey, ok = key.(*rsa.PrivateKey)
	test.Assert(t, ok, "Couldn't load RSA key")
	signer, err = jose.NewSigner("RS256", rsaKey)
	test.AssertNotError(t, err, "Failed to make signer")

	// Test POST valid JSON with registration up in the mock (with incorrect agreement URL)
	nonce, err = wfe.nonceService.Nonce()
	test.AssertNotError(t, err, "Unable to create nonce")
	result, err = signer.Sign([]byte(`{"resource":"reg","agreement":"https://letsencrypt.org/im-bad"}`), nonce)

	// Test POST valid JSON with registration up in the mock
	wfe.Registration(responseWriter,
		makePostRequestWithPath("/1", result.FullSerialize()))
	test.AssertEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"Provided agreement URL [https://letsencrypt.org/im-bad] does not match current agreement URL [`+agreementURL+`]"}`)
	responseWriter.Body.Reset()

	// Test POST valid JSON with registration up in the mock (with correct agreement URL)
	nonce, err = wfe.nonceService.Nonce()
	test.AssertNotError(t, err, "Unable to create nonce")
	result, err = signer.Sign([]byte(`{"resource":"reg","agreement":"`+agreementURL+`"}`), nonce)
	test.AssertNotError(t, err, "Couldn't sign")
	wfe.Registration(responseWriter,
		makePostRequestWithPath("/1", result.FullSerialize()))
	test.AssertNotContains(t, responseWriter.Body.String(), "urn:acme:error")
	links := responseWriter.Header()["Link"]
	test.AssertEquals(t, contains(links, "</acme/new-authz>;rel=\"next\""), true)
	test.AssertEquals(t, contains(links, "<"+agreementURL+">;rel=\"terms-of-service\""), true)

	responseWriter.Body.Reset()
}

func TestTermsRedirect(t *testing.T) {
	wfe := setupWFE(t)

	wfe.RA = &MockRegistrationAuthority{}
	wfe.SA = &mocks.MockSA{}
	wfe.Stats, _ = statsd.NewNoopClient()
	wfe.SubscriberAgreementURL = agreementURL

	responseWriter := httptest.NewRecorder()

	path, _ := url.Parse("/terms")
	wfe.Terms(responseWriter, &http.Request{
		Method: "GET",
		URL:    path,
	})
	test.AssertEquals(
		t, responseWriter.Header().Get("Location"),
		agreementURL)
	test.AssertEquals(t, responseWriter.Code, 302)
}

func TestIssuer(t *testing.T) {
	wfe := setupWFE(t)
	wfe.IssuerCacheDuration = time.Second * 10
	wfe.IssuerCert = []byte{0, 0, 1}

	responseWriter := httptest.NewRecorder()

	wfe.Issuer(responseWriter, &http.Request{
		Method: "GET",
	})
	test.AssertEquals(t, responseWriter.Code, http.StatusOK)
	test.Assert(t, bytes.Compare(responseWriter.Body.Bytes(), wfe.IssuerCert) == 0, "Incorrect bytes returned")
	test.AssertEquals(t, responseWriter.Header().Get("Cache-Control"), "public, max-age=10")
}

func TestGetCertificate(t *testing.T) {
	wfe := setupWFE(t)
	wfe.CertCacheDuration = time.Second * 10
	wfe.CertNoCacheExpirationWindow = time.Hour * 24 * 7
	wfe.SA = &mocks.MockSA{}

	certPemBytes, _ := ioutil.ReadFile("test/178.crt")
	certBlock, _ := pem.Decode(certPemBytes)

	responseWriter := httptest.NewRecorder()

	// Valid serial, cached
	path, _ := url.Parse("/acme/cert/0000000000000000000000000000000000b2")
	wfe.Certificate(responseWriter, &http.Request{
		Method: "GET",
		URL:    path,
	})
	test.AssertEquals(t, responseWriter.Code, 200)
	test.AssertEquals(t, responseWriter.Header().Get("Cache-Control"), "public, max-age=10")
	test.AssertEquals(t, responseWriter.Header().Get("Content-Type"), "application/pkix-cert")
	test.Assert(t, bytes.Compare(responseWriter.Body.Bytes(), certBlock.Bytes) == 0, "Certificates don't match")

	// Unused serial, no cache
	responseWriter = httptest.NewRecorder()
	path, _ = url.Parse("/acme/cert/0000000000000000000000000000000000ff")
	wfe.Certificate(responseWriter, &http.Request{
		Method: "GET",
		URL:    path,
	})
	test.AssertEquals(t, responseWriter.Code, 404)
	test.AssertEquals(t, responseWriter.Header().Get("Cache-Control"), "public, max-age=0, no-cache")
	test.AssertEquals(t, responseWriter.Body.String(), `{"type":"urn:acme:error:malformed","detail":"Certificate not found"}`)

	// Invalid serial, no cache
	responseWriter = httptest.NewRecorder()
	path, _ = url.Parse("/acme/cert/nothex")
	wfe.Certificate(responseWriter, &http.Request{
		Method: "GET",
		URL:    path,
	})
	test.AssertEquals(t, responseWriter.Code, 404)
	test.AssertEquals(t, responseWriter.Header().Get("Cache-Control"), "public, max-age=0, no-cache")
	test.AssertEquals(t, responseWriter.Body.String(), `{"type":"urn:acme:error:malformed","detail":"Certificate not found"}`)

	// Invalid serial, no cache
	responseWriter = httptest.NewRecorder()
	path, _ = url.Parse("/acme/cert/00000000000000")
	wfe.Certificate(responseWriter, &http.Request{
		Method: "GET",
		URL:    path,
	})
	test.AssertEquals(t, responseWriter.Code, 404)
	test.AssertEquals(t, responseWriter.Header().Get("Cache-Control"), "public, max-age=0, no-cache")
	test.AssertEquals(t, responseWriter.Body.String(), `{"type":"urn:acme:error:malformed","detail":"Certificate not found"}`)
}

func assertCsrLogged(t *testing.T, mockLog *mocks.MockSyslogWriter) {
	matches := mockLog.GetAllMatching("^\\[AUDIT\\] Certificate request JSON=")
	test.Assert(t, len(matches) == 1,
		fmt.Sprintf("Incorrect number of certificate request log entries: %d",
			len(matches)))
	test.AssertEquals(t, matches[0].Priority, syslog.LOG_NOTICE)
}

func TestLogCsrPem(t *testing.T) {
	const certificateRequestJson = `{
		"csr": "MIICWTCCAUECAQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAycX3ca-fViOuRWF38mssORISFxbJvspDfhPGRBZDxJ63NIqQzupB-6dp48xkcX7Z_KDaRJStcpJT2S0u33moNT4FHLklQBETLhExDk66cmlz6Xibp3LGZAwhWuec7wJoEwIgY8oq4rxihIyGq7HVIJoq9DqZGrUgfZMDeEJqbphukQOaXGEop7mD-eeu8-z5EVkB1LiJ6Yej6R8MAhVPHzG5fyOu6YVo6vY6QgwjRLfZHNj5XthxgPIEETZlUbiSoI6J19GYHvLURBTy5Ys54lYAPIGfNwcIBAH4gtH9FrYcDY68R22rp4iuxdvkf03ZWiT0F2W1y7_C9B2jayTzvQIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAHd6Do9DIZ2hvdt1GwBXYjsqprZidT_DYOMfYcK17KlvdkFT58XrBH88ulLZ72NXEpiFMeTyzfs3XEyGq_Bbe7TBGVYZabUEh-LOskYwhgcOuThVN7tHnH5rhN-gb7cEdysjTb1QL-vOUwYgV75CB6PE5JVYK-cQsMIVvo0Kz4TpNgjJnWzbcH7h0mtvub-fCv92vBPjvYq8gUDLNrok6rbg05tdOJkXsF2G_W-Q6sf2Fvx0bK5JeH4an7P7cXF9VG9nd4sRt5zd-L3IcyvHVKxNhIJXZVH0AOqh_1YrKI9R0QKQiZCEy0xN1okPlcaIVaFhb7IKAHPxTI3r5f72LXY"
	}`
	wfe := setupWFE(t)
	var certificateRequest core.CertificateRequest
	err := json.Unmarshal([]byte(certificateRequestJson), &certificateRequest)
	test.AssertNotError(t, err, "Unable to parse certificateRequest")

	mockSA := mocks.MockSA{}
	reg, err := mockSA.GetRegistration(789)
	test.AssertNotError(t, err, "Unable to get registration")

	remoteAddr := "12.34.98.76"

	wfe.logCsr(remoteAddr, certificateRequest, reg)

	mockLog := wfe.log.SyslogWriter.(*mocks.MockSyslogWriter)
	matches := mockLog.GetAllMatching("Certificate request")
	test.Assert(t, len(matches) == 1,
		"Incorrect number of certificate request log entries")
	test.AssertEquals(t, matches[0].Priority, syslog.LOG_NOTICE)
	test.AssertEquals(t, matches[0].Message, `[AUDIT] Certificate request JSON={"RemoteAddr":"12.34.98.76","CsrBase64":"MIICWTCCAUECAQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAycX3ca+fViOuRWF38mssORISFxbJvspDfhPGRBZDxJ63NIqQzupB+6dp48xkcX7Z/KDaRJStcpJT2S0u33moNT4FHLklQBETLhExDk66cmlz6Xibp3LGZAwhWuec7wJoEwIgY8oq4rxihIyGq7HVIJoq9DqZGrUgfZMDeEJqbphukQOaXGEop7mD+eeu8+z5EVkB1LiJ6Yej6R8MAhVPHzG5fyOu6YVo6vY6QgwjRLfZHNj5XthxgPIEETZlUbiSoI6J19GYHvLURBTy5Ys54lYAPIGfNwcIBAH4gtH9FrYcDY68R22rp4iuxdvkf03ZWiT0F2W1y7/C9B2jayTzvQIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAHd6Do9DIZ2hvdt1GwBXYjsqprZidT/DYOMfYcK17KlvdkFT58XrBH88ulLZ72NXEpiFMeTyzfs3XEyGq/Bbe7TBGVYZabUEh+LOskYwhgcOuThVN7tHnH5rhN+gb7cEdysjTb1QL+vOUwYgV75CB6PE5JVYK+cQsMIVvo0Kz4TpNgjJnWzbcH7h0mtvub+fCv92vBPjvYq8gUDLNrok6rbg05tdOJkXsF2G/W+Q6sf2Fvx0bK5JeH4an7P7cXF9VG9nd4sRt5zd+L3IcyvHVKxNhIJXZVH0AOqh/1YrKI9R0QKQiZCEy0xN1okPlcaIVaFhb7IKAHPxTI3r5f72LXY=","Registration":{"id":789,"key":{"kty":"RSA","n":"yNWVhtYEKJR21y9xsHV-PD_bYwbXSeNuFal46xYxVfRL5mqha7vttvjB_vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K_klBYN8oYvTwwmeSkAz6ut7ZxPv-nZaT5TJhGk0NT2kh_zSpdriEJ_3vW-mqxYbbBmpvHqsa1_zx9fSuHYctAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV-mzfMyboQjujPh7aNJxAWSq4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF-w8hOTI3XXohUdu29Se26k2B0PolDSuj0GIQU6-W9TdLXSjBb2SpQ","e":"AQAB"},"agreement":"http://example.invalid/terms"}}`)
}

func TestLengthRequired(t *testing.T) {
	wfe := setupWFE(t)
	_, _, _, err := wfe.verifyPOST(&http.Request{
		Method: "POST",
		URL:    mustParseURL("/"),
	}, false, "resource")
	test.Assert(t, err != nil, "No error returned for request body missing Content-Length.")
	_, ok := err.(core.LengthRequiredError)
	test.Assert(t, ok, "Error code for missing content-length wasn't 411.")
}

func TestBadKeyCSR(t *testing.T) {
	wfe := setupWFE(t)
	responseWriter := httptest.NewRecorder()

	// CSR with a bad (512 bit RSA) key.
	// openssl req -outform der -new -newkey rsa:512 -nodes -keyout foo.com.key
	//   -subj /CN=foo.com | base64 -w0 | sed -e 's,+,-,g' -e 's,/,_,g'
	wfe.NewCertificate(responseWriter,
		makePostRequest(signRequest(t, `{
			"resource":"new-cert",
			"csr": "MIHLMHcCAQAwEjEQMA4GA1UEAwwHZm9vLmNvbTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDCZftp4x4owgjBnwOKfzihIPedT-BUmV2fuQPMqaUlc8yJUp13vcO5uxUlaBm8leM7Dj_sgTDP_JgykorlYo73AgMBAAGgADANBgkqhkiG9w0BAQsFAANBAEaQ2QBhweK-kp1ejQCedUhMit_wG-uTBtKnc3M82f6_fztLkhg1vWQ782nmhbEI5orXp6QtNHgJYnBpqA9Ut00"
		}`, &wfe.nonceService)))

	test.AssertEquals(t,
		responseWriter.Body.String(),
		`{"type":"urn:acme:error:malformed","detail":"Invalid key in certificate request :: Key too small: 512"}`)
}
