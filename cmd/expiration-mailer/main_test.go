// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"testing"
	"text/template"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/square/go-jose"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
)

func bigIntFromB64(b64 string) *big.Int {
	bytes, _ := base64.URLEncoding.DecodeString(b64)
	x := big.NewInt(0)
	x.SetBytes(bytes)
	return x
}

func intFromB64(b64 string) int {
	return int(bigIntFromB64(b64).Int64())
}

type fakeRegStore struct {
	RegByID map[int64]core.Registration
}

func (f fakeRegStore) GetRegistration(id int64) (core.Registration, error) {
	r, ok := f.RegByID[id]
	if !ok {
		msg := fmt.Sprintf("no such registration %d", id)
		return r, core.NoSuchRegistrationError(msg)
	}
	return r, nil
}

func newFakeRegStore() fakeRegStore {
	return fakeRegStore{RegByID: make(map[int64]core.Registration)}
}

func newFakeClock(t *testing.T) clock.FakeClock {
	const fakeTimeFormat = "2006-01-02T15:04:05.999999999Z"
	ft, err := time.Parse(fakeTimeFormat, fakeTimeFormat)
	if err != nil {
		t.Fatal(err)
	}
	fc := clock.NewFake()
	fc.Set(ft.UTC())
	return fc
}

const testTmpl = `hi, cert for DNS names {{.DNSNames}} is going to expire in {{.DaysToExpiration}} days ({{.ExpirationDate}})`
const testEmailSubject = `email subject for test`
const emailARaw = "rolandshoemaker@gmail.com"
const emailBRaw = "test@gmail.com"

var (
	emailA, _ = core.ParseAcmeURL("mailto:" + emailARaw)
	emailB, _ = core.ParseAcmeURL("mailto:" + emailBRaw)
	jsonKeyA  = []byte(`{
  "kty":"RSA",
  "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
  "e":"AQAB"
}`)
	jsonKeyB = []byte(`{
  "kty":"RSA",
  "n":"z8bp-jPtHt4lKBqepeKF28g_QAEOuEsCIou6sZ9ndsQsEjxEOQxQ0xNOQezsKa63eogw8YS3vzjUcPP5BJuVzfPfGd5NVUdT-vSSwxk3wvk_jtNqhrpcoG0elRPQfMVsQWmxCAXCVRz3xbcFI8GTe-syynG3l-g1IzYIIZVNI6jdljCZML1HOMTTW4f7uJJ8mM-08oQCeHbr5ejK7O2yMSSYxW03zY-Tj1iVEebROeMv6IEEJNFSS4yM-hLpNAqVuQxFGetwtwjDMC1Drs1dTWrPuUAAjKGrP151z1_dE74M5evpAhZUmpKv1hY-x85DC6N0hFPgowsanmTNNiV75w",
  "e":"AAEAAQ"
}`)
	log  = mocks.UseMockLog()
	tmpl = template.Must(template.New("expiry-email").Parse(testTmpl))
)

func TestSendNags(t *testing.T) {
	stats, _ := statsd.NewNoopClient(nil)
	mc := mocks.Mailer{}
	rs := newFakeRegStore()
	fc := newFakeClock(t)

	m := mailer{
		stats:         stats,
		mailer:        &mc,
		emailTemplate: tmpl,
		subject:       testEmailSubject,
		rs:            rs,
		clk:           fc,
	}

	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "happy",
		},
		NotAfter: fc.Now().AddDate(0, 0, 2),
		DNSNames: []string{"example.com"},
	}

	err := m.sendNags([]*core.AcmeURL{emailA}, []*x509.Certificate{cert})
	test.AssertNotError(t, err, "Failed to send warning messages")
	test.AssertEquals(t, len(mc.Messages), 1)
	test.AssertEquals(t, mocks.MailerMessage{
		To:      emailARaw,
		Subject: testEmailSubject,
		Body:    fmt.Sprintf(`hi, cert for DNS names example.com is going to expire in 2 days (%s)`, cert.NotAfter.Format(time.RFC822Z)),
	}, mc.Messages[0])

	mc.Clear()
	err = m.sendNags([]*core.AcmeURL{emailA, emailB}, []*x509.Certificate{cert})
	test.AssertNotError(t, err, "Failed to send warning messages")
	test.AssertEquals(t, len(mc.Messages), 2)
	test.AssertEquals(t, mocks.MailerMessage{
		To:      emailARaw,
		Subject: testEmailSubject,
		Body:    fmt.Sprintf(`hi, cert for DNS names example.com is going to expire in 2 days (%s)`, cert.NotAfter.Format(time.RFC822Z)),
	}, mc.Messages[0])
	test.AssertEquals(t, mocks.MailerMessage{
		To:      emailBRaw,
		Subject: testEmailSubject,
		Body:    fmt.Sprintf(`hi, cert for DNS names example.com is going to expire in 2 days (%s)`, cert.NotAfter.Format(time.RFC822Z)),
	}, mc.Messages[1])

	mc.Clear()
	err = m.sendNags([]*core.AcmeURL{}, []*x509.Certificate{cert})
	test.AssertNotError(t, err, "Not an error to pass no email contacts")
	test.AssertEquals(t, len(mc.Messages), 0)

	templates, err := template.ParseGlob("../../data/*.template")
	test.AssertNotError(t, err, "Failed to parse templates")
	for _, template := range templates.Templates() {
		m.emailTemplate = template
		err = m.sendNags(nil, []*x509.Certificate{cert})
		test.AssertNotError(t, err, "failed to send nag")
	}
}

var n = bigIntFromB64("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw==")
var e = intFromB64("AQAB")
var d = bigIntFromB64("bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ==")
var p = bigIntFromB64("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc=")
var q = bigIntFromB64("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc=")

var testKey = rsa.PrivateKey{
	PublicKey: rsa.PublicKey{N: n, E: e},
	D:         d,
	Primes:    []*big.Int{p, q},
}

func TestFindExpiringCertificates(t *testing.T) {
	ctx := setup(t, []time.Duration{time.Hour * 24, time.Hour * 24 * 4, time.Hour * 24 * 7})

	log.Clear()
	err := ctx.m.findExpiringCertificates()
	test.AssertNotError(t, err, "Failed on no certificates")
	test.AssertEquals(t, len(log.GetAllMatching("Searching for certificates that expire between.*")), 3)

	// Add some expiring certificates and registrations
	var keyA jose.JsonWebKey
	var keyB jose.JsonWebKey
	err = json.Unmarshal(jsonKeyA, &keyA)
	test.AssertNotError(t, err, "Failed to unmarshal public JWK")
	err = json.Unmarshal(jsonKeyB, &keyB)
	test.AssertNotError(t, err, "Failed to unmarshal public JWK")
	regA := core.Registration{
		ID: 1,
		Contact: []*core.AcmeURL{
			emailA,
		},
		Key:       keyA,
		InitialIP: net.ParseIP("2.3.2.3"),
	}
	regB := core.Registration{
		ID: 2,
		Contact: []*core.AcmeURL{
			emailB,
		},
		Key:       keyB,
		InitialIP: net.ParseIP("2.3.2.3"),
	}
	regA, err = ctx.ssa.NewRegistration(regA)
	if err != nil {
		t.Fatalf("Couldn't store regA: %s", err)
	}
	regB, err = ctx.ssa.NewRegistration(regB)
	if err != nil {
		t.Fatalf("Couldn't store regB: %s", err)
	}

	// Expires in <1d, last nag was the 4d nag
	rawCertA := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "happy A",
		},
		NotAfter:     ctx.fc.Now().Add(23 * time.Hour),
		DNSNames:     []string{"example-a.com"},
		SerialNumber: big.NewInt(1337),
	}
	certDerA, _ := x509.CreateCertificate(rand.Reader, &rawCertA, &rawCertA, &testKey.PublicKey, &testKey)
	certA := &core.Certificate{
		RegistrationID: regA.ID,
		Serial:         "001",
		Expires:        rawCertA.NotAfter,
		DER:            certDerA,
	}
	certStatusA := &core.CertificateStatus{
		Serial:                "001",
		LastExpirationNagSent: ctx.fc.Now().AddDate(0, 0, -3),
		Status:                core.OCSPStatusGood,
	}

	// Expires in 3d, already sent 4d nag at 4.5d
	rawCertB := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "happy B",
		},
		NotAfter:     ctx.fc.Now().AddDate(0, 0, 3),
		DNSNames:     []string{"example-b.com"},
		SerialNumber: big.NewInt(1337),
	}
	certDerB, _ := x509.CreateCertificate(rand.Reader, &rawCertB, &rawCertB, &testKey.PublicKey, &testKey)
	certB := &core.Certificate{
		RegistrationID: regA.ID,
		Serial:         "002",
		Expires:        rawCertB.NotAfter,
		DER:            certDerB,
	}
	certStatusB := &core.CertificateStatus{
		Serial:                "002",
		LastExpirationNagSent: ctx.fc.Now().Add(-36 * time.Hour),
		Status:                core.OCSPStatusGood,
	}

	// Expires in 7d and change, no nag sent at all yet
	rawCertC := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "happy C",
		},
		NotAfter:     ctx.fc.Now().Add((7*24 + 1) * time.Hour),
		DNSNames:     []string{"example-c.com"},
		SerialNumber: big.NewInt(1337),
	}
	certDerC, _ := x509.CreateCertificate(rand.Reader, &rawCertC, &rawCertC, &testKey.PublicKey, &testKey)
	certC := &core.Certificate{
		RegistrationID: regB.ID,
		Serial:         "003",
		Expires:        rawCertC.NotAfter,
		DER:            certDerC,
	}
	certStatusC := &core.CertificateStatus{
		Serial: "003",
		Status: core.OCSPStatusGood,
	}

	setupDBMap, err := sa.NewDbMap(vars.DBConnSAFullPerms)
	err = setupDBMap.Insert(certA)
	test.AssertNotError(t, err, "Couldn't add certA")
	err = setupDBMap.Insert(certB)
	test.AssertNotError(t, err, "Couldn't add certB")
	err = setupDBMap.Insert(certC)
	test.AssertNotError(t, err, "Couldn't add certC")
	err = setupDBMap.Insert(certStatusA)
	test.AssertNotError(t, err, "Couldn't add certStatusA")
	err = setupDBMap.Insert(certStatusB)
	test.AssertNotError(t, err, "Couldn't add certStatusB")
	err = setupDBMap.Insert(certStatusC)
	test.AssertNotError(t, err, "Couldn't add certStatusC")

	log.Clear()
	err = ctx.m.findExpiringCertificates()
	test.AssertNotError(t, err, "Failed to find expiring certs")
	// Should get 001 and 003
	test.AssertEquals(t, len(ctx.mc.Messages), 2)

	test.AssertEquals(t, mocks.MailerMessage{
		To:      emailARaw,
		Subject: "",
		Body:    fmt.Sprintf(`hi, cert for DNS names example-a.com is going to expire in 0 days (%s)`, rawCertA.NotAfter.UTC().Format(time.RFC822Z)),
	}, ctx.mc.Messages[0])
	test.AssertEquals(t, mocks.MailerMessage{
		To:      emailBRaw,
		Subject: "",
		Body:    fmt.Sprintf(`hi, cert for DNS names example-c.com is going to expire in 7 days (%s)`, rawCertC.NotAfter.UTC().Format(time.RFC822Z)),
	}, ctx.mc.Messages[1])

	// A consecutive run shouldn't find anything
	ctx.mc.Clear()
	log.Clear()
	err = ctx.m.findExpiringCertificates()
	test.AssertNotError(t, err, "Failed to find expiring certs")
	test.AssertEquals(t, len(ctx.mc.Messages), 0)
}

func TestCertIsRenewed(t *testing.T) {
	ctx := setup(t, []time.Duration{time.Hour * 24, time.Hour * 24 * 4, time.Hour * 24 * 7})

	reg := satest.CreateWorkingRegistration(t, ctx.ssa)

	testCerts := []*struct {
		Serial       int
		stringSerial string
		FQDNHash     []byte
		DNS          string
		NotBefore    time.Time
		NotAfter     time.Time
		// this field is the test assertion
		IsRenewed bool
	}{
		{
			Serial:    1001,
			FQDNHash:  []byte("hash of A"),
			DNS:       "a.example.com",
			NotBefore: ctx.fc.Now().Add((-1 * 24) * time.Hour),
			NotAfter:  ctx.fc.Now().Add((89 * 24) * time.Hour),
			IsRenewed: true,
		},
		{
			Serial:    1002,
			FQDNHash:  []byte("hash of A"),
			DNS:       "a.example.com",
			NotBefore: ctx.fc.Now().Add((0 * 24) * time.Hour),
			NotAfter:  ctx.fc.Now().Add((90 * 24) * time.Hour),
			IsRenewed: false,
		},
		{
			Serial:    1003,
			FQDNHash:  []byte("hash of B"),
			DNS:       "b.example.net",
			NotBefore: ctx.fc.Now().Add((0 * 24) * time.Hour),
			NotAfter:  ctx.fc.Now().Add((90 * 24) * time.Hour),
			IsRenewed: false,
		},
		{
			Serial:    1004,
			FQDNHash:  []byte("hash of C"),
			DNS:       "c.example.org",
			NotBefore: ctx.fc.Now().Add((-100 * 24) * time.Hour),
			NotAfter:  ctx.fc.Now().Add((-10 * 24) * time.Hour),
			IsRenewed: true,
		},
		{
			Serial:    1005,
			FQDNHash:  []byte("hash of C"),
			DNS:       "c.example.org",
			NotBefore: ctx.fc.Now().Add((-80 * 24) * time.Hour),
			NotAfter:  ctx.fc.Now().Add((10 * 24) * time.Hour),
			IsRenewed: true,
		},
		{
			Serial:    1006,
			FQDNHash:  []byte("hash of C"),
			DNS:       "c.example.org",
			NotBefore: ctx.fc.Now().Add((-75 * 24) * time.Hour),
			NotAfter:  ctx.fc.Now().Add((15 * 24) * time.Hour),
			IsRenewed: true,
		},
		{
			Serial:    1007,
			FQDNHash:  []byte("hash of C"),
			DNS:       "c.example.org",
			NotBefore: ctx.fc.Now().Add((-1 * 24) * time.Hour),
			NotAfter:  ctx.fc.Now().Add((89 * 24) * time.Hour),
			IsRenewed: false,
		},
	}

	setupDBMap, err := sa.NewDbMap(vars.DBConnSAFullPerms)
	if err != nil {
		t.Fatal(err)
	}

	for _, testData := range testCerts {
		testData.stringSerial = strconv.Itoa(testData.Serial)

		rawCert := x509.Certificate{
			Subject: pkix.Name{
				CommonName: testData.DNS,
			},
			NotBefore:    testData.NotBefore,
			NotAfter:     testData.NotAfter,
			DNSNames:     []string{testData.DNS},
			SerialNumber: big.NewInt(int64(testData.Serial)),
		}
		certDer, err := x509.CreateCertificate(rand.Reader, &rawCert, &rawCert, &testKey.PublicKey, &testKey)
		if err != nil {
			t.Fatal(err)
		}
		cert := &core.Certificate{
			RegistrationID: reg.ID,
			Serial:         testData.stringSerial,
			Issued:         testData.NotBefore,
			Expires:        testData.NotAfter,
			DER:            certDer,
		}
		certStatus := &core.CertificateStatus{
			Serial: testData.stringSerial,
			Status: core.OCSPStatusGood,
		}
		fqdnStatus := &core.FQDNSet{
			SetHash: testData.FQDNHash,
			Serial:  testData.stringSerial,
			Issued:  testData.NotBefore,
			Expires: testData.NotAfter,
		}

		err = setupDBMap.Insert(cert)
		test.AssertNotError(t, err, fmt.Sprintf("Couldn't add cert %s", testData.stringSerial))
		err = setupDBMap.Insert(certStatus)
		test.AssertNotError(t, err, fmt.Sprintf("Couldn't add certStatus %s", testData.stringSerial))
		err = setupDBMap.Insert(fqdnStatus)
		test.AssertNotError(t, err, fmt.Sprintf("Couldn't add fqdnStatus %s", testData.stringSerial))
	}

	for _, testData := range testCerts {
		renewed, err := ctx.m.certIsRenewed(testData.stringSerial)
		if err != nil {
			t.Errorf("error checking renewal state for %s: %v", testData.stringSerial, err)
			continue
		}
		if renewed != testData.IsRenewed {
			t.Errorf("for %s: got %v, expected %v", testData.stringSerial, renewed, testData.IsRenewed)
		}
	}
}

func TestLifetimeOfACert(t *testing.T) {
	ctx := setup(t, []time.Duration{time.Hour * 24, time.Hour * 24 * 4, time.Hour * 24 * 7})
	defer ctx.cleanUp()

	var keyA jose.JsonWebKey
	err := json.Unmarshal(jsonKeyA, &keyA)
	test.AssertNotError(t, err, "Failed to unmarshal public JWK")

	regA := core.Registration{
		ID: 1,
		Contact: []*core.AcmeURL{
			emailA,
		},
		Key:       keyA,
		InitialIP: net.ParseIP("1.2.2.1"),
	}
	regA, err = ctx.ssa.NewRegistration(regA)
	if err != nil {
		t.Fatalf("Couldn't store regA: %s", err)
	}
	rawCertA := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "happy A",
		},

		NotAfter:     ctx.fc.Now(),
		DNSNames:     []string{"example-a.com"},
		SerialNumber: big.NewInt(1337),
	}
	certDerA, _ := x509.CreateCertificate(rand.Reader, &rawCertA, &rawCertA, &testKey.PublicKey, &testKey)
	certA := &core.Certificate{
		RegistrationID: regA.ID,
		Serial:         "001",
		Expires:        rawCertA.NotAfter,
		DER:            certDerA,
	}

	certStatusA := &core.CertificateStatus{
		Serial: "001",
		Status: core.OCSPStatusGood,
	}

	setupDBMap, err := sa.NewDbMap(vars.DBConnSAFullPerms)
	err = setupDBMap.Insert(certA)
	test.AssertNotError(t, err, "unable to insert Certificate")
	err = setupDBMap.Insert(certStatusA)
	test.AssertNotError(t, err, "unable to insert CertificateStatus")

	type lifeTest struct {
		timeLeft time.Duration
		numMsgs  int
		context  string
	}
	tests := []lifeTest{
		{
			timeLeft: 9 * 24 * time.Hour, // 9 days before expiration

			numMsgs: 0,
			context: "Expected no emails sent because we are more than 7 days out.",
		},
		{
			(7*24 + 12) * time.Hour, // 7.5 days before
			1,
			"Sent 1 for 7 day notice.",
		},
		{
			7 * 24 * time.Hour,
			1,
			"The 7 day email was already sent.",
		},
		{
			(4*24 - 1) * time.Hour, // <4 days before, the mailer did not run yesterday
			2,
			"Sent 1 for the 7 day notice, and 1 for the 4 day notice.",
		},
		{
			36 * time.Hour, // within 1day + nagMargin
			3,
			"Sent 1 for the 7 day notice, 1 for the 4 day notice, and 1 for the 1 day notice.",
		},
		{
			12 * time.Hour,
			3,
			"The 1 day before email was already sent.",
		},
		{
			-2 * 24 * time.Hour, // 2 days after expiration
			3,
			"No expiration warning emails are sent after expiration",
		},
	}

	for _, tt := range tests {
		ctx.fc.Add(-tt.timeLeft)
		err = ctx.m.findExpiringCertificates()
		test.AssertNotError(t, err, "error calling findExpiringCertificates")
		if len(ctx.mc.Messages) != tt.numMsgs {
			t.Errorf(tt.context+" number of messages: expected %d, got %d", tt.numMsgs, len(ctx.mc.Messages))
		}
		ctx.fc.Add(tt.timeLeft)
	}
}

func TestDontFindRevokedCert(t *testing.T) {
	expiresIn := 24 * time.Hour
	ctx := setup(t, []time.Duration{expiresIn})

	var keyA jose.JsonWebKey
	err := json.Unmarshal(jsonKeyA, &keyA)
	test.AssertNotError(t, err, "Failed to unmarshal public JWK")

	emailA, _ := core.ParseAcmeURL("mailto:one@mail.com")

	regA := core.Registration{
		ID: 1,
		Contact: []*core.AcmeURL{
			emailA,
		},
		Key:       keyA,
		InitialIP: net.ParseIP("6.5.5.6"),
	}
	regA, err = ctx.ssa.NewRegistration(regA)
	if err != nil {
		t.Fatalf("Couldn't store regA: %s", err)
	}
	rawCertA := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "happy A",
		},

		NotAfter:     ctx.fc.Now().Add(expiresIn),
		DNSNames:     []string{"example-a.com"},
		SerialNumber: big.NewInt(1337),
	}
	certDerA, _ := x509.CreateCertificate(rand.Reader, &rawCertA, &rawCertA, &testKey.PublicKey, &testKey)
	certA := &core.Certificate{
		RegistrationID: regA.ID,
		Serial:         "001",
		Expires:        rawCertA.NotAfter,
		DER:            certDerA,
	}

	certStatusA := &core.CertificateStatus{
		Serial: "001",
		Status: core.OCSPStatusRevoked,
	}

	setupDBMap, err := sa.NewDbMap(vars.DBConnSAFullPerms)
	err = setupDBMap.Insert(certA)
	test.AssertNotError(t, err, "unable to insert Certificate")
	err = setupDBMap.Insert(certStatusA)
	test.AssertNotError(t, err, "unable to insert CertificateStatus")

	err = ctx.m.findExpiringCertificates()
	test.AssertNotError(t, err, "err from findExpiringCertificates")

	if len(ctx.mc.Messages) != 0 {
		t.Errorf("no emails should have been sent, but sent %d", len(ctx.mc.Messages))
	}
}

func TestDedupOnRegistration(t *testing.T) {
	expiresIn := 96 * time.Hour
	ctx := setup(t, []time.Duration{expiresIn})

	var keyA jose.JsonWebKey
	err := json.Unmarshal(jsonKeyA, &keyA)
	test.AssertNotError(t, err, "Failed to unmarshal public JWK")

	regA := core.Registration{
		ID: 1,
		Contact: []*core.AcmeURL{
			emailA,
		},
		Key:       keyA,
		InitialIP: net.ParseIP("6.5.5.6"),
	}
	regA, err = ctx.ssa.NewRegistration(regA)
	if err != nil {
		t.Fatalf("Couldn't store regA: %s", err)
	}
	rawCertA := newX509Cert("happy A",
		ctx.fc.Now().Add(72*time.Hour),
		[]string{"example-a.com", "shared-example.com"},
		1338,
	)

	certDerA, _ := x509.CreateCertificate(rand.Reader, rawCertA, rawCertA, &testKey.PublicKey, &testKey)
	certA := &core.Certificate{
		RegistrationID: regA.ID,
		Serial:         "001",
		Expires:        rawCertA.NotAfter,
		DER:            certDerA,
	}
	certStatusA := &core.CertificateStatus{
		Serial:                "001",
		LastExpirationNagSent: time.Unix(0, 0),
		Status:                core.OCSPStatusGood,
	}

	rawCertB := newX509Cert("happy B",
		ctx.fc.Now().Add(48*time.Hour),
		[]string{"example-b.com", "shared-example.com"},
		1337,
	)
	certDerB, _ := x509.CreateCertificate(rand.Reader, rawCertB, rawCertB, &testKey.PublicKey, &testKey)
	certB := &core.Certificate{
		RegistrationID: regA.ID,
		Serial:         "002",
		Expires:        rawCertB.NotAfter,
		DER:            certDerB,
	}
	certStatusB := &core.CertificateStatus{
		Serial:                "002",
		LastExpirationNagSent: time.Unix(0, 0),
		Status:                core.OCSPStatusGood,
	}

	setupDBMap, err := sa.NewDbMap(vars.DBConnSAFullPerms)
	err = setupDBMap.Insert(certA)
	test.AssertNotError(t, err, "Couldn't add certA")
	err = setupDBMap.Insert(certB)
	test.AssertNotError(t, err, "Couldn't add certB")
	err = setupDBMap.Insert(certStatusA)
	test.AssertNotError(t, err, "Couldn't add certStatusA")
	err = setupDBMap.Insert(certStatusB)
	test.AssertNotError(t, err, "Couldn't add certStatusB")

	err = ctx.m.findExpiringCertificates()
	test.AssertNotError(t, err, "error calling findExpiringCertificates")
	if len(ctx.mc.Messages) > 1 {
		t.Errorf("num of messages, want %d, got %d", 1, len(ctx.mc.Messages))
	}
	if len(ctx.mc.Messages) == 0 {
		t.Fatalf("no messages sent")
	}
	domains := "example-a.com\nexample-b.com\nshared-example.com"
	expected := mocks.MailerMessage{
		To:      emailARaw,
		Subject: "",
		Body: fmt.Sprintf(`hi, cert for DNS names %s is going to expire in 1 days (%s)`,
			domains,
			rawCertB.NotAfter.Format(time.RFC822Z)),
	}
	test.AssertEquals(t, expected, ctx.mc.Messages[0])
}

type testCtx struct {
	dbMap   *gorp.DbMap
	ssa     core.StorageAdder
	mc      *mocks.Mailer
	fc      clock.FakeClock
	m       *mailer
	cleanUp func()
}

func setup(t *testing.T, nagTimes []time.Duration) *testCtx {
	// We use the test_setup user (which has full permissions to everything)
	// because the SA we return is used for inserting data to set up the test.
	dbMap, err := sa.NewDbMap(vars.DBConnSAFullPerms)
	if err != nil {
		t.Fatalf("Couldn't connect the database: %s", err)
	}
	fc := newFakeClock(t)
	ssa, err := sa.NewSQLStorageAuthority(dbMap, fc, log)
	if err != nil {
		t.Fatalf("unable to create SQLStorageAuthority: %s", err)
	}
	cleanUp := test.ResetSATestDatabase(t)

	stats, _ := statsd.NewNoopClient(nil)
	mc := &mocks.Mailer{}

	offsetNags := make([]time.Duration, len(nagTimes))
	for i, t := range nagTimes {
		offsetNags[i] = t + defaultNagCheckInterval
	}

	m := &mailer{
		log:           blog.GetAuditLogger(),
		stats:         stats,
		mailer:        mc,
		emailTemplate: tmpl,
		dbMap:         dbMap,
		rs:            ssa,
		nagTimes:      offsetNags,
		limit:         100,
		clk:           fc,
	}
	return &testCtx{
		dbMap:   dbMap,
		ssa:     ssa,
		mc:      mc,
		fc:      fc,
		m:       m,
		cleanUp: cleanUp,
	}
}
