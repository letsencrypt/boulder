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
	"strings"
	"testing"
	"text/template"
	"time"

	"golang.org/x/net/context"

	"github.com/golang/mock/gomock"
	"github.com/jmhodges/clock"
	"gopkg.in/go-gorp/gorp.v2"
	"gopkg.in/square/go-jose.v1"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/metrics/mock_metrics"
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

func (f fakeRegStore) GetRegistration(ctx context.Context, id int64) (core.Registration, error) {
	r, ok := f.RegByID[id]
	if !ok {
		return r, berrors.NotFoundError("no registration found for %q", id)
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
	emailA   = "mailto:" + emailARaw
	emailB   = "mailto:" + emailBRaw
	jsonKeyA = []byte(`{
  "kty":"RSA",
  "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
  "e":"AQAB"
}`)
	jsonKeyB = []byte(`{
  "kty":"RSA",
  "n":"z8bp-jPtHt4lKBqepeKF28g_QAEOuEsCIou6sZ9ndsQsEjxEOQxQ0xNOQezsKa63eogw8YS3vzjUcPP5BJuVzfPfGd5NVUdT-vSSwxk3wvk_jtNqhrpcoG0elRPQfMVsQWmxCAXCVRz3xbcFI8GTe-syynG3l-g1IzYIIZVNI6jdljCZML1HOMTTW4f7uJJ8mM-08oQCeHbr5ejK7O2yMSSYxW03zY-Tj1iVEebROeMv6IEEJNFSS4yM-hLpNAqVuQxFGetwtwjDMC1Drs1dTWrPuUAAjKGrP151z1_dE74M5evpAhZUmpKv1hY-x85DC6N0hFPgowsanmTNNiV75w",
  "e":"AAEAAQ"
}`)
	jsonKeyC = []byte(`{
  "kty":"RSA",
  "n":"rFH5kUBZrlPj73epjJjyCxzVzZuV--JjKgapoqm9pOuOt20BUTdHqVfC2oDclqM7HFhkkX9OSJMTHgZ7WaVqZv9u1X2yjdx9oVmMLuspX7EytW_ZKDZSzL-sCOFCuQAuYKkLbsdcA3eHBK_lwc4zwdeHFMKIulNvLqckkqYB9s8GpgNXBDIQ8GjR5HuJke_WUNjYHSd8jY1LU9swKWsLQe2YoQUz_ekQvBvBCoaFEtrtRaSJKNLIVDObXFr2TLIiFiM0Em90kK01-eQ7ZiruZTKomll64bRFPoNo4_uwubddg3xTqur2vdF3NyhTrYdvAgTem4uC0PFjEQ1bK_djBQ",
  "e":"AQAB"
}`)
	log      = blog.UseMock()
	tmpl     = template.Must(template.New("expiry-email").Parse(testTmpl))
	subjTmpl = template.Must(template.New("expiry-email-subject").Parse("Testing: " + defaultExpirationSubject))
	ctx      = context.Background()
)

func TestSendNags(t *testing.T) {
	stats := metrics.NewNoopScope()
	mc := mocks.Mailer{}
	rs := newFakeRegStore()
	fc := newFakeClock(t)

	staticTmpl := template.Must(template.New("expiry-email-subject-static").Parse(testEmailSubject))

	m := mailer{
		stats:         stats,
		log:           log,
		mailer:        &mc,
		emailTemplate: tmpl,
		// Explicitly override the default subject to use testEmailSubject
		subjectTemplate: staticTmpl,
		rs:              rs,
		clk:             fc,
	}

	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "happy",
		},
		NotAfter: fc.Now().AddDate(0, 0, 2),
		DNSNames: []string{"example.com"},
	}

	err := m.sendNags([]string{emailA}, []*x509.Certificate{cert})
	test.AssertNotError(t, err, "Failed to send warning messages")
	test.AssertEquals(t, len(mc.Messages), 1)
	test.AssertEquals(t, mocks.MailerMessage{
		To:      emailARaw,
		Subject: testEmailSubject,
		Body:    fmt.Sprintf(`hi, cert for DNS names example.com is going to expire in 2 days (%s)`, cert.NotAfter.Format(time.RFC822Z)),
	}, mc.Messages[0])

	mc.Clear()
	err = m.sendNags([]string{emailA, emailB}, []*x509.Certificate{cert})
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
	err = m.sendNags([]string{}, []*x509.Certificate{cert})
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

var serial1 = big.NewInt(0x1336)
var serial1String = core.SerialToString(serial1)
var serial2 = big.NewInt(0x1337)
var serial2String = core.SerialToString(serial2)
var serial3 = big.NewInt(0x1338)
var serial3String = core.SerialToString(serial3)
var serial4 = big.NewInt(0x1339)
var serial4String = core.SerialToString(serial4)
var serial5 = big.NewInt(0x1340)
var serial5String = core.SerialToString(serial5)
var serial6 = big.NewInt(0x1341)
var serial7 = big.NewInt(0x1342)

var testKey = rsa.PrivateKey{
	PublicKey: rsa.PublicKey{N: n, E: e},
	D:         d,
	Primes:    []*big.Int{p, q},
}

func TestProcessCerts(t *testing.T) {
	testCtx := setup(t, []time.Duration{time.Hour * 24 * 7})

	certs := addExpiringCerts(t, testCtx)
	log.Clear()
	testCtx.m.processCerts(certs)
	// Test that the lastExpirationNagSent was updated for the certificate
	// corresponding to serial4, which is set up as "already renewed" by
	// addExpiringCerts.
	if len(log.GetAllMatching("DEBUG: SQL:  UPDATE certificateStatus .*2006-01-02 15:04:05.999999999.*\"000000000000000000000000000000001339\"")) != 1 {
		t.Errorf("Expected an update to certificateStatus, got these log lines:\n%s",
			strings.Join(log.GetAllMatching(".*"), "\n"))
	}
}

func TestFindExpiringCertificates(t *testing.T) {
	testCtx := setup(t, []time.Duration{time.Hour * 24, time.Hour * 24 * 4, time.Hour * 24 * 7})

	addExpiringCerts(t, testCtx)

	log.Clear()
	err := testCtx.m.findExpiringCertificates()
	test.AssertNotError(t, err, "Failed on no certificates")
	test.AssertEquals(t, len(log.GetAllMatching("Searching for certificates that expire between.*")), 3)

	log.Clear()
	err = testCtx.m.findExpiringCertificates()
	test.AssertNotError(t, err, "Failed to find expiring certs")
	// Should get 001 and 003
	test.AssertEquals(t, len(testCtx.mc.Messages), 2)

	test.AssertEquals(t, mocks.MailerMessage{
		To: emailARaw,
		// A certificate with only one domain should have only one domain listed in
		// the subject
		Subject: "Testing: Let's Encrypt certificate expiration notice for domain \"example-a.com\"",
		Body:    "hi, cert for DNS names example-a.com is going to expire in 0 days (03 Jan 06 14:04 +0000)",
	}, testCtx.mc.Messages[0])
	test.AssertEquals(t, mocks.MailerMessage{
		To: emailBRaw,
		// A certificate with two domains should have only one domain listed and an
		// additional count included
		Subject: "Testing: Let's Encrypt certificate expiration notice for domain \"another.example-c.com\" (and 1 more)",
		Body:    "hi, cert for DNS names another.example-c.com\nexample-c.com is going to expire in 7 days (09 Jan 06 16:04 +0000)",
	}, testCtx.mc.Messages[1])

	// Check that regC's only certificate being renewed does not cause a log
	test.AssertEquals(t, len(log.GetAllMatching("no certs given to send nags for")), 0)

	// A consecutive run shouldn't find anything
	testCtx.mc.Clear()
	log.Clear()
	err = testCtx.m.findExpiringCertificates()
	test.AssertNotError(t, err, "Failed to find expiring certs")
	test.AssertEquals(t, len(testCtx.mc.Messages), 0)
}

func addExpiringCerts(t *testing.T, ctx *testCtx) []core.Certificate {
	// Add some expiring certificates and registrations
	var keyA jose.JsonWebKey
	var keyB jose.JsonWebKey
	var keyC jose.JsonWebKey
	err := json.Unmarshal(jsonKeyA, &keyA)
	test.AssertNotError(t, err, "Failed to unmarshal public JWK")
	err = json.Unmarshal(jsonKeyB, &keyB)
	test.AssertNotError(t, err, "Failed to unmarshal public JWK")
	err = json.Unmarshal(jsonKeyC, &keyC)
	test.AssertNotError(t, err, "Failed to unmarshal public JWK")
	regA := core.Registration{
		ID: 1,
		Contact: &[]string{
			emailA,
		},
		Key:       &keyA,
		InitialIP: net.ParseIP("2.3.2.3"),
	}
	regB := core.Registration{
		ID: 2,
		Contact: &[]string{
			emailB,
		},
		Key:       &keyB,
		InitialIP: net.ParseIP("2.3.2.3"),
	}
	regC := core.Registration{
		ID: 3,
		Contact: &[]string{
			emailB,
		},
		Key:       &keyC,
		InitialIP: net.ParseIP("210.3.2.3"),
	}
	bg := context.Background()
	regA, err = ctx.ssa.NewRegistration(bg, regA)
	if err != nil {
		t.Fatalf("Couldn't store regA: %s", err)
	}
	regB, err = ctx.ssa.NewRegistration(bg, regB)
	if err != nil {
		t.Fatalf("Couldn't store regB: %s", err)
	}
	regC, err = ctx.ssa.NewRegistration(bg, regC)
	if err != nil {
		t.Fatalf("Couldn't store regC: %s", err)
	}

	// Expires in <1d, last nag was the 4d nag
	rawCertA := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "happy A",
		},
		NotAfter:     ctx.fc.Now().Add(23 * time.Hour),
		DNSNames:     []string{"example-a.com"},
		SerialNumber: serial1,
	}
	certDerA, _ := x509.CreateCertificate(rand.Reader, &rawCertA, &rawCertA, &testKey.PublicKey, &testKey)
	certA := &core.Certificate{
		RegistrationID: regA.ID,
		Serial:         serial1String,
		Expires:        rawCertA.NotAfter,
		DER:            certDerA,
	}
	certStatusA := &core.CertificateStatus{
		Serial:                serial1String,
		LastExpirationNagSent: ctx.fc.Now().AddDate(0, 0, -3),
		Status:                core.OCSPStatusGood,
		NotAfter:              rawCertA.NotAfter,
	}

	// Expires in 3d, already sent 4d nag at 4.5d
	rawCertB := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "happy B",
		},
		NotAfter:     ctx.fc.Now().AddDate(0, 0, 3),
		DNSNames:     []string{"example-b.com"},
		SerialNumber: serial2,
	}
	certDerB, _ := x509.CreateCertificate(rand.Reader, &rawCertB, &rawCertB, &testKey.PublicKey, &testKey)
	certB := &core.Certificate{
		RegistrationID: regA.ID,
		Serial:         serial2String,
		Expires:        rawCertB.NotAfter,
		DER:            certDerB,
	}
	certStatusB := &core.CertificateStatus{
		Serial:                serial2String,
		LastExpirationNagSent: ctx.fc.Now().Add(-36 * time.Hour),
		Status:                core.OCSPStatusGood,
		NotAfter:              rawCertB.NotAfter,
	}

	// Expires in 7d and change, no nag sent at all yet
	rawCertC := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "happy C",
		},
		NotAfter:     ctx.fc.Now().Add((7*24 + 1) * time.Hour),
		DNSNames:     []string{"example-c.com", "another.example-c.com"},
		SerialNumber: serial3,
	}
	certDerC, _ := x509.CreateCertificate(rand.Reader, &rawCertC, &rawCertC, &testKey.PublicKey, &testKey)
	certC := &core.Certificate{
		RegistrationID: regB.ID,
		Serial:         serial3String,
		Expires:        rawCertC.NotAfter,
		DER:            certDerC,
	}
	certStatusC := &core.CertificateStatus{
		Serial:   serial3String,
		Status:   core.OCSPStatusGood,
		NotAfter: rawCertC.NotAfter,
	}

	// Expires in 3d, renewed
	rawCertD := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "happy D",
		},
		NotAfter:     ctx.fc.Now().AddDate(0, 0, 3),
		DNSNames:     []string{"example-d.com"},
		SerialNumber: serial4,
	}
	certDerD, _ := x509.CreateCertificate(rand.Reader, &rawCertD, &rawCertD, &testKey.PublicKey, &testKey)
	certD := &core.Certificate{
		RegistrationID: regC.ID,
		Serial:         serial4String,
		Expires:        rawCertD.NotAfter,
		DER:            certDerD,
	}
	certStatusD := &core.CertificateStatus{
		Serial:   serial4String,
		Status:   core.OCSPStatusGood,
		NotAfter: rawCertD.NotAfter,
	}
	fqdnStatusD := &core.FQDNSet{
		SetHash: []byte("hash of D"),
		Serial:  serial4String,
		Issued:  ctx.fc.Now().AddDate(0, 0, -87),
		Expires: ctx.fc.Now().AddDate(0, 0, 3),
	}
	fqdnStatusDRenewed := &core.FQDNSet{
		SetHash: []byte("hash of D"),
		Serial:  serial5String,
		Issued:  ctx.fc.Now().AddDate(0, 0, -3),
		Expires: ctx.fc.Now().AddDate(0, 0, 87),
	}

	setupDBMap, err := sa.NewDbMap(vars.DBConnSAFullPerms, 0)
	err = setupDBMap.Insert(certA)
	test.AssertNotError(t, err, "Couldn't add certA")
	err = setupDBMap.Insert(certB)
	test.AssertNotError(t, err, "Couldn't add certB")
	err = setupDBMap.Insert(certC)
	test.AssertNotError(t, err, "Couldn't add certC")
	err = setupDBMap.Insert(certD)
	test.AssertNotError(t, err, "Couldn't add certD")
	err = setupDBMap.Insert(certStatusA)
	test.AssertNotError(t, err, "Couldn't add certStatusA")
	err = setupDBMap.Insert(certStatusB)
	test.AssertNotError(t, err, "Couldn't add certStatusB")
	err = setupDBMap.Insert(certStatusC)
	test.AssertNotError(t, err, "Couldn't add certStatusC")
	err = setupDBMap.Insert(certStatusD)
	test.AssertNotError(t, err, "Couldn't add certStatusD")
	err = setupDBMap.Insert(fqdnStatusD)
	test.AssertNotError(t, err, "Couldn't add fqdnStatusD")
	err = setupDBMap.Insert(fqdnStatusDRenewed)
	test.AssertNotError(t, err, "Couldn't add fqdnStatusDRenewed")
	return []core.Certificate{*certA, *certB, *certC, *certD}
}

func TestFindCertsAtCapacity(t *testing.T) {
	testCtx := setup(t, []time.Duration{time.Hour * 24})

	addExpiringCerts(t, testCtx)

	log.Clear()

	// Override the mailer `stats` with a mock
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	statter := mock_metrics.NewMockScope(ctrl)
	testCtx.m.stats = statter

	// Set the limit to 1 so we are "at capacity" with one result
	testCtx.m.limit = 1

	// The mock statter should have had the "48h0m0s" nag capacity stat incremented once.
	// Note: this is not the 24h0m0s nag as you would expect sending time.Hour
	// * 24 to setup() for the nag duration. This is because all of the nags are
	// offset by defaultNagCheckInterval, which is 24hrs.
	statter.EXPECT().Inc("Errors.Nag-48h0m0s.AtCapacity", int64(1))

	// findExpiringCertificates() ends up invoking sendNags which calls
	// TimingDuration so we need to EXPECT that with the mock
	statter.EXPECT().TimingDuration("SendLatency", time.Duration(0))
	// Similarly, findExpiringCertificates() sends its latency as well
	statter.EXPECT().TimingDuration("ProcessingCertificatesLatency", time.Duration(0))

	err := testCtx.m.findExpiringCertificates()
	test.AssertNotError(t, err, "Failed to find expiring certs")
	test.AssertEquals(t, len(testCtx.mc.Messages), 1)

	// A consecutive run shouldn't find anything - similarly we do not EXPECT()
	// anything on statter to be called, and if it is then we have a test failure
	testCtx.mc.Clear()
	log.Clear()
	err = testCtx.m.findExpiringCertificates()
	test.AssertNotError(t, err, "Failed to find expiring certs")
	test.AssertEquals(t, len(testCtx.mc.Messages), 0)
}

func TestCertIsRenewed(t *testing.T) {
	testCtx := setup(t, []time.Duration{time.Hour * 24, time.Hour * 24 * 4, time.Hour * 24 * 7})

	reg := satest.CreateWorkingRegistration(t, testCtx.ssa)

	testCerts := []*struct {
		Serial       *big.Int
		stringSerial string
		FQDNHash     []byte
		DNS          string
		NotBefore    time.Time
		NotAfter     time.Time
		// this field is the test assertion
		IsRenewed bool
	}{
		{
			Serial:    serial1,
			FQDNHash:  []byte("hash of A"),
			DNS:       "a.example.com",
			NotBefore: testCtx.fc.Now().Add((-1 * 24) * time.Hour),
			NotAfter:  testCtx.fc.Now().Add((89 * 24) * time.Hour),
			IsRenewed: true,
		},
		{
			Serial:    serial2,
			FQDNHash:  []byte("hash of A"),
			DNS:       "a.example.com",
			NotBefore: testCtx.fc.Now().Add((0 * 24) * time.Hour),
			NotAfter:  testCtx.fc.Now().Add((90 * 24) * time.Hour),
			IsRenewed: false,
		},
		{
			Serial:    serial3,
			FQDNHash:  []byte("hash of B"),
			DNS:       "b.example.net",
			NotBefore: testCtx.fc.Now().Add((0 * 24) * time.Hour),
			NotAfter:  testCtx.fc.Now().Add((90 * 24) * time.Hour),
			IsRenewed: false,
		},
		{
			Serial:    serial4,
			FQDNHash:  []byte("hash of C"),
			DNS:       "c.example.org",
			NotBefore: testCtx.fc.Now().Add((-100 * 24) * time.Hour),
			NotAfter:  testCtx.fc.Now().Add((-10 * 24) * time.Hour),
			IsRenewed: true,
		},
		{
			Serial:    serial5,
			FQDNHash:  []byte("hash of C"),
			DNS:       "c.example.org",
			NotBefore: testCtx.fc.Now().Add((-80 * 24) * time.Hour),
			NotAfter:  testCtx.fc.Now().Add((10 * 24) * time.Hour),
			IsRenewed: true,
		},
		{
			Serial:    serial6,
			FQDNHash:  []byte("hash of C"),
			DNS:       "c.example.org",
			NotBefore: testCtx.fc.Now().Add((-75 * 24) * time.Hour),
			NotAfter:  testCtx.fc.Now().Add((15 * 24) * time.Hour),
			IsRenewed: true,
		},
		{
			Serial:    serial7,
			FQDNHash:  []byte("hash of C"),
			DNS:       "c.example.org",
			NotBefore: testCtx.fc.Now().Add((-1 * 24) * time.Hour),
			NotAfter:  testCtx.fc.Now().Add((89 * 24) * time.Hour),
			IsRenewed: false,
		},
	}

	setupDBMap, err := sa.NewDbMap(vars.DBConnSAFullPerms, 0)
	if err != nil {
		t.Fatal(err)
	}

	for _, testData := range testCerts {
		testData.stringSerial = core.SerialToString(testData.Serial)

		rawCert := x509.Certificate{
			Subject: pkix.Name{
				CommonName: testData.DNS,
			},
			NotBefore:    testData.NotBefore,
			NotAfter:     testData.NotAfter,
			DNSNames:     []string{testData.DNS},
			SerialNumber: testData.Serial,
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
		renewed, err := testCtx.m.certIsRenewed(testData.stringSerial)
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
	testCtx := setup(t, []time.Duration{time.Hour * 24, time.Hour * 24 * 4, time.Hour * 24 * 7})
	defer testCtx.cleanUp()

	var keyA jose.JsonWebKey
	err := json.Unmarshal(jsonKeyA, &keyA)
	test.AssertNotError(t, err, "Failed to unmarshal public JWK")

	regA := core.Registration{
		ID: 1,
		Contact: &[]string{
			emailA,
		},
		Key:       &keyA,
		InitialIP: net.ParseIP("1.2.2.1"),
	}
	regA, err = testCtx.ssa.NewRegistration(ctx, regA)
	if err != nil {
		t.Fatalf("Couldn't store regA: %s", err)
	}
	rawCertA := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "happy A",
		},

		NotAfter:     testCtx.fc.Now(),
		DNSNames:     []string{"example-a.com"},
		SerialNumber: serial1,
	}
	certDerA, _ := x509.CreateCertificate(rand.Reader, &rawCertA, &rawCertA, &testKey.PublicKey, &testKey)
	certA := &core.Certificate{
		RegistrationID: regA.ID,
		Serial:         serial1String,
		Expires:        rawCertA.NotAfter,
		DER:            certDerA,
	}

	certStatusA := &core.CertificateStatus{
		Serial:   serial1String,
		Status:   core.OCSPStatusGood,
		NotAfter: rawCertA.NotAfter,
	}

	setupDBMap, err := sa.NewDbMap(vars.DBConnSAFullPerms, 0)
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
		testCtx.fc.Add(-tt.timeLeft)
		err = testCtx.m.findExpiringCertificates()
		test.AssertNotError(t, err, "error calling findExpiringCertificates")
		if len(testCtx.mc.Messages) != tt.numMsgs {
			t.Errorf(tt.context+" number of messages: expected %d, got %d", tt.numMsgs, len(testCtx.mc.Messages))
		}
		testCtx.fc.Add(tt.timeLeft)
	}
}

func TestDontFindRevokedCert(t *testing.T) {
	expiresIn := 24 * time.Hour
	testCtx := setup(t, []time.Duration{expiresIn})

	var keyA jose.JsonWebKey
	err := json.Unmarshal(jsonKeyA, &keyA)
	test.AssertNotError(t, err, "Failed to unmarshal public JWK")

	emailA := "mailto:one@mail.com"

	regA := core.Registration{
		ID: 1,
		Contact: &[]string{
			emailA,
		},
		Key:       &keyA,
		InitialIP: net.ParseIP("6.5.5.6"),
	}
	regA, err = testCtx.ssa.NewRegistration(ctx, regA)
	if err != nil {
		t.Fatalf("Couldn't store regA: %s", err)
	}
	rawCertA := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "happy A",
		},

		NotAfter:     testCtx.fc.Now().Add(expiresIn),
		DNSNames:     []string{"example-a.com"},
		SerialNumber: serial1,
	}
	certDerA, _ := x509.CreateCertificate(rand.Reader, &rawCertA, &rawCertA, &testKey.PublicKey, &testKey)
	certA := &core.Certificate{
		RegistrationID: regA.ID,
		Serial:         serial1String,
		Expires:        rawCertA.NotAfter,
		DER:            certDerA,
	}

	certStatusA := &core.CertificateStatus{
		Serial: serial1String,
		Status: core.OCSPStatusRevoked,
	}

	setupDBMap, err := sa.NewDbMap(vars.DBConnSAFullPerms, 0)
	err = setupDBMap.Insert(certA)
	test.AssertNotError(t, err, "unable to insert Certificate")
	err = setupDBMap.Insert(certStatusA)
	test.AssertNotError(t, err, "unable to insert CertificateStatus")

	err = testCtx.m.findExpiringCertificates()
	test.AssertNotError(t, err, "err from findExpiringCertificates")

	if len(testCtx.mc.Messages) != 0 {
		t.Errorf("no emails should have been sent, but sent %d", len(testCtx.mc.Messages))
	}
}

func TestDedupOnRegistration(t *testing.T) {
	expiresIn := 96 * time.Hour
	testCtx := setup(t, []time.Duration{expiresIn})

	var keyA jose.JsonWebKey
	err := json.Unmarshal(jsonKeyA, &keyA)
	test.AssertNotError(t, err, "Failed to unmarshal public JWK")

	regA := core.Registration{
		ID: 1,
		Contact: &[]string{
			emailA,
		},
		Key:       &keyA,
		InitialIP: net.ParseIP("6.5.5.6"),
	}
	regA, err = testCtx.ssa.NewRegistration(ctx, regA)
	if err != nil {
		t.Fatalf("Couldn't store regA: %s", err)
	}
	rawCertA := newX509Cert("happy A",
		testCtx.fc.Now().Add(72*time.Hour),
		[]string{"example-a.com", "shared-example.com"},
		serial1,
	)

	certDerA, _ := x509.CreateCertificate(rand.Reader, rawCertA, rawCertA, &testKey.PublicKey, &testKey)
	certA := &core.Certificate{
		RegistrationID: regA.ID,
		Serial:         serial1String,
		Expires:        rawCertA.NotAfter,
		DER:            certDerA,
	}
	certStatusA := &core.CertificateStatus{
		Serial:                serial1String,
		LastExpirationNagSent: time.Unix(0, 0),
		Status:                core.OCSPStatusGood,
		NotAfter:              rawCertA.NotAfter,
	}

	rawCertB := newX509Cert("happy B",
		testCtx.fc.Now().Add(48*time.Hour),
		[]string{"example-b.com", "shared-example.com"},
		serial2,
	)
	certDerB, _ := x509.CreateCertificate(rand.Reader, rawCertB, rawCertB, &testKey.PublicKey, &testKey)
	certB := &core.Certificate{
		RegistrationID: regA.ID,
		Serial:         serial2String,
		Expires:        rawCertB.NotAfter,
		DER:            certDerB,
	}
	certStatusB := &core.CertificateStatus{
		Serial:                serial2String,
		LastExpirationNagSent: time.Unix(0, 0),
		Status:                core.OCSPStatusGood,
		NotAfter:              rawCertB.NotAfter,
	}

	setupDBMap, err := sa.NewDbMap(vars.DBConnSAFullPerms, 0)
	err = setupDBMap.Insert(certA)
	test.AssertNotError(t, err, "Couldn't add certA")
	err = setupDBMap.Insert(certB)
	test.AssertNotError(t, err, "Couldn't add certB")
	err = setupDBMap.Insert(certStatusA)
	test.AssertNotError(t, err, "Couldn't add certStatusA")
	err = setupDBMap.Insert(certStatusB)
	test.AssertNotError(t, err, "Couldn't add certStatusB")

	err = testCtx.m.findExpiringCertificates()
	test.AssertNotError(t, err, "error calling findExpiringCertificates")
	if len(testCtx.mc.Messages) > 1 {
		t.Errorf("num of messages, want %d, got %d", 1, len(testCtx.mc.Messages))
	}
	if len(testCtx.mc.Messages) == 0 {
		t.Fatalf("no messages sent")
	}
	domains := "example-a.com\nexample-b.com\nshared-example.com"
	expected := mocks.MailerMessage{
		To: emailARaw,
		// A certificate with three domain names should have one in the subject and
		// a count of '2 more' at the end
		Subject: "Testing: Let's Encrypt certificate expiration notice for domain \"example-a.com\" (and 2 more)",
		Body: fmt.Sprintf(`hi, cert for DNS names %s is going to expire in 1 days (%s)`,
			domains,
			rawCertB.NotAfter.Format(time.RFC822Z)),
	}
	test.AssertEquals(t, expected, testCtx.mc.Messages[0])
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
	dbMap, err := sa.NewDbMap(vars.DBConnSAFullPerms, 0)
	if err != nil {
		t.Fatalf("Couldn't connect the database: %s", err)
	}
	fc := newFakeClock(t)
	ssa, err := sa.NewSQLStorageAuthority(dbMap, fc, log, metrics.NewNoopScope())
	if err != nil {
		t.Fatalf("unable to create SQLStorageAuthority: %s", err)
	}
	cleanUp := test.ResetSATestDatabase(t)

	stats := metrics.NewNoopScope()
	mc := &mocks.Mailer{}

	offsetNags := make([]time.Duration, len(nagTimes))
	for i, t := range nagTimes {
		offsetNags[i] = t + defaultNagCheckInterval
	}

	m := &mailer{
		log:             log,
		stats:           stats,
		mailer:          mc,
		emailTemplate:   tmpl,
		subjectTemplate: subjTmpl,
		dbMap:           dbMap,
		rs:              ssa,
		nagTimes:        offsetNags,
		limit:           100,
		clk:             fc,
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
