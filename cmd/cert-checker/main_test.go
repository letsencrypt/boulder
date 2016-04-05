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
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/mocks"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
)

func BenchmarkCheckCert(b *testing.B) {
	saDbMap, err := sa.NewDbMap(vars.DBConnSA)
	if err != nil {
		fmt.Println("Couldn't connect to database")
		return
	}
	paDbMap, err := sa.NewDbMap(vars.DBConnPolicy)
	if err != nil {
		fmt.Println("Couldn't connect to database")
		return
	}
	defer func() {
		test.ResetSATestDatabase(b)()
		test.ResetPolicyTestDatabase(b)()
	}()

	checker := newChecker(saDbMap, paDbMap, clock.Default(), false, nil, expectedValidityPeriod)
	testKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	expiry := time.Now().AddDate(0, 0, 1)
	serial := big.NewInt(1337)
	rawCert := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		NotAfter:     expiry,
		DNSNames:     []string{"example-a.com"},
		SerialNumber: serial,
	}
	certDer, _ := x509.CreateCertificate(rand.Reader, &rawCert, &rawCert, &testKey.PublicKey, testKey)
	cert := core.Certificate{
		Serial:  core.SerialToString(serial),
		Digest:  core.Fingerprint256(certDer),
		DER:     certDer,
		Issued:  time.Now(),
		Expires: expiry,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checker.checkCert(cert)
	}
}

func TestCheckCert(t *testing.T) {
	saDbMap, err := sa.NewDbMap(vars.DBConnSA)
	test.AssertNotError(t, err, "Couldn't connect to database")
	saCleanup := test.ResetSATestDatabase(t)
	paDbMap, err := sa.NewDbMap(vars.DBConnPolicy)
	test.AssertNotError(t, err, "Couldn't connect to policy database")
	paCleanup := test.ResetPolicyTestDatabase(t)
	defer func() {
		saCleanup()
		paCleanup()
	}()

	testKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	fc := clock.NewFake()
	fc.Add(time.Hour * 24 * 90)

	checker := newChecker(saDbMap, paDbMap, fc, false, nil, expectedValidityPeriod)

	issued := checker.clock.Now().Add(-time.Hour * 24 * 45)
	goodExpiry := issued.Add(expectedValidityPeriod)
	serial := big.NewInt(1337)
	// Problems
	//   Expiry period is too long
	//   Basic Constraints aren't set
	//   Wrong key usage (none)
	rawCert := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeexample.com",
		},
		NotBefore:             issued,
		NotAfter:              goodExpiry.AddDate(0, 0, 1), // Period too long
		DNSNames:              []string{"example-a.com"},
		SerialNumber:          serial,
		BasicConstraintsValid: false,
	}
	brokenCertDer, err := x509.CreateCertificate(rand.Reader, &rawCert, &rawCert, &testKey.PublicKey, testKey)
	test.AssertNotError(t, err, "Couldn't create certificate")
	// Problems
	//   Digest doesn't match
	//   Serial doesn't match
	//   Expiry doesn't match
	//   Issued doesn't match
	cert := core.Certificate{
		Serial:  "8485f2687eba29ad455ae4e31c8679206fec",
		DER:     brokenCertDer,
		Issued:  issued.Add(12 * time.Hour),
		Expires: goodExpiry.AddDate(0, 0, 2), // Expiration doesn't match
	}

	problems := checker.checkCert(cert)

	problemsMap := map[string]int{
		"Stored digest doesn't match certificate digest":                            1,
		"Stored serial doesn't match certificate serial":                            1,
		"Stored expiration doesn't match certificate NotAfter":                      1,
		"Certificate doesn't have basic constraints set":                            1,
		"Certificate has a validity period longer than 2160h0m0s":                   1,
		"Stored issuance date is outside of 6 hour window of certificate NotBefore": 1,
		"Certificate has incorrect key usage extensions":                            1,
		"Certificate has common name >64 characters long (65)":                      1,
	}
	test.AssertEquals(t, len(problems), 8)
	for _, p := range problems {
		_, ok := problemsMap[p]
		if !ok {
			t.Errorf("Expected problem '%s' but didn't find it.", p)
		}
		delete(problemsMap, p)
	}
	for k := range problemsMap {
		t.Errorf("Found unexpected problem '%s'.", k)
	}

	// Same settings as above, but the stored serial number in the DB is invalid.
	cert.Serial = "not valid"
	problems = checker.checkCert(cert)
	foundInvalidSerialProblem := false
	for _, p := range problems {
		if p == "Stored serial is invalid" {
			foundInvalidSerialProblem = true
		}
	}
	test.Assert(t, foundInvalidSerialProblem, "Invalid certificate serial number in DB did not trigger problem.")

	// Fix the problems
	rawCert.Subject.CommonName = "example-a.com"
	rawCert.NotAfter = goodExpiry
	rawCert.BasicConstraintsValid = true
	rawCert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	goodCertDer, err := x509.CreateCertificate(rand.Reader, &rawCert, &rawCert, &testKey.PublicKey, testKey)
	test.AssertNotError(t, err, "Couldn't create certificate")
	parsed, err := x509.ParseCertificate(goodCertDer)
	test.AssertNotError(t, err, "Couldn't parse created certificate")
	cert.Serial = core.SerialToString(serial)
	cert.Digest = core.Fingerprint256(goodCertDer)
	cert.DER = goodCertDer
	cert.Expires = parsed.NotAfter
	cert.Issued = parsed.NotBefore
	problems = checker.checkCert(cert)
	test.AssertEquals(t, len(problems), 0)
}

func TestGetAndProcessCerts(t *testing.T) {
	saDbMap, err := sa.NewDbMap(vars.DBConnSA)
	test.AssertNotError(t, err, "Couldn't connect to database")
	paDbMap, err := sa.NewDbMap(vars.DBConnPolicy)
	test.AssertNotError(t, err, "Couldn't connect to policy database")
	fc := clock.NewFake()

	checker := newChecker(saDbMap, paDbMap, fc, false, nil, expectedValidityPeriod)
	sa, err := sa.NewSQLStorageAuthority(saDbMap, fc, mocks.UseMockLog())
	test.AssertNotError(t, err, "Couldn't create SA to insert certificates")
	saCleanUp := test.ResetSATestDatabase(t)
	paCleanUp := test.ResetPolicyTestDatabase(t)
	defer func() {
		saCleanUp()
		paCleanUp()
	}()

	testKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	// Problems
	//   Expiry period is too long
	rawCert := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "not-blacklisted.com",
		},
		BasicConstraintsValid: true,
		DNSNames:              []string{"not-blacklisted.com"},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	reg := satest.CreateWorkingRegistration(t, sa)
	test.AssertNotError(t, err, "Couldn't create registration")
	for i := int64(0); i < 5; i++ {
		rawCert.SerialNumber = big.NewInt(i)
		certDER, err := x509.CreateCertificate(rand.Reader, &rawCert, &rawCert, &testKey.PublicKey, testKey)
		test.AssertNotError(t, err, "Couldn't create certificate")
		_, err = sa.AddCertificate(certDER, reg.ID)
		test.AssertNotError(t, err, "Couldn't add certificate")
	}

	err = checker.getCerts(false)
	test.AssertNotError(t, err, "Failed to retrieve certificates")
	test.AssertEquals(t, len(checker.certs), 5)
	wg := new(sync.WaitGroup)
	wg.Add(1)
	checker.processCerts(wg, false)
	test.AssertEquals(t, checker.issuedReport.BadCerts, int64(5))
	test.AssertEquals(t, len(checker.issuedReport.Entries), 5)
}

func TestSaveReport(t *testing.T) {
	r := report{
		begin:     time.Time{},
		end:       time.Time{},
		GoodCerts: 2,
		BadCerts:  1,
		Entries: map[string]reportEntry{
			"020000000000004b475da49b91da5c17": {
				Valid: true,
			},
			"020000000000004d1613e581432cba7e": {
				Valid: true,
			},
			"020000000000004e402bc21035c6634a": {
				Valid:    false,
				Problems: []string{"None really..."},
			},
		},
	}

	err := r.dump()
	test.AssertNotError(t, err, "Failed to dump results")
}
