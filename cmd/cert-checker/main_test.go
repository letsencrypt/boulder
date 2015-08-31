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

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
)

var dbConnStr = "mysql+tcp://boulder@localhost:3306/boulder_sa_test"

func BenchmarkCheckCert(b *testing.B) {
	dbMap, err := sa.NewDbMap(dbConnStr)
	if err != nil {
		fmt.Println("Couldn't connect to database")
		return
	}

	checker := newChecker(dbMap)
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
		Status:  core.StatusValid,
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
	testKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	checker := newChecker(nil)
	fc := clock.NewFake()
	fc.Add(time.Hour * 24 * 90)
	checker.clock = fc

	issued := checker.clock.Now().Add(-time.Hour * 24 * 45)
	goodExpiry := issued.Add(checkPeriod)
	serial := big.NewInt(1337)
	// Problems
	//   Blacklsited common name
	//   Expiry period is too long
	//   Basic Constraints aren't set
	//   Wrong key usage (none)
	rawCert := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
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
	cert := core.Certificate{
		Status:  core.StatusValid,
		DER:     brokenCertDer,
		Issued:  issued,
		Expires: goodExpiry.AddDate(0, 0, 2), // Expiration doesn't match
	}

	problems := checker.checkCert(cert)
	test.AssertEquals(t, len(problems), 7)

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
	problems = checker.checkCert(cert)
	test.AssertEquals(t, len(problems), 0)
}

func TestGetAndProcessCerts(t *testing.T) {
	dbMap, err := sa.NewDbMap(dbConnStr)
	test.AssertNotError(t, err, "Couldn't connect to database")
	checker := newChecker(dbMap)
	sa, err := sa.NewSQLStorageAuthority(dbMap)
	test.AssertNotError(t, err, "Couldn't create SA to insert certificates")
	defer func() {
		dbMap.TruncateTables()
		test.AssertNotError(t, err, "Failed to truncate tables")
	}()

	testKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	// Problems
	//   Expiry period is too long
	rawCert := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "not-blacklisted.com",
		},
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	reg, err := sa.NewRegistration(core.Registration{
		Key: satest.GoodJWK(),
	})
	test.AssertNotError(t, err, "Couldn't create registration")
	for i := int64(0); i < 5; i++ {
		rawCert.SerialNumber = big.NewInt(i)
		certDER, err := x509.CreateCertificate(rand.Reader, &rawCert, &rawCert, &testKey.PublicKey, testKey)
		test.AssertNotError(t, err, "Couldn't create certificate")
		_, err = sa.AddCertificate(certDER, reg.ID)
		test.AssertNotError(t, err, "Couldn't add certificate")
	}

	err = checker.getCerts()
	test.AssertNotError(t, err, "Failed to retrieve certificates")
	test.AssertEquals(t, len(checker.certs), 5)
	wg := new(sync.WaitGroup)
	wg.Add(1)
	checker.processCerts(wg)
	test.AssertEquals(t, checker.issuedReport.BadCerts, int64(5))
	test.AssertEquals(t, len(checker.issuedReport.Entries), 5)
}
