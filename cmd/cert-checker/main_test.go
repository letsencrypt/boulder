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
	"testing"
	"time"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/sa"
)

var dbConnStr = "mysql+tcp://boulder@localhost:3306/boulder_test"

func BenchmarkCheckCert(b *testing.B) {
	dbMap, err := sa.NewDbMap(dbConnStr)
	if err != nil {
		fmt.Println("Couldn't connect to database")
		return
	}

	checker := newChecker(dbMap)
	testKey, _ := rsa.GenerateKey(rand.Reader, 512)
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
