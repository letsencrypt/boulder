package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
)

func TestBackfill(t *testing.T) {
	if !strings.HasSuffix(os.Getenv("BOULDER_CONFIG_DIR"), "config-next") {
		return
	}

	dbMap, err := sa.NewDbMap(vars.DBConnSA, 0)
	test.AssertNotError(t, err, "failed to create db map")
	defer test.ResetSATestDatabase(t)
	logger := log.NewMock()

	fc := clock.NewFake()
	fc.Set(time.Date(2015, 3, 4, 5, 0, 0, 0, time.UTC))

	ssa, err := sa.NewSQLStorageAuthority(dbMap, fc, logger, metrics.NoopRegisterer, 1)
	test.AssertNotError(t, err, "failed to create sa")

	reg := satest.CreateWorkingRegistration(t, ssa)

	issued := fc.Now()
	expires := fc.Now().Add(time.Hour * 24)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(123),
		DNSNames:     []string{"example.com"},
		NotBefore:    issued,
		NotAfter:     expires,
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "failed to generate test key")
	testA, err := x509.CreateCertificate(rand.Reader, template, template, k.Public(), k)
	test.AssertNotError(t, err, "failed to generate test certificate")

	_, err = ssa.AddCertificate(context.Background(), testA, reg.ID, nil, &issued)
	test.AssertNotError(t, err, "failed to store certificate")

	work, err := getWork(logger, dbMap, 1000, 0)
	test.AssertNotError(t, err, "getWork failed")
	test.AssertEquals(t, len(work), 1)

	err = doWork(logger, dbMap, work)
	test.AssertNotError(t, err, "doWork failed")
	// Duplicate entries shouldn't error out
	err = doWork(logger, dbMap, work)
	test.AssertNotError(t, err, "doWork failed")

	work, err = getWork(logger, dbMap, 1000, 1)
	test.AssertNotError(t, err, "failed to retrieve work")
	test.AssertEquals(t, len(work), 0)

	template.SerialNumber = big.NewInt(321)
	testB, err := x509.CreateCertificate(rand.Reader, template, template, k.Public(), k)
	test.AssertNotError(t, err, "failed to generate test certificate")
	_, err = ssa.AddCertificate(context.Background(), testB, reg.ID, nil, &issued)
	test.AssertNotError(t, err, "failed to store certificate")
	template.SerialNumber = big.NewInt(213)
	testC, err := x509.CreateCertificate(rand.Reader, template, template, k.Public(), k)
	test.AssertNotError(t, err, "failed to generate test certificate")
	_, err = ssa.AddCertificate(context.Background(), testC, reg.ID, nil, &issued)
	test.AssertNotError(t, err, "failed to store certificate")

	backfill(logger, dbMap, 1, 0)

	var keyHashes []struct {
		ID           int64
		KeyHash      []byte
		CertNotAfter time.Time
		CertSerial   string
	}
	_, err = dbMap.Select(&keyHashes, "SELECT * FROM keyHashToSerial")
	test.AssertNotError(t, err, "failed to retrieve rows from keyHashToSerial")
	test.AssertEquals(t, len(keyHashes), 3)
	spki, err := x509.MarshalPKIXPublicKey(k.Public())
	test.AssertNotError(t, err, "failed to marshal spki")
	spkiHash := sha256.Sum256(spki)
	test.AssertEquals(t, keyHashes[0].CertSerial, "00000000000000000000000000000000007b")
	test.AssertEquals(t, keyHashes[1].CertSerial, "000000000000000000000000000000000141")
	test.AssertEquals(t, keyHashes[2].CertSerial, "0000000000000000000000000000000000d5")
	test.AssertEquals(t, keyHashes[0].CertNotAfter, expires)
	test.AssertEquals(t, keyHashes[1].CertNotAfter, expires)
	test.AssertEquals(t, keyHashes[2].CertNotAfter, expires)
	test.Assert(t, bytes.Equal(keyHashes[0].KeyHash, spkiHash[:]), "SPKI hash mismatch")
	test.Assert(t, bytes.Equal(keyHashes[1].KeyHash, spkiHash[:]), "SPKI hash mismatch")
	test.Assert(t, bytes.Equal(keyHashes[2].KeyHash, spkiHash[:]), "SPKI hash mismatch")
}
