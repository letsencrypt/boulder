package main

import (
	"io/ioutil"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
)

func setup(t *testing.T, addFQDNSets bool) (backfiller, func()) {
	stats, _ := statsd.NewNoopClient()

	// Create an SA
	dbMap, err := sa.NewDbMap(vars.DBConnSA)
	if err != nil {
		t.Fatalf("Failed to create dbMap: %s", err)
	}
	fc := clock.NewFake()
	fc.Add(1 * time.Hour)
	sa, err := sa.NewSQLStorageAuthority(dbMap, fc, addFQDNSets)
	if err != nil {
		t.Fatalf("Failed to create SA: %s", err)
	}
	cleanup := test.ResetSATestDatabase(t)

	certDER, err := ioutil.ReadFile("test-cert.der")
	test.AssertNotError(t, err, "Couldn't read example cert DER")
	reg := satest.CreateWorkingRegistration(t, sa)
	_, err = sa.AddCertificate(certDER, reg.ID)
	test.AssertNotError(t, err, "Couldn't add certificate")

	return backfiller{sa, dbMap, stats, blog.GetAuditLogger(), fc}, cleanup
}

func TestFindAndAddCerts(t *testing.T) {
	b, cleanup := setup(t, false)
	defer cleanup()

	results, err := b.findCerts()
	test.AssertNotError(t, err, "Failed to find missing name sets")
	test.AssertEquals(t, len(results), 1)

	err = b.processResults(results)
	test.AssertNotError(t, err, "Failed to add missing name sets")

	results, err = b.findCerts()
	test.AssertNotError(t, err, "Failed to find missing name sets")
	test.AssertEquals(t, len(results), 0)
}

func TestDontAdd(t *testing.T) {
	b, cleanup := setup(t, true)
	defer cleanup()

	results, err := b.findCerts()
	test.AssertNotError(t, err, "Failed to find missing name sets")
	test.AssertEquals(t, len(results), 0)
}
