package main

import (
	"io/ioutil"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
)

func TestBackfill(t *testing.T) {
	stats, _ := statsd.NewNoopClient()

	// Create an SA
	dbMap, err := sa.NewDbMap(vars.DBConnSA)
	if err != nil {
		t.Fatalf("Failed to create dbMap: %s", err)
	}
	fc := clock.NewFake()
	fc.Add(1 * time.Hour)
	sa, err := sa.NewSQLStorageAuthority(dbMap, fc)
	if err != nil {
		t.Fatalf("Failed to create SA: %s", err)
	}
	defer test.ResetSATestDatabase(t)
	b := backfiller{sa, dbMap, stats, blog.GetAuditLogger(), fc}

	certDER, err := ioutil.ReadFile("test-cert.der")
	test.AssertNotError(t, err, "Couldn't read example cert DER")

	reg := satest.CreateWorkingRegistration(t, sa)

	err = dbMap.Insert(&core.Certificate{RegistrationID: reg.ID, DER: certDER, Serial: "serial"})
	test.AssertNotError(t, err, "Couldn't insert stub certificate")

	results, err := b.findCerts()
	test.AssertNotError(t, err, "Failed to find missing name sets")
	test.AssertEquals(t, len(results), 1)
	test.AssertEquals(t, results[0].Serial, "serial")

	err = b.processResults(results)
	test.AssertNotError(t, err, "Failed to add missing name sets")

	results, err = b.findCerts()
	test.AssertNotError(t, err, "Failed to find missing name sets")
	test.AssertEquals(t, len(results), 0)
}
