package main

import (
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"golang.org/x/net/context"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
)

func TestPurgeAuthzs(t *testing.T) {
	dbMap, err := sa.NewDbMap(vars.DBConnSAFullPerms, 0)
	if err != nil {
		t.Fatalf("Couldn't connect the database: %s", err)
	}
	log := blog.UseMock()
	fc := clock.NewFake()
	fc.Add(time.Hour)
	ssa, err := sa.NewSQLStorageAuthority(dbMap, fc, log)
	if err != nil {
		t.Fatalf("unable to create SQLStorageAuthority: %s", err)
	}
	cleanUp := test.ResetSATestDatabase(t)
	defer cleanUp()
	stats := metrics.NewNoopScope()

	p := expiredAuthzPurger{stats, log, fc, dbMap, 1}

	rows, err := p.purgeAuthzs(time.Time{}, true, "authz")
	test.AssertNotError(t, err, "purgeAuthzs failed")
	test.AssertEquals(t, rows, int64(0))

	old, new := fc.Now().Add(-time.Hour), fc.Now().Add(time.Hour)

	reg := satest.CreateWorkingRegistration(t, ssa)
	_, err = ssa.NewPendingAuthorization(context.Background(), core.Authorization{RegistrationID: reg.ID, Expires: &old})
	test.AssertNotError(t, err, "NewPendingAuthorization failed")
	_, err = ssa.NewPendingAuthorization(context.Background(), core.Authorization{RegistrationID: reg.ID, Expires: &old})
	test.AssertNotError(t, err, "NewPendingAuthorization failed")
	_, err = ssa.NewPendingAuthorization(context.Background(), core.Authorization{RegistrationID: reg.ID, Expires: &new})
	test.AssertNotError(t, err, "NewPendingAuthorization failed")

	rows, err = p.purgeAuthzs(fc.Now(), true, "authz")
	test.AssertNotError(t, err, "purgeAuthzs failed")
	test.AssertEquals(t, rows, int64(2))
	rows, err = p.purgeAuthzs(fc.Now().Add(time.Hour), true, "authz")
	test.AssertNotError(t, err, "purgeAuthzs failed")
	test.AssertEquals(t, rows, int64(1))
}
