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
	ssa, err := sa.NewSQLStorageAuthority(dbMap, fc, log, metrics.NewNoopScope())
	if err != nil {
		t.Fatalf("unable to create SQLStorageAuthority: %s", err)
	}
	cleanUp := test.ResetSATestDatabase(t)
	defer cleanUp()
	stats := metrics.NewNoopScope()

	p := expiredAuthzPurger{stats, log, fc, dbMap, 1}

	err = p.purgeAuthzs(time.Time{}, true)
	test.AssertNotError(t, err, "purgeAuthzs failed")

	old, new := fc.Now().Add(-time.Hour), fc.Now().Add(time.Hour)

	reg := satest.CreateWorkingRegistration(t, ssa)
	_, err = ssa.NewPendingAuthorization(context.Background(), core.Authorization{
		RegistrationID: reg.ID,
		Expires:        &old,
		Challenges:     []core.Challenge{{ID: 1}},
	})
	test.AssertNotError(t, err, "NewPendingAuthorization failed")
	_, err = ssa.NewPendingAuthorization(context.Background(), core.Authorization{
		RegistrationID: reg.ID,
		Expires:        &old,
		Challenges:     []core.Challenge{{ID: 2}},
	})
	test.AssertNotError(t, err, "NewPendingAuthorization failed")
	_, err = ssa.NewPendingAuthorization(context.Background(), core.Authorization{
		RegistrationID: reg.ID,
		Expires:        &new,
		Challenges:     []core.Challenge{{ID: 3}},
	})
	test.AssertNotError(t, err, "NewPendingAuthorization failed")

	err = p.purgeAuthzs(fc.Now(), true)
	test.AssertNotError(t, err, "purgeAuthzs failed")
	count, err := dbMap.SelectInt("SELECT COUNT(1) FROM pendingAuthorizations")
	test.AssertNotError(t, err, "dbMap.SelectInt failed")
	test.AssertEquals(t, count, int64(1))
	count, err = dbMap.SelectInt("SELECT COUNT(1) FROM challenges")
	test.AssertNotError(t, err, "dbMap.SelectInt failed")
	test.AssertEquals(t, count, int64(1))

	err = p.purgeAuthzs(fc.Now().Add(time.Hour), true)
	test.AssertNotError(t, err, "purgeAuthzs failed")
	count, err = dbMap.SelectInt("SELECT COUNT(1) FROM pendingAuthorizations")
	test.AssertNotError(t, err, "dbMap.SelectInt failed")
	test.AssertEquals(t, count, int64(0))
	count, err = dbMap.SelectInt("SELECT COUNT(1) FROM challenges")
	test.AssertNotError(t, err, "dbMap.SelectInt failed")
	test.AssertEquals(t, count, int64(0))

}
