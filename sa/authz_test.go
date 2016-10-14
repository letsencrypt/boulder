package sa

import (
	"fmt"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
	"gopkg.in/gorp.v1"
)

func setup(t *testing.T) (*gorp.DbMap, *SQLStorageAuthority, clock.FakeClock, func()) {
	dbMap, err := NewDbMap(vars.DBConnSA, 0)
	if err != nil {
		t.Fatalf("Failed to create dbMap: %s", err)
	}

	fc := clock.NewFake()
	fc.Set(time.Date(2016, 10, 6, 0, 0, 0, 0, time.UTC))

	sa, err := NewSQLStorageAuthority(dbMap, fc, log)
	if err != nil {
		t.Fatalf("Failed to create SA: %s", err)
	}

	cleanUp := test.ResetSATestDatabase(t)
	return dbMap, sa, fc, cleanUp
}

func TestStatusIsPending(t *testing.T) {
	testCases := []struct {
		status  core.AcmeStatus
		pending bool
	}{
		{status: core.StatusUnknown, pending: true},
		{status: core.StatusPending, pending: true},
		{status: core.StatusProcessing, pending: true},
		{status: core.StatusValid, pending: false},
		{status: core.StatusInvalid, pending: false},
		{status: core.StatusRevoked, pending: false},
		{status: core.StatusDeactivated, pending: false},
	}

	for _, c := range testCases {
		result := statusIsPending(c.status)
		if result != c.pending {
			t.Errorf("statusIsPending error. statusIsPending(%#v) = %s. Expected %s",
				c.status, result, c.pending)
		}
	}
}

func TestAuthzExists(t *testing.T) {
	dbMap, ssa, _, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, ssa)

	tx, err := dbMap.Begin()
	test.AssertNotError(t, err, "Couldn't create new dbMap tx")

	// Pick a random ID
	randomID := core.NewToken()

	// A random ID shouldn't exist if we haven't created it.
	exists := authzIdExists(tx, randomID)
	test.AssertEquals(t, exists, false)

	authz := core.Authorization{
		ID:             randomID,
		RegistrationID: reg.ID,
		Status:         core.StatusPending,
	}

	// Adding it to the `pendingAuthorizations` table by using
	// a `pendingauthzModel{}` should be sufficient for `authzIdExists` to return
	// true.
	oldStylePendingAuthz := pendingauthzModel{Authorization: authz}
	err = tx.Insert(&oldStylePendingAuthz)
	if err != nil {
		err = Rollback(tx, err)
		t.Fatalf("Failed to insert pendingAuthorizations table test authz: %#v\n", err)
	}
	exists = authzIdExists(tx, randomID)
	test.AssertEquals(t, exists, true)

	// Pick a new random ID
	newID := core.NewToken()
	for newID == randomID {
		newID = core.NewToken()
	}

	// Adding a pending authz to the `authz` table by using a `authzModel{}`
	// should be sufficient for `authzIdExists` to return true.
	authz.ID = newID
	newStylePendingAuthz := authzModel{Authorization: authz}
	err = tx.Insert(&newStylePendingAuthz)
	if err != nil {
		err = Rollback(tx, err)
		t.Fatalf("Failed to insert authz table test authz: %#v\n", err)
	}
	exists = authzIdExists(tx, newID)
	test.AssertEquals(t, exists, true)
	_ = tx.Commit()
}

func TestGetAuthz(t *testing.T) {
	dbMap, ssa, _, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, ssa)

	tx, err := dbMap.Begin()
	test.AssertNotError(t, err, "Couldn't create new dbMap tx")

	firstID := core.NewToken()

	authz := core.Authorization{
		ID:             firstID,
		RegistrationID: reg.ID,
		Status:         core.StatusPending,
	}

	// Add one authz to the "pendingAuthorizations" table
	oldStylePendingAuthz := pendingauthzModel{Authorization: authz}
	err = tx.Insert(&oldStylePendingAuthz)
	if err != nil {
		err = Rollback(tx, err)
		t.Fatalf("Failed to insert pendingAuthorizations table test authz: %#v\n", err)
	}

	secondID := core.NewToken()
	for secondID == firstID {
		secondID = core.NewToken()
	}

	// Add a second authz to the "authz" table.
	authz.ID = secondID
	newStylePendingAuthz := authzModel{Authorization: authz}
	err = tx.Insert(&newStylePendingAuthz)
	if err != nil {
		err = Rollback(tx, err)
		t.Fatalf("Failed to insert authz table test authz: %#v\n", err)
	}

	// Try to retrieve the first authz by ID
	result, table, err := getAuthz(tx, firstID)
	test.AssertNotError(t, err, fmt.Sprintf("unexpected error calling getAuthz(%s)", firstID))
	// Its attributes should match
	test.AssertEquals(t, result.ID, firstID)
	test.AssertEquals(t, result.Status, authz.Status)
	test.AssertEquals(t, result.RegistrationID, authz.RegistrationID)
	// And it should have been retrieved from the "pendingAuthorizations" table
	test.AssertEquals(t, table, "pendingAuthorizations")

	// Try to retrieve the second authz by ID
	result, table, err = getAuthz(tx, secondID)
	test.AssertNotError(t, err, fmt.Sprintf("unexpected error calling getAuthz(%s)", secondID))
	// Its attributes should match
	test.AssertEquals(t, result.ID, secondID)
	test.AssertEquals(t, result.Status, authz.Status)
	test.AssertEquals(t, result.RegistrationID, authz.RegistrationID)
	// And it should have been retrieved from the "pendingAuthorizations" table
	test.AssertEquals(t, table, "authz")

	// Try to retrieve an ID that doesn't exist
	result, table, err = getAuthz(tx, "this doesn't exist")
	// It should be an error!
	test.AssertError(t, err, "No error was returned by getAuthz() a non-existing authz ID")

	_ = tx.Commit()
}
