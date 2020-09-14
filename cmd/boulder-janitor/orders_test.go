package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/sa"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
)

func TestDeleteOrder(t *testing.T) {
	ctx := context.Background()
	log, fc := setup()

	// Create one dbMap for the SA with the SA user.
	dbMap, err := sa.NewDbMap(vars.DBConnSA, 0)
	test.AssertNotError(t, err, "error creating db map")
	// Create a SSA backed by the SA user dbMap
	ssa, err := sa.NewSQLStorageAuthority(dbMap, fc, log, metrics.NoopRegisterer, 1)
	test.AssertNotError(t, err, "error creating SA")

	// Don't forget to cleanup!
	defer func() {
		test.ResetSATestDatabase(t)
	}()

	// Create a test registration
	jwk := satest.GoodJWK()
	reg, err := ssa.NewRegistration(ctx, core.Registration{
		Key:       jwk,
		InitialIP: net.ParseIP("127.0.0.1"),
	})
	test.AssertNotError(t, err, "error creating test registration")

	// Create a test authorization
	expires := fc.Now().Add(time.Hour).UTC().UnixNano()
	authzA := &corepb.Authorization{
		Identifier:     "test.example.com",
		RegistrationID: reg.ID,
		Status:         string(core.StatusPending),
		Expires:        expires,
		Challenges: []*corepb.Challenge{
			{
				Status: string(core.StatusPending),
				Type:   string(core.ChallengeTypeDNS01),
				Token:  "YXNkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			},
		},
	}
	req := &sapb.AddPendingAuthorizationsRequest{Authz: []*corepb.Authorization{authzA}}
	ids, err := ssa.NewAuthorizations2(context.Background(), req)
	test.AssertNotError(t, err, "error adding test authz2")
	test.AssertEquals(t, len(ids.Ids), 1)

	// Create a test order referencing the test registration
	testOrder, err := ssa.NewOrder(ctx, &corepb.Order{
		RegistrationID:   reg.ID,
		Status:           string(core.StatusPending),
		Expires:          expires,
		Names:            []string{"test.example.com"},
		V2Authorizations: []int64{ids.Ids[0]},
	})
	test.AssertNotError(t, err, "error creating test order")

	// Create a cleanup config for the Orders job
	config := CleanupConfig{
		WorkSleep:   cmd.ConfigDuration{Duration: time.Second},
		BatchSize:   1,
		MaxDPS:      1,
		Parallelism: 1,
	}

	// Create a dbMap for the janitor user. We don't want to use the SA dbMap
	// because it doesn't have DELETE grants.
	// Create one dbMap for the SA with the SA user.
	janitorDbMap, err := sa.NewDbMap("janitor@tcp(boulder-mysql:3306)/boulder_sa_test", 0)
	test.AssertNotError(t, err, "error creating db map")

	// Create an Orders job and delete the mock order by its ID
	j := newOrdersJob(janitorDbMap, log, fc, config)
	err = j.deleteHandler(testOrder.Id)
	// It should not error
	test.AssertNotError(t, err, "error calling deleteHandler")

	// The order should be gone
	_, err = ssa.GetOrder(ctx, &sapb.OrderRequest{Id: testOrder.Id})
	test.AssertError(t, err, "found order after deleting it")
	test.AssertEquals(t, berrors.Is(err, berrors.NotFound), true)

	// The orderToAuthz2 rows should be gone
	var authzIDs []int64
	_, err = janitorDbMap.Select(
		&authzIDs,
		"SELECT authzID FROM orderToAuthz2 WHERE orderID = ?;",
		testOrder.Id)
	test.AssertNotError(t, err, "error finding orderToAuthz2 rows")
	test.AssertEquals(t, len(authzIDs), 0)

	// The requested names rows should be gone
	var requestedNamesIDs []int64
	_, err = janitorDbMap.Select(
		&requestedNamesIDs,
		"SELECT id FROM requestedNames WHERE orderID = ?;",
		testOrder.Id)
	test.AssertNotError(t, err, "error finding requestedNames rows")
	test.AssertEquals(t, len(requestedNamesIDs), 0)

	// The orderFqdnSets rows should be gone
	var orderFqdnSetIDs []int64
	_, err = janitorDbMap.Select(
		&requestedNamesIDs,
		"SELECT id FROM orderFqdnSets WHERE orderID = ?;",
		testOrder.Id)
	test.AssertNotError(t, err, "error finding orderFqdnSets rows")
	test.AssertEquals(t, len(orderFqdnSetIDs), 0)
}
