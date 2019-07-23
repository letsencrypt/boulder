package main

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/test"
	"github.com/prometheus/client_golang/prometheus"
)

func setup() (*blog.Mock, clock.Clock) {
	return blog.UseMock(), clock.NewFake()
}

type mockDB struct {
	t               *testing.T
	expectedQuery   string
	expectedArgMap  map[string]interface{}
	selectResult    []int64
	expectedExecArg int64
	execResult      sql.Result
	errResult       error
}

func (m mockDB) Exec(query string, args ...interface{}) (sql.Result, error) {
	test.AssertEquals(m.t, query, m.expectedQuery)

	if len(args) < 1 {
		m.t.Fatal("Exec() had no args")
	} else if idArg, ok := args[0].(int64); !ok {
		m.t.Fatalf("Select()'s args[0] was %T not int64", args[0])
	} else {
		test.AssertEquals(m.t, idArg, m.expectedExecArg)
	}

	return m.execResult, m.errResult
}

func (m mockDB) Select(result interface{}, query string, args ...interface{}) ([]interface{}, error) {
	test.AssertEquals(m.t, query, m.expectedQuery)

	if len(args) < 1 {
		m.t.Fatal("Select() had no args")
	} else if argMap, ok := args[0].(map[string]interface{}); !ok {
		m.t.Fatalf("Select()'s args[0] was %T not map[string]interface{}", args[0])
	} else {
		test.AssertDeepEquals(m.t, argMap, m.expectedArgMap)
	}

	if idResults, ok := result.(*[]int64); !ok {
		m.t.Fatalf("Select()'s result target pointer was %T not []int64", result)
	} else {
		for _, id := range m.selectResult {
			*idResults = append(*idResults, id)
		}
	}

	return nil, m.errResult
}

func TestGetWork(t *testing.T) {
	log, clk := setup()
	startID := int64(10)
	table := "certificates"
	purgeBefore := clk.Now().Add(-time.Hour)
	batchSize := int64(20)
	workQuery := `SELECT id FROM certificates WHERE id > :startID AND time <= :cutoff ORDER by id LIMIT :limit`
	mockIDs := []int64{
		1,
		2,
		3,
		10,
		90,
	}

	testDB := &mockDB{
		t:             t,
		expectedQuery: workQuery,
		expectedArgMap: map[string]interface{}{
			"startID": startID,
			"cutoff":  purgeBefore,
			"limit":   batchSize,
		},
	}

	workChan := make(chan int64)

	job := &batchedDBJob{
		db:          testDB,
		log:         log,
		table:       table,
		purgeBefore: purgeBefore,
		batchSize:   batchSize,
		workQuery:   workQuery,
	}

	// Mock Select() to return a non-nil error result
	testDB.errResult = errors.New("database is on vacation")
	_, err := job.getWork(workChan, startID)
	// We expect to get back an error
	test.AssertError(t, err, "no error returned from getWork with bad DB")

	// Mock Select() to return good results and a nil error
	testDB.errResult = nil
	testDB.selectResult = mockIDs

	// Start a go routine to read the work channel results
	go func() {
		// We should be able to read one item per mockID and it should match the expected ID
		for i := 0; i < len(mockIDs); i++ {
			got := <-workChan
			test.AssertEquals(t, got, mockIDs[i])
		}
	}()

	// We expect to get back no error and the correct lastID
	lastID, err := job.getWork(workChan, startID)
	test.AssertNotError(t, err, "unexpected error from getWork")
	test.AssertEquals(t, lastID, mockIDs[len(mockIDs)-1])

	// We expect the work gauge for this table has been updated
	workCount, err := test.GaugeValueWithLabels(workStat, prometheus.Labels{"table": table})
	test.AssertNotError(t, err, "unexpected error from GaugeValueWithLabels")
	test.AssertEquals(t, workCount, len(mockIDs))
}

func TestDeleteResource(t *testing.T) {
	log, _ := setup()
	table := "certificates"

	testID := int64(1)

	testDB := &mockDB{
		t:               t,
		expectedQuery:   "DELETE FROM certificates WHERE id = ?",
		expectedExecArg: testID,
	}

	job := &batchedDBJob{
		db:    testDB,
		log:   log,
		table: table,
	}

	// Mock Exec() to return a non-nil error result
	testDB.errResult = errors.New("database is on vacation")
	err := job.deleteResource(testID)
	// We expect an err result back
	test.AssertError(t, err, "no error returned from deleteResource with bad DB")
	// We expect no deletes to have been tracked in the deletedStat
	test.AssertEquals(t, test.CountCounterVec("table", "certificates", deletedStat), 0)

	// With the mock error removed we expect no error returned from deleteResource
	testDB.errResult = nil
	err = job.deleteResource(testID)
	test.AssertNotError(t, err, "unexpected error from deleteResource")
	// We expect a delete to have been tracked in the deletedStat
	test.AssertEquals(t, test.CountCounterVec("table", "certificates", deletedStat), 1)
}

type slowDB struct{}

func (db slowDB) Exec(_ string, _ ...interface{}) (sql.Result, error) {
	time.Sleep(time.Second)
	return nil, nil
}

func (db slowDB) Select(result interface{}, _ string, _ ...interface{}) ([]interface{}, error) {
	return nil, nil
}

func TestCleanResource(t *testing.T) {
	log, _ := setup()

	// Use a DB that always sleeps for 1 second for each Exec()'d delete.
	db := slowDB{}

	job := batchedDBJob{
		db:    db,
		log:   log,
		table: "example",
		// Start with a parallelism of 1
		parallelism: 1,
	}

	busyWork := func() <-chan int64 {
		work := make(chan int64, 2)
		work <- 1
		work <- 2
		close(work)
		return work
	}

	// Create some work without blocking the test go routine
	work := busyWork()

	// Run cleanResource and track the elapsed time
	start := time.Now()
	job.cleanResource(work)
	elapsed := time.Since(start)

	// With a parallelism of 1 and a sleep of 1 second per delete it should take
	// more than 1 second to delete both IDs in the work channel
	test.Assert(t,
		elapsed >= time.Second,
		fmt.Sprintf("expected parallelism of 1 to take longer than 1 second to delete two rows, took %s", elapsed))

	// Both rows should have been deleted
	expectedLog := `deleted a total of 2 rows from table "example"`
	matches := log.GetAllMatching(expectedLog)
	test.AssertEquals(t, len(matches), 1)

	// Increase the parallelism
	job.parallelism = 2
	// Recreate the work channel
	work = busyWork()
	// Clear the log
	log.Clear()

	// Run cleanResource again and track the elapsed time
	start = time.Now()
	job.cleanResource(work)
	elapsed = time.Since(start)

	// With a parallelism of 2 and a sleep of 1 second per delete it should take
	// less than 1 second to delete both IDs in the work channel
	test.Assert(t,
		elapsed <= time.Second+(time.Millisecond*500),
		fmt.Sprintf("expected parallelism of 2 to take less than 1 second to delete two rows, took %s", elapsed))

	// Both rows should have been deleted
	matches = log.GetAllMatching(expectedLog)
	test.AssertEquals(t, len(matches), 1)

	// Introduce a low max DPS to the job
	job.maxDPS = 1
	// Recreate the work channel
	work = busyWork()
	// Clear the log
	log.Clear()

	// Run cleanResource again and track the elapsed time
	start = time.Now()
	job.cleanResource(work)
	elapsed = time.Since(start)

	// With the maxDPS of 1 the parallelism of 2 should be limited such that it
	// will take more than 1 second to delete both IDs in the work channel once
	// again.
	test.Assert(t,
		elapsed >= time.Second,
		fmt.Sprintf("expected parallelism of 2 with max DPS 1 to take longer than 1 second to delete two rows, took %s", elapsed))

	// Both rows should have been deleted
	matches = log.GetAllMatching(expectedLog)
	test.AssertEquals(t, len(matches), 1)
}
