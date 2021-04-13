package janitor

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/db"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/test"
	"github.com/prometheus/client_golang/prometheus"
)

func setup() (*blog.Mock, clock.FakeClock) {
	return blog.UseMock(), clock.NewFake()
}

type mockDB struct {
	t               *testing.T
	expectedQuery   string
	expectedArgMap  map[string]interface{}
	selectResult    []workUnit
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

	if idResults, ok := result.(*[]workUnit); !ok {
		m.t.Fatalf("Select()'s result target pointer was %T not []int64", result)
	} else {
		*idResults = append(*idResults, m.selectResult...)
	}

	return nil, m.errResult
}

func (m mockDB) SelectOne(interface{}, string, ...interface{}) error {
	return errors.New("not implemented")
}

func (m mockDB) Insert(...interface{}) error {
	return errors.New("not implemented")
}

func (m mockDB) Begin() (db.Transaction, error) {
	return nil, errors.New("not implemented")
}

func TestGetWork(t *testing.T) {
	log, clk := setup()
	startID := int64(10)
	table := "certificates"
	clk.Add(time.Hour * 5)
	resultsExpires := clk.Now().Add(-time.Hour * 2)
	batchSize := int64(20)
	workQuery := `
SELECT id, expires AS expires
FROM certificates
WHERE id > :startID
LIMIT :limit`
	mockIDs := []workUnit{
		{1, resultsExpires},
		{2, resultsExpires},
		{3, resultsExpires},
		{10, resultsExpires},
		{90, resultsExpires},
	}

	testDB := &mockDB{
		t:             t,
		expectedQuery: workQuery,
		expectedArgMap: map[string]interface{}{
			"startID": startID,
			"limit":   batchSize,
		},
	}

	workChan := make(chan int64, 5)

	job := &batchedDBJob{
		db:            testDB,
		log:           log,
		clk:           clk,
		table:         table,
		expiresColumn: "expires",
		purgeBefore:   time.Hour,
		batchSize:     batchSize,
	}

	// Mock Select() to return a non-nil error result
	testDB.errResult = errors.New("database is on vacation")
	_, err := job.getWork(workChan, startID)
	// We expect to get back an error
	test.AssertError(t, err, "no error returned from getWork with bad DB")

	// Mock Select() to return good results and a nil error
	testDB.errResult = nil
	testDB.selectResult = mockIDs

	// We expect to get back no error and the correct lastID
	lastID, err := job.getWork(workChan, startID)
	test.AssertNotError(t, err, "unexpected error from getWork")
	test.AssertEquals(t, lastID, mockIDs[len(mockIDs)-1].ID)

	// We should be able to read one item per mockID and it should match the expected ID
	for i := 0; i < len(mockIDs); i++ {
		got := <-workChan
		test.AssertEquals(t, got, mockIDs[i].ID)
	}

	// We expect the work gauge for this table has been updated
	test.AssertMetricWithLabelsEquals(
		t, workStat, prometheus.Labels{"table": table}, float64(len(mockIDs)))

	// Set the third item in mockIDs to have an expiry after the purge cutoff
	// so we expect to only get the first two items returned from getWork
	testDB.selectResult[2].Expires = clk.Now()
	workStat.Reset()

	// We expect to get back no error and the correct lastID
	lastID, err = job.getWork(workChan, startID)
	test.AssertNotError(t, err, "unexpected error from getWork")
	test.AssertEquals(t, lastID, testDB.selectResult[1].ID)

	for i := 0; i < 2; i++ {
		got := <-workChan
		test.AssertEquals(t, got, mockIDs[i].ID)
	}
	test.AssertMetricWithLabelsEquals(
		t, workStat, prometheus.Labels{"table": table}, 2)
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

	// create a batchedDBJob with the simpleResourceDelete function as the
	// deleteHandler
	job := &batchedDBJob{
		db:            testDB,
		log:           log,
		table:         table,
		expiresColumn: "expires",
		deleteHandler: deleteDefault,
	}

	// Mock Exec() to return a non-nil error result
	testDB.errResult = errors.New("database is on vacation")
	err := job.deleteHandler(job, testID)
	// We expect an err result back
	test.AssertError(t, err, "no error returned from deleteHandler with bad DB")
	// We expect no deletes to have been tracked in the deletedStat
	test.AssertMetricWithLabelsEquals(
		t, deletedStat, prometheus.Labels{"table": "certificates"}, 0)

	// With the mock error removed we expect no error returned from simpleDeleteResource
	testDB.errResult = nil
	err = job.deleteHandler(job, testID)
	test.AssertNotError(t, err, "unexpected error from deleteHandler")
	// We expect a delete to have been tracked in the deletedStat
	test.AssertMetricWithLabelsEquals(
		t, deletedStat, prometheus.Labels{"table": "certificates"}, 1)
}

type slowDB struct{}

func (db slowDB) Exec(_ string, _ ...interface{}) (sql.Result, error) {
	time.Sleep(time.Second)
	return nil, nil
}

func (db slowDB) Select(result interface{}, _ string, _ ...interface{}) ([]interface{}, error) {
	return nil, nil
}

func (db slowDB) SelectOne(interface{}, string, ...interface{}) error {
	return errors.New("not implemented")
}

func (db slowDB) Insert(...interface{}) error {
	return errors.New("not implemented")
}

func (db slowDB) Begin() (db.Transaction, error) {
	return nil, errors.New("not implemented")
}

func TestCleanResource(t *testing.T) {
	log, _ := setup()

	// Use a DB that always sleeps for 1 second for each Exec()'d delete.
	db := slowDB{}

	job := batchedDBJob{
		db:            db,
		log:           log,
		table:         "example",
		expiresColumn: "expires",
		// Start with a parallelism of 1
		parallelism:   1,
		deleteHandler: deleteDefault,
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

func TestBatchedDBJobValid(t *testing.T) {
	testCases := []struct {
		name        string
		j           batchedDBJob
		expectedErr error
	}{
		{
			name:        "no table",
			j:           batchedDBJob{},
			expectedErr: errNoTable,
		},
		{
			name: "no purgeBefore",
			j: batchedDBJob{
				table: "chef's",
			},
			expectedErr: errNoPurgeBefore,
		},
		{
			name: "too small purgeBefore",
			j: batchedDBJob{
				table:       "chef's",
				purgeBefore: minPurgeBefore,
			},
			expectedErr: errNoPurgeBefore,
		},
		{
			name: "no batchSize",
			j: batchedDBJob{
				table:       "chef's",
				purgeBefore: minPurgeBefore + time.Hour,
			},
			expectedErr: errNoBatchSize,
		},
		{
			name: "no parallelism",
			j: batchedDBJob{
				table:       "chef's",
				purgeBefore: minPurgeBefore + time.Hour,
				batchSize:   1,
			},
			expectedErr: errNoParallelism,
		},
		{
			name: "valid",
			j: batchedDBJob{
				table:         "chef's",
				expiresColumn: "kitchen",
				purgeBefore:   time.Hour * 24 * 91,
				batchSize:     1,
				parallelism:   1,
			},
			expectedErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.j.valid()
			test.AssertEquals(t, err, tc.expectedErr)
		})
	}
}
