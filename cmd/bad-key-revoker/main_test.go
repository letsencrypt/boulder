package notmain

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/db"
	blog "github.com/letsencrypt/boulder/log"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
)

func randHash(t *testing.T) []byte {
	t.Helper()
	h := make([]byte, 32)
	_, err := rand.Read(h)
	test.AssertNotError(t, err, "failed to read rand")
	return h
}

func insertBlockedRow(t *testing.T, dbMap *db.WrappedMap, fc clock.Clock, hash []byte, by int64, checked bool) {
	t.Helper()
	_, err := dbMap.ExecContext(context.Background(), `INSERT INTO blockedKeys
		(keyHash, added, source, revokedBy, extantCertificatesChecked)
		VALUES
		(?, ?, ?, ?, ?)`,
		hash,
		fc.Now(),
		1,
		by,
		checked,
	)
	test.AssertNotError(t, err, "failed to add test row")
}

func fcBeforeRepLag(clk clock.Clock, bkr *badKeyRevoker) clock.FakeClock {
	fc := clock.NewFake()
	fc.Set(clk.Now().Add(-bkr.maxExpectedReplicationLag - time.Second))
	return fc
}

func TestSelectUncheckedRows(t *testing.T) {
	ctx := context.Background()

	dbMap, err := sa.DBMapForTest(vars.DBConnSAFullPerms)
	test.AssertNotError(t, err, "failed setting up db client")
	defer test.ResetBoulderTestDatabase(t)()

	fc := clock.NewFake()

	bkr := &badKeyRevoker{
		dbMap:                     dbMap,
		logger:                    blog.NewMock(),
		clk:                       fc,
		maxExpectedReplicationLag: time.Second * 22,
	}

	hashA, hashB, hashC := randHash(t), randHash(t), randHash(t)

	// insert a blocked key that's marked as already checked
	insertBlockedRow(t, dbMap, fc, hashA, 1, true)
	count, err := bkr.countUncheckedKeys(ctx)
	test.AssertNotError(t, err, "countUncheckedKeys failed")
	test.AssertEquals(t, count, 0)
	_, err = bkr.selectUncheckedKey(ctx)
	test.AssertError(t, err, "selectUncheckedKey didn't fail with no rows to process")
	test.Assert(t, db.IsNoRows(err), "returned error is not sql.ErrNoRows")

	// insert a blocked key that's due to be checked
	insertBlockedRow(t, dbMap, fcBeforeRepLag(fc, bkr), hashB, 1, false)
	// insert a freshly blocked key, so it's not yet due to be checked
	insertBlockedRow(t, dbMap, fc, hashC, 1, false)
	count, err = bkr.countUncheckedKeys(ctx)
	test.AssertNotError(t, err, "countUncheckedKeys failed")
	test.AssertEquals(t, count, 1)
	row, err := bkr.selectUncheckedKey(ctx)
	test.AssertNotError(t, err, "selectUncheckKey failed")
	test.AssertByteEquals(t, row.KeyHash, hashB)
	test.AssertEquals(t, row.RevokedBy, int64(1))
}

func insertRegistration(t *testing.T, dbMap *db.WrappedMap, fc clock.Clock) int64 {
	t.Helper()
	jwkHash := make([]byte, 32)
	_, err := rand.Read(jwkHash)
	test.AssertNotError(t, err, "failed to read rand")
	res, err := dbMap.ExecContext(
		context.Background(),
		"INSERT INTO registrations (jwk, jwk_sha256, agreement, createdAt, status) VALUES (?, ?, ?, ?, ?)",
		[]byte{},
		fmt.Sprintf("%x", jwkHash),
		"yes",
		fc.Now(),
		string(core.StatusValid),
	)
	test.AssertNotError(t, err, "failed to insert test registrations row")
	regID, err := res.LastInsertId()
	test.AssertNotError(t, err, "failed to get registration ID")
	return regID
}

type ExpiredStatus bool

const (
	Expired   = ExpiredStatus(true)
	Unexpired = ExpiredStatus(false)
	Revoked   = core.OCSPStatusRevoked
	Unrevoked = core.OCSPStatusGood
)

func insertGoodCert(t *testing.T, dbMap *db.WrappedMap, fc clock.Clock, keyHash []byte, serial string, regID int64) {
	insertCert(t, dbMap, fc, keyHash, serial, regID, Unexpired, Unrevoked)
}

func insertCert(t *testing.T, dbMap *db.WrappedMap, fc clock.Clock, keyHash []byte, serial string, regID int64, expiredStatus ExpiredStatus, status core.OCSPStatus) {
	t.Helper()
	ctx := context.Background()

	expiresOffset := 0 * time.Second
	if !expiredStatus {
		expiresOffset = 90*24*time.Hour - 1*time.Second // 90 days exclusive
	}

	_, err := dbMap.ExecContext(
		ctx,
		`INSERT IGNORE INTO keyHashToSerial
	     (keyHash, certNotAfter, certSerial) VALUES
		 (?, ?, ?)`,
		keyHash,
		fc.Now().Add(expiresOffset),
		serial,
	)
	test.AssertNotError(t, err, "failed to insert test keyHashToSerial row")

	_, err = dbMap.ExecContext(
		ctx,
		"INSERT INTO certificateStatus (serial, status, isExpired, ocspLastUpdated, revokedDate, revokedReason, lastExpirationNagSent) VALUES (?, ?, ?, ?, ?, ?, ?)",
		serial,
		status,
		expiredStatus,
		fc.Now(),
		time.Time{},
		0,
		time.Time{},
	)
	test.AssertNotError(t, err, "failed to insert test certificateStatus row")

	_, err = dbMap.ExecContext(
		ctx,
		"INSERT INTO precertificates (serial, registrationID, der, issued, expires) VALUES (?, ?, ?, ?, ?)",
		serial,
		regID,
		[]byte{1, 2, 3},
		fc.Now(),
		fc.Now().Add(expiresOffset),
	)
	test.AssertNotError(t, err, "failed to insert test certificateStatus row")

	_, err = dbMap.ExecContext(
		ctx,
		"INSERT INTO certificates (serial, registrationID, der, digest, issued, expires) VALUES (?, ?, ?, ?, ?, ?)",
		serial,
		regID,
		[]byte{1, 2, 3},
		[]byte{},
		fc.Now(),
		fc.Now().Add(expiresOffset),
	)
	test.AssertNotError(t, err, "failed to insert test certificates row")
}

// Test that we produce an error when a serial from the keyHashToSerial table
// does not have a corresponding entry in the certificateStatus and
// precertificates table.
func TestFindUnrevokedNoRows(t *testing.T) {
	ctx := context.Background()

	dbMap, err := sa.DBMapForTest(vars.DBConnSAFullPerms)
	test.AssertNotError(t, err, "failed setting up db client")
	defer test.ResetBoulderTestDatabase(t)()

	fc := clock.NewFake()

	hashA := randHash(t)
	_, err = dbMap.ExecContext(
		ctx,
		"INSERT INTO keyHashToSerial (keyHash, certNotAfter, certSerial) VALUES (?, ?, ?)",
		hashA,
		fc.Now().Add(90*24*time.Hour-1*time.Second), // 90 days exclusive
		"zz",
	)
	test.AssertNotError(t, err, "failed to insert test keyHashToSerial row")

	bkr := &badKeyRevoker{
		dbMap:                     dbMap,
		serialBatchSize:           1,
		maxRevocations:            10,
		clk:                       fc,
		maxExpectedReplicationLag: time.Second * 22,
	}
	_, err = bkr.findUnrevoked(ctx, uncheckedBlockedKey{KeyHash: hashA})
	test.Assert(t, db.IsNoRows(err), "expected NoRows error")
}

func TestFindUnrevoked(t *testing.T) {
	ctx := context.Background()

	dbMap, err := sa.DBMapForTest(vars.DBConnSAFullPerms)
	test.AssertNotError(t, err, "failed setting up db client")
	defer test.ResetBoulderTestDatabase(t)()

	fc := clock.NewFake()

	regID := insertRegistration(t, dbMap, fc)

	bkr := &badKeyRevoker{
		dbMap:                     dbMap,
		serialBatchSize:           1,
		maxRevocations:            10,
		clk:                       fc,
		maxExpectedReplicationLag: time.Second * 22,
	}

	hashA := randHash(t)
	// insert valid, unexpired
	insertCert(t, dbMap, fc, hashA, "ff", regID, Unexpired, Unrevoked)
	// insert valid, unexpired, duplicate
	insertCert(t, dbMap, fc, hashA, "ff", regID, Unexpired, Unrevoked)
	// insert valid, expired
	insertCert(t, dbMap, fc, hashA, "ee", regID, Expired, Unrevoked)
	// insert revoked
	insertCert(t, dbMap, fc, hashA, "dd", regID, Unexpired, Revoked)

	rows, err := bkr.findUnrevoked(ctx, uncheckedBlockedKey{KeyHash: hashA})
	test.AssertNotError(t, err, "findUnrevoked failed")
	test.AssertEquals(t, len(rows), 1)
	test.AssertEquals(t, rows[0].Serial, "ff")
	test.AssertEquals(t, rows[0].RegistrationID, int64(1))
	test.AssertByteEquals(t, rows[0].DER, []byte{1, 2, 3})

	bkr.maxRevocations = 0
	_, err = bkr.findUnrevoked(ctx, uncheckedBlockedKey{KeyHash: hashA})
	test.AssertError(t, err, "findUnrevoked didn't fail with 0 maxRevocations")
	test.AssertEquals(t, err.Error(), fmt.Sprintf("too many certificates to revoke associated with %x: got 1, max 0", hashA))
}

type mockRevoker struct {
	revoked int
	mu      sync.Mutex
}

func (mr *mockRevoker) AdministrativelyRevokeCertificate(ctx context.Context, in *rapb.AdministrativelyRevokeCertificateRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	mr.revoked++
	return nil, nil
}

func TestRevokeCerts(t *testing.T) {
	dbMap, err := sa.DBMapForTest(vars.DBConnSAFullPerms)
	test.AssertNotError(t, err, "failed setting up db client")
	defer test.ResetBoulderTestDatabase(t)()

	fc := clock.NewFake()
	mr := &mockRevoker{}
	bkr := &badKeyRevoker{
		dbMap:    dbMap,
		raClient: mr,
		clk:      fc,
	}

	err = bkr.revokeCerts([]unrevokedCertificate{
		{ID: 0, Serial: "ff"},
		{ID: 1, Serial: "ee"},
	})
	test.AssertNotError(t, err, "revokeCerts failed")
	test.AssertEquals(t, mr.revoked, 2)
}

func TestCertificateAbsent(t *testing.T) {
	ctx := context.Background()

	dbMap, err := sa.DBMapForTest(vars.DBConnSAFullPerms)
	test.AssertNotError(t, err, "failed setting up db client")
	defer test.ResetBoulderTestDatabase(t)()

	fc := clock.NewFake()
	bkr := &badKeyRevoker{
		dbMap:                     dbMap,
		maxRevocations:            1,
		serialBatchSize:           1,
		raClient:                  &mockRevoker{},
		logger:                    blog.NewMock(),
		clk:                       fc,
		maxExpectedReplicationLag: time.Second * 22,
	}

	// populate DB with all the test data
	regIDA := insertRegistration(t, dbMap, fc)
	hashA := randHash(t)
	insertBlockedRow(t, dbMap, fcBeforeRepLag(fc, bkr), hashA, regIDA, false)

	// Add an entry to keyHashToSerial but not to certificateStatus or certificate
	// status, and expect an error.
	_, err = dbMap.ExecContext(
		ctx,
		"INSERT INTO keyHashToSerial (keyHash, certNotAfter, certSerial) VALUES (?, ?, ?)",
		hashA,
		fc.Now().Add(90*24*time.Hour-1*time.Second), // 90 days exclusive
		"ffaaee",
	)
	test.AssertNotError(t, err, "failed to insert test keyHashToSerial row")

	_, err = bkr.invoke(ctx)
	test.AssertError(t, err, "expected error when row in keyHashToSerial didn't have a matching cert")
}

func TestInvoke(t *testing.T) {
	ctx := context.Background()

	dbMap, err := sa.DBMapForTest(vars.DBConnSAFullPerms)
	test.AssertNotError(t, err, "failed setting up db client")
	defer test.ResetBoulderTestDatabase(t)()

	fc := clock.NewFake()

	mr := &mockRevoker{}
	bkr := &badKeyRevoker{
		dbMap:                     dbMap,
		maxRevocations:            10,
		serialBatchSize:           1,
		raClient:                  mr,
		logger:                    blog.NewMock(),
		clk:                       fc,
		maxExpectedReplicationLag: time.Second * 22,
	}

	// populate DB with all the test data
	regIDA := insertRegistration(t, dbMap, fc)
	regIDB := insertRegistration(t, dbMap, fc)
	regIDC := insertRegistration(t, dbMap, fc)
	regIDD := insertRegistration(t, dbMap, fc)
	hashA := randHash(t)
	insertBlockedRow(t, dbMap, fcBeforeRepLag(fc, bkr), hashA, regIDC, false)
	insertGoodCert(t, dbMap, fc, hashA, "ff", regIDA)
	insertGoodCert(t, dbMap, fc, hashA, "ee", regIDB)
	insertGoodCert(t, dbMap, fc, hashA, "dd", regIDC)
	insertGoodCert(t, dbMap, fc, hashA, "cc", regIDD)

	noWork, err := bkr.invoke(ctx)
	test.AssertNotError(t, err, "invoke failed")
	test.AssertEquals(t, noWork, false)
	test.AssertEquals(t, mr.revoked, 4)
	test.AssertMetricWithLabelsEquals(t, keysToProcess, prometheus.Labels{}, 1)

	var checked struct {
		ExtantCertificatesChecked bool
	}
	err = dbMap.SelectOne(ctx, &checked, "SELECT extantCertificatesChecked FROM blockedKeys WHERE keyHash = ?", hashA)
	test.AssertNotError(t, err, "failed to select row from blockedKeys")
	test.AssertEquals(t, checked.ExtantCertificatesChecked, true)

	// add a row with no associated valid certificates
	hashB := randHash(t)
	insertBlockedRow(t, dbMap, fcBeforeRepLag(fc, bkr), hashB, regIDC, false)
	insertCert(t, dbMap, fc, hashB, "bb", regIDA, Expired, Revoked)

	noWork, err = bkr.invoke(ctx)
	test.AssertNotError(t, err, "invoke failed")
	test.AssertEquals(t, noWork, false)

	checked.ExtantCertificatesChecked = false
	err = dbMap.SelectOne(ctx, &checked, "SELECT extantCertificatesChecked FROM blockedKeys WHERE keyHash = ?", hashB)
	test.AssertNotError(t, err, "failed to select row from blockedKeys")
	test.AssertEquals(t, checked.ExtantCertificatesChecked, true)

	noWork, err = bkr.invoke(ctx)
	test.AssertNotError(t, err, "invoke failed")
	test.AssertEquals(t, noWork, true)
}

func TestInvokeRevokerHasNoExtantCerts(t *testing.T) {
	// This test checks that when the user who revoked the initial
	// certificate that added the row to blockedKeys doesn't have any
	// extant certificates themselves their contact email is still
	// resolved and we avoid sending any emails to accounts that
	// share the same email.
	dbMap, err := sa.DBMapForTest(vars.DBConnSAFullPerms)
	test.AssertNotError(t, err, "failed setting up db client")
	defer test.ResetBoulderTestDatabase(t)()

	fc := clock.NewFake()

	mr := &mockRevoker{}
	bkr := &badKeyRevoker{dbMap: dbMap,
		maxRevocations:            10,
		serialBatchSize:           1,
		raClient:                  mr,
		logger:                    blog.NewMock(),
		clk:                       fc,
		maxExpectedReplicationLag: time.Second * 22,
	}

	// populate DB with all the test data
	regIDA := insertRegistration(t, dbMap, fc)
	regIDB := insertRegistration(t, dbMap, fc)
	regIDC := insertRegistration(t, dbMap, fc)

	hashA := randHash(t)

	insertBlockedRow(t, dbMap, fcBeforeRepLag(fc, bkr), hashA, regIDA, false)

	insertGoodCert(t, dbMap, fc, hashA, "ee", regIDB)
	insertGoodCert(t, dbMap, fc, hashA, "dd", regIDB)
	insertGoodCert(t, dbMap, fc, hashA, "cc", regIDC)
	insertGoodCert(t, dbMap, fc, hashA, "bb", regIDC)

	noWork, err := bkr.invoke(context.Background())
	test.AssertNotError(t, err, "invoke failed")
	test.AssertEquals(t, noWork, false)
	test.AssertEquals(t, mr.revoked, 4)
}

func TestBackoffPolicy(t *testing.T) {
	fc := clock.NewFake()
	mocklog := blog.NewMock()
	bkr := &badKeyRevoker{
		clk:                 fc,
		backoffIntervalMax:  time.Second * 60,
		backoffIntervalBase: time.Second * 1,
		backoffFactor:       1.3,
		logger:              mocklog,
	}

	// Backoff once. Check to make sure the backoff is logged.
	bkr.backoff()
	resultLog := mocklog.GetAllMatching("INFO: backoff trying again in")
	if len(resultLog) == 0 {
		t.Fatalf("no backoff loglines found")
	}

	// Make sure `backoffReset` resets the ticker.
	bkr.backoffReset()
	test.AssertEquals(t, bkr.backoffTicker, 0)
}
