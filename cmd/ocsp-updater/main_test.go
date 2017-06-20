package main

import (
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/jmhodges/clock"
	"golang.org/x/net/context"
	"gopkg.in/go-gorp/gorp.v2"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/publisher/mock_publisher"
	"github.com/letsencrypt/boulder/revocation"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
)

var ctx = context.Background()

type mockCA struct {
	sleepTime time.Duration
}

func (ca *mockCA) IssueCertificate(_ context.Context, csr x509.CertificateRequest, regID int64) (core.Certificate, error) {
	return core.Certificate{}, nil
}

func (ca *mockCA) GenerateOCSP(_ context.Context, xferObj core.OCSPSigningRequest) (ocsp []byte, err error) {
	ocsp = []byte{1, 2, 3}
	time.Sleep(ca.sleepTime)
	return
}

type mockPub struct {
	sa   core.StorageAuthority
	logs []cmd.LogDescription
}

func logPublicKeyToID(logPK string) (string, error) {
	logPKBytes, err := base64.StdEncoding.DecodeString(logPK)
	if err != nil {
		return "", err
	}

	logPKHash := sha256.Sum256(logPKBytes)
	logID := base64.StdEncoding.EncodeToString(logPKHash[:])
	return logID, nil
}

func (p *mockPub) SubmitToCT(_ context.Context, _ []byte) error {
	// Add an SCT for every configured log
	for _, log := range p.logs {
		logID, err := logPublicKeyToID(log.Key)
		if err != nil {
			return err
		}
		sct := core.SignedCertificateTimestamp{
			SCTVersion:        0,
			LogID:             logID,
			Timestamp:         0,
			Extensions:        []byte{},
			Signature:         []byte{0},
			CertificateSerial: "00",
		}
		err = p.sa.AddSCTReceipt(ctx, sct)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *mockPub) SubmitToSingleCT(_ context.Context, _, logPublicKey string, _ []byte) error {
	logID, err := logPublicKeyToID(logPublicKey)
	if err != nil {
		return err
	}
	// Add an SCT for the provided log ID
	sct := core.SignedCertificateTimestamp{
		SCTVersion:        0,
		LogID:             logID,
		Timestamp:         0,
		Extensions:        []byte{},
		Signature:         []byte{0},
		CertificateSerial: "00",
	}
	err = p.sa.AddSCTReceipt(ctx, sct)
	return err
}

var log = blog.UseMock()

const (
	// Each log's test PK is the base64 of "test pk 1" .. "test pk 2"
	testLogAPK = "dGVzdCBwayAx"
	testLogBPK = "dGVzdCBwayAy"
	testLogCPK = "dGVzdCBwayAz"
	// Each log's ID is the base64 of the SHA256 sum of the PK above
	testLogAID = "27sby+EK3U1YKhUUGi9vBfFskgHvKpRMJ7PtNJzGUF8="
	testLogBID = "EpN+1e1h2jWN6W4IRG4KwjwiY9QIWaep5Qf3s8NLRmc="
	testLogCID = "OOn8yL8QPsMuqENGprtlkOYkJqwhhcAifEHUPevmnCc="
)

func setup(t *testing.T) (*OCSPUpdater, core.StorageAuthority, *gorp.DbMap, clock.FakeClock, func()) {
	dbMap, err := sa.NewDbMap(vars.DBConnSA, 0)
	test.AssertNotError(t, err, "Failed to create dbMap")
	sa.SetSQLDebug(dbMap, log)

	fc := clock.NewFake()
	fc.Add(1 * time.Hour)

	sa, err := sa.NewSQLStorageAuthority(dbMap, fc, log, metrics.NewNoopScope())
	test.AssertNotError(t, err, "Failed to create SA")

	cleanUp := test.ResetSATestDatabase(t)

	logs := []cmd.LogDescription{
		cmd.LogDescription{
			URI: "test",
			Key: testLogAPK,
		},
		cmd.LogDescription{
			URI: "test2",
			Key: testLogBPK,
		},
		cmd.LogDescription{
			URI: "test3",
			Key: testLogCPK,
		},
	}

	updater, err := newUpdater(
		metrics.NewNoopScope(),
		fc,
		dbMap,
		&mockCA{},
		&mockPub{sa, logs},
		sa,
		cmd.OCSPUpdaterConfig{
			NewCertificateBatchSize: 1,
			OldOCSPBatchSize:        1,
			MissingSCTBatchSize:     1,
			NewCertificateWindow:    cmd.ConfigDuration{Duration: time.Second},
			OldOCSPWindow:           cmd.ConfigDuration{Duration: time.Second},
			MissingSCTWindow:        cmd.ConfigDuration{Duration: time.Second},
		},
		logs,
		"",
		blog.NewMock(),
	)
	test.AssertNotError(t, err, "Failed to create newUpdater")

	return updater, sa, dbMap, fc, cleanUp
}

func TestGenerateAndStoreOCSPResponse(t *testing.T) {
	updater, sa, _, _, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID, nil)
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")

	status, err := sa.GetCertificateStatus(ctx, core.SerialToString(parsedCert.SerialNumber))
	test.AssertNotError(t, err, "Couldn't get the core.CertificateStatus from the database")

	meta, err := updater.generateResponse(ctx, status)
	test.AssertNotError(t, err, "Couldn't generate OCSP response")
	err = updater.storeResponse(meta)
	test.AssertNotError(t, err, "Couldn't store certificate status")

	secondMeta, err := updater.generateRevokedResponse(ctx, status)
	test.AssertNotError(t, err, "Couldn't generate revoked OCSP response")
	err = updater.storeResponse(secondMeta)
	test.AssertNotError(t, err, "Couldn't store certificate status")

	newStatus, err := sa.GetCertificateStatus(ctx, status.Serial)
	test.AssertNotError(t, err, "Couldn't retrieve certificate status")
	test.AssertByteEquals(t, meta.OCSPResponse, newStatus.OCSPResponse)
}

func TestGenerateOCSPResponses(t *testing.T) {
	updater, sa, dbMap, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCertA, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	_, err = sa.AddCertificate(ctx, parsedCertA.Raw, reg.ID, nil)
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")
	parsedCertB, err := core.LoadCert("test-cert-b.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	_, err = sa.AddCertificate(ctx, parsedCertB.Raw, reg.ID, nil)
	test.AssertNotError(t, err, "Couldn't add test-cert-b.pem")

	// We need to set a fake "ocspLastUpdated" value for the two certs we created
	// in order to satisfy the "ocspStaleMaxAge" constraint.
	fakeLastUpdate := fc.Now().Add(-time.Hour * 24 * 3)
	_, err = dbMap.Exec(
		"UPDATE certificateStatus SET ocspLastUpdated = ? WHERE serial IN (?, ?)",
		fakeLastUpdate,
		core.SerialToString(parsedCertA.SerialNumber),
		core.SerialToString(parsedCertB.SerialNumber))
	test.AssertNotError(t, err, "Couldn't update ocspLastUpdated")

	earliest := fc.Now().Add(-time.Hour)
	certs, err := updater.findStaleOCSPResponses(earliest, 10)
	test.AssertNotError(t, err, "Couldn't find stale responses")
	test.AssertEquals(t, len(certs), 2)

	// Hacky test of parallelism: Make each request to the CA take 1 second, and
	// produce 2 requests to the CA. If the pair of requests complete in about a
	// second, they were made in parallel.
	// Note that this test also tests the basic functionality of
	// generateOCSPResponses.
	start := time.Now()
	updater.cac = &mockCA{time.Second}
	updater.parallelGenerateOCSPRequests = 10
	err = updater.generateOCSPResponses(ctx, certs, metrics.NewNoopScope())
	test.AssertNotError(t, err, "Couldn't generate OCSP responses")
	elapsed := time.Since(start)
	if elapsed > 1500*time.Millisecond {
		t.Errorf("generateOCSPResponses took too long, expected it to make calls in parallel.")
	}

	certs, err = updater.findStaleOCSPResponses(earliest, 10)
	test.AssertNotError(t, err, "Failed to find stale responses")
	test.AssertEquals(t, len(certs), 0)
}

func TestFindStaleOCSPResponses(t *testing.T) {
	updater, sa, dbMap, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID, nil)
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")

	// We need to set a fake "ocspLastUpdated" value for the cert we created
	// in order to satisfy the "ocspStaleMaxAge" constraint.
	fakeLastUpdate := fc.Now().Add(-time.Hour * 24 * 3)
	_, err = dbMap.Exec(
		"UPDATE certificateStatus SET ocspLastUpdated = ? WHERE serial = ?",
		fakeLastUpdate,
		core.SerialToString(parsedCert.SerialNumber))
	test.AssertNotError(t, err, "Couldn't update ocspLastUpdated")

	earliest := fc.Now().Add(-time.Hour)
	certs, err := updater.findStaleOCSPResponses(earliest, 10)
	test.AssertNotError(t, err, "Couldn't find certificate")
	test.AssertEquals(t, len(certs), 1)

	status, err := sa.GetCertificateStatus(ctx, core.SerialToString(parsedCert.SerialNumber))
	test.AssertNotError(t, err, "Couldn't get the core.Certificate from the database")

	meta, err := updater.generateResponse(ctx, status)
	test.AssertNotError(t, err, "Couldn't generate OCSP response")
	err = updater.storeResponse(meta)
	test.AssertNotError(t, err, "Couldn't store OCSP response")

	certs, err = updater.findStaleOCSPResponses(earliest, 10)
	test.AssertNotError(t, err, "Failed to find stale responses")
	test.AssertEquals(t, len(certs), 0)
}

func TestFindStaleOCSPResponsesStaleMaxAge(t *testing.T) {
	updater, sa, dbMap, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCertA, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	_, err = sa.AddCertificate(ctx, parsedCertA.Raw, reg.ID, nil)
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")
	parsedCertB, err := core.LoadCert("test-cert-b.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	_, err = sa.AddCertificate(ctx, parsedCertB.Raw, reg.ID, nil)
	test.AssertNotError(t, err, "Couldn't add test-cert-b.pem")

	// Set a "ocspLastUpdated" value of 3 days ago for parsedCertA
	okLastUpdated := fc.Now().Add(-time.Hour * 24 * 3)
	_, err = dbMap.Exec(
		"UPDATE certificateStatus SET ocspLastUpdated = ? WHERE serial = ?",
		okLastUpdated,
		core.SerialToString(parsedCertA.SerialNumber))
	test.AssertNotError(t, err, "Couldn't update ocspLastUpdated for parsedCertA")

	// Set a "ocspLastUpdated" value of 35 days ago for parsedCertB
	excludedLastUpdated := fc.Now().Add(-time.Hour * 24 * 35)
	_, err = dbMap.Exec(
		"UPDATE certificateStatus SET ocspLastUpdated = ? WHERE serial = ?",
		excludedLastUpdated,
		core.SerialToString(parsedCertB.SerialNumber))
	test.AssertNotError(t, err, "Couldn't update ocspLastUpdated for parsedCertB")

	// Running `findStaleOCSPResponses should only find *ONE* of the above
	// certificates, parsedCertA. The second should be excluded by the
	// `ocspStaleMaxAge` cutoff.
	earliest := fc.Now().Add(-time.Hour)
	certs, err := updater.findStaleOCSPResponses(earliest, 10)
	test.AssertNotError(t, err, "Couldn't find stale responses")
	test.AssertEquals(t, len(certs), 1)
	test.AssertEquals(t, certs[0].Serial, core.SerialToString(parsedCertA.SerialNumber))
}

func TestGetCertificatesWithMissingResponses(t *testing.T) {
	updater, sa, _, _, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	cert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	_, err = sa.AddCertificate(ctx, cert.Raw, reg.ID, nil)
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")

	statuses, err := updater.getCertificatesWithMissingResponses(10)
	test.AssertNotError(t, err, "Couldn't get status")
	test.AssertEquals(t, len(statuses), 1)
}

func TestFindRevokedCertificatesToUpdate(t *testing.T) {
	updater, sa, _, _, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	cert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	_, err = sa.AddCertificate(ctx, cert.Raw, reg.ID, nil)
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")

	statuses, err := updater.findRevokedCertificatesToUpdate(10)
	test.AssertNotError(t, err, "Failed to find revoked certificates")
	test.AssertEquals(t, len(statuses), 0)

	err = sa.MarkCertificateRevoked(ctx, core.SerialToString(cert.SerialNumber), revocation.KeyCompromise)
	test.AssertNotError(t, err, "Failed to revoke certificate")

	statuses, err = updater.findRevokedCertificatesToUpdate(10)
	test.AssertNotError(t, err, "Failed to find revoked certificates")
	test.AssertEquals(t, len(statuses), 1)
}

func TestNewCertificateTick(t *testing.T) {
	updater, sa, _, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID, nil)
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")

	prev := fc.Now().Add(-time.Hour)
	err = updater.newCertificateTick(ctx, 10)
	test.AssertNotError(t, err, "Couldn't run newCertificateTick")

	certs, err := updater.findStaleOCSPResponses(prev, 10)
	test.AssertNotError(t, err, "Failed to find stale responses")
	test.AssertEquals(t, len(certs), 0)
}

func TestOldOCSPResponsesTick(t *testing.T) {
	updater, sa, _, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID, nil)
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")

	updater.ocspMinTimeToExpiry = 1 * time.Hour
	err = updater.oldOCSPResponsesTick(ctx, 10)
	test.AssertNotError(t, err, "Couldn't run oldOCSPResponsesTick")

	certs, err := updater.findStaleOCSPResponses(fc.Now().Add(-updater.ocspMinTimeToExpiry), 10)
	test.AssertNotError(t, err, "Failed to find stale responses")
	test.AssertEquals(t, len(certs), 0)
}

// TestOldOCSPResponsesTickIsExpired checks that the old OCSP responses tick
// updates the `IsExpired` field opportunistically as it encounters certificates
// that are expired but whose certificate status rows do not have `IsExpired`
// set.
func TestOldOCSPResponsesTickIsExpired(t *testing.T) {
	// Explicitly enable the CertStatusOptimizationsMigrated feature so the OCSP
	// updater can use the `IsExpired` field. This must be done before `setup()`
	// so the correct dbMap associations are used
	_ = features.Set(map[string]bool{"CertStatusOptimizationsMigrated": true})
	defer features.Reset()

	updater, sa, dbMap, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	serial := core.SerialToString(parsedCert.SerialNumber)

	// Add a new test certificate
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID, nil)
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")

	// We need to set a fake "ocspLastUpdated" value for the cert we created
	// in order to satisfy the "ocspStaleMaxAge" constraint. It needs to fall
	// within the range of the updater.ocspMinTimeToExpiry we set later.
	fakeLastUpdate := parsedCert.NotAfter.Add(-time.Hour)
	_, err = dbMap.Exec(
		"UPDATE certificateStatus SET ocspLastUpdated = ? WHERE serial = ?",
		fakeLastUpdate,
		serial)
	test.AssertNotError(t, err, "Couldn't update ocspLastUpdated")

	// The certificate isn't expired, so the certificate status should have
	// a false `IsExpired`
	cs, err := sa.GetCertificateStatus(ctx, serial)
	test.AssertNotError(t, err, fmt.Sprintf("Couldn't get certificate status for %q", serial))
	test.AssertEquals(t, cs.IsExpired, false)

	// Advance the clock to the point that the certificate we added is now expired
	fc.Set(parsedCert.NotAfter.Add(time.Hour))

	// Run the oldOCSPResponsesTick so that it can have a chance to find expired
	// certificates
	updater.ocspMinTimeToExpiry = 1 * time.Hour
	err = updater.oldOCSPResponsesTick(ctx, 10)
	test.AssertNotError(t, err, "Couldn't run oldOCSPResponsesTick")

	// Since we advanced the fakeclock beyond our test certificate's NotAfter we
	// expect the certificate status has been updated to have a true `IsExpired`
	cs, err = sa.GetCertificateStatus(ctx, serial)
	test.AssertNotError(t, err, fmt.Sprintf("Couldn't get certificate status for %q", serial))
	test.AssertEquals(t, cs.IsExpired, true)
}

func TestMissingReceiptsTick(t *testing.T) {
	updater, sa, _, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	fc.Set(parsedCert.NotBefore.Add(time.Minute))
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID, nil)
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")

	updater.oldestIssuedSCT = 2 * time.Hour

	serials, err := updater.getSerialsIssuedSince(fc.Now().Add(-2*time.Hour), 1)
	test.AssertNotError(t, err, "Failed to retrieve serials")
	test.AssertEquals(t, len(serials), 1)

	// Run the missing receipts tick
	err = updater.missingReceiptsTick(ctx, 5)
	test.AssertNotError(t, err, "Failed to run missingReceiptsTick")

	// We have three logs configured from setup, and with the
	// ResubmitMissingSCTsOnly feature flag disabled we expect that we submitted
	// to all three logs.
	logIDs, err := updater.getSubmittedReceipts("00")
	test.AssertNotError(t, err, "Couldn't get submitted receipts for serial 00")
	test.AssertEquals(t, len(logIDs), 3)
	test.AssertEquals(t, logIDs[0], testLogAID)
	test.AssertEquals(t, logIDs[1], testLogBID)
	test.AssertEquals(t, logIDs[2], testLogCID)

	// make sure we don't spin forever after reducing the
	// number of logs we submit to
	logA, err := newLog(
		cmd.LogDescription{
			URI: "test",
			Key: testLogAPK,
		})
	test.AssertNotError(t, err, "Failed to newLog test log A")
	updater.logs = []*ctLog{logA}
	err = updater.missingReceiptsTick(ctx, 10)
	test.AssertNotError(t, err, "Failed to run missingReceiptsTick")
}

func TestMissingOnlyReceiptsTick(t *testing.T) {
	updater, sa, _, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	fc.Set(parsedCert.NotBefore.Add(time.Minute))
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID, nil)
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")

	updater.oldestIssuedSCT = 2 * time.Hour

	serials, err := updater.getSerialsIssuedSince(fc.Now().Add(-2*time.Hour), 1)
	test.AssertNotError(t, err, "Failed to retrieve serials")
	test.AssertEquals(t, len(serials), 1)

	// Enable the ResubmitMissingSCTsOnly feature flag for this test run
	_ = features.Set(map[string]bool{"ResubmitMissingSCTsOnly": true})
	defer features.Reset()

	// Use a mock publisher so we can EXPECT specific calls
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockPub := mock_publisher.NewMockPublisher(ctrl)
	updater.pubc = mockPub

	// Add an SCT for one of the three logs (test2)
	sct := core.SignedCertificateTimestamp{
		SCTVersion:        0,
		LogID:             testLogBID,
		Timestamp:         0,
		Extensions:        []byte{},
		Signature:         []byte{0},
		CertificateSerial: core.SerialToString(parsedCert.SerialNumber),
	}
	err = sa.AddSCTReceipt(ctx, sct)
	test.AssertNotError(t, err, "Failed to AddSCTReceipt")

	// We expect that there are only going to be TWO calls to SubmitSingleCT, one
	// for each of the missing logs. We do NOT expect a call for "test2" since we
	// already added a SCT for that log!
	mockPub.EXPECT().SubmitToSingleCT(ctx, "test", testLogAPK, parsedCert.Raw)
	mockPub.EXPECT().SubmitToSingleCT(ctx, "test3", testLogCPK, parsedCert.Raw)

	// Run the missing receipts tick, with the correct EXPECT's there should be no errors
	err = updater.missingReceiptsTick(ctx, 5)
	test.AssertNotError(t, err, "Failed to run missingReceiptsTick")
}

/*
 * https://github.com/letsencrypt/boulder/issues/1872 identified that the
 * `getSerialsIssuedSince` function may never terminate if there are always new
 * serials added between iterations of the SQL query loop. In order to unit test
 * the fix we require a `ocspDB` implementation that will forever return
 * a serial when queried.
 */
type inexhaustibleDB struct{}

func (s inexhaustibleDB) Select(output interface{}, _ string, _ ...interface{}) ([]interface{}, error) {
	outputPtr, _ := output.(*[]string)
	// Always return one serial regardless of the query
	*outputPtr = []string{"1234"}
	return nil, nil
}

func (s inexhaustibleDB) Exec(_ string, _ ...interface{}) (sql.Result, error) {
	return nil, nil // NOP - we don't use this selector anywhere Exec is called
}

func (s inexhaustibleDB) SelectOne(_ interface{}, _ string, _ ...interface{}) error {
	return nil // NOP - we don't use this selector anywhere SelectOne is called
}

func TestMissingReceiptsTickTerminate(t *testing.T) {
	updater, _, _, fc, cleanUp := setup(t)
	defer cleanUp()

	// Replace the dbMap with the inexhaustibleDB to ensure the
	// conditions that cause the termination bug described in
	// https://github.com/letsencrypt/boulder/issues/1872 are met
	updater.dbMap = inexhaustibleDB{}
	updater.oldestIssuedSCT = 2 * time.Hour

	// Note: Must use a batch size larger than the # of rows returned by
	// inexhaustibleDB or `updater.getSerialsIssuedSince` will never
	// return
	batchSize := 5

	serials, err := updater.getSerialsIssuedSince(fc.Now().Add(-2*time.Hour), batchSize)
	test.AssertNotError(t, err, "Failed to retrieve serials")
	// Even though the inexhaustibleDB returns 1 result for every
	// query, since we abort when results < batchSize the expected behaviour is to
	// terminate with 1 result, the first fake serial returned for the first
	// query. No subsequent results are evaluated.
	test.AssertEquals(t, len(serials), 1)
}

func TestRevokedCertificatesTick(t *testing.T) {
	updater, sa, _, _, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID, nil)
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")

	err = sa.MarkCertificateRevoked(ctx, core.SerialToString(parsedCert.SerialNumber), revocation.KeyCompromise)
	test.AssertNotError(t, err, "Failed to revoke certificate")

	statuses, err := updater.findRevokedCertificatesToUpdate(10)
	test.AssertNotError(t, err, "Failed to find revoked certificates")
	test.AssertEquals(t, len(statuses), 1)

	err = updater.revokedCertificatesTick(ctx, 10)
	test.AssertNotError(t, err, "Failed to run revokedCertificatesTick")

	status, err := sa.GetCertificateStatus(ctx, core.SerialToString(parsedCert.SerialNumber))
	test.AssertNotError(t, err, "Failed to get certificate status")
	test.AssertEquals(t, status.Status, core.OCSPStatusRevoked)
	test.Assert(t, len(status.OCSPResponse) != 0, "Certificate status doesn't contain OCSP response")
}

func TestStoreResponseGuard(t *testing.T) {
	updater, sa, _, _, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID, nil)
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")

	status, err := sa.GetCertificateStatus(ctx, core.SerialToString(parsedCert.SerialNumber))
	test.AssertNotError(t, err, "Failed to get certificate status")

	err = sa.MarkCertificateRevoked(ctx, core.SerialToString(parsedCert.SerialNumber), 0)
	test.AssertNotError(t, err, "Failed to revoked certificate")

	// Attempt to update OCSP response where status.Status is good but stored status
	// is revoked, this should fail silently
	status.OCSPResponse = []byte{0, 1, 1}
	err = updater.storeResponse(&status)
	test.AssertNotError(t, err, "Failed to update certificate status")

	// Make sure the OCSP response hasn't actually changed
	unchangedStatus, err := sa.GetCertificateStatus(ctx, core.SerialToString(parsedCert.SerialNumber))
	test.AssertNotError(t, err, "Failed to get certificate status")
	test.AssertEquals(t, len(unchangedStatus.OCSPResponse), 0)

	// Changing the status to the stored status should allow the update to occur
	status.Status = core.OCSPStatusRevoked
	err = updater.storeResponse(&status)
	test.AssertNotError(t, err, "Failed to updated certificate status")

	// Make sure the OCSP response has been updated
	changedStatus, err := sa.GetCertificateStatus(ctx, core.SerialToString(parsedCert.SerialNumber))
	test.AssertNotError(t, err, "Failed to get certificate status")
	test.AssertEquals(t, len(changedStatus.OCSPResponse), 3)
}

func TestLoopTickBackoff(t *testing.T) {
	fc := clock.NewFake()
	l := looper{
		clk:                  fc,
		stats:                metrics.NewNoopScope(),
		failureBackoffFactor: 1.5,
		failureBackoffMax:    10 * time.Minute,
		tickDur:              time.Minute,
		tickFunc:             func(context.Context, int) error { return errors.New("baddie") },
	}

	start := l.clk.Now()
	l.tick()
	// Expected to sleep for 1m
	backoff := float64(60000000000)
	maxJittered := backoff * 1.2
	test.AssertBetween(t, l.clk.Now().Sub(start).Nanoseconds(), int64(backoff), int64(maxJittered))

	start = l.clk.Now()
	l.tick()
	// Expected to sleep for 1m30s
	backoff = 90000000000
	maxJittered = backoff * 1.2
	test.AssertBetween(t, l.clk.Now().Sub(start).Nanoseconds(), int64(backoff), int64(maxJittered))

	l.failures = 6
	start = l.clk.Now()
	l.tick()
	// Expected to sleep for 11m23.4375s, should be truncated to 10m
	backoff = 600000000000
	maxJittered = backoff * 1.2
	test.AssertBetween(t, l.clk.Now().Sub(start).Nanoseconds(), int64(backoff), int64(maxJittered))

	l.tickFunc = func(context.Context, int) error { return nil }
	start = l.clk.Now()
	l.tick()
	test.AssertEquals(t, l.failures, 0)
	test.AssertEquals(t, l.clk.Now(), start)
}

func TestGetSubmittedReceipts(t *testing.T) {
	updater, sa, _, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	fc.Set(parsedCert.NotBefore.Add(time.Minute))
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID, nil)
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")

	// Before adding any SCTs, there should be no receipts or errors for serial 00
	receipts, err := updater.getSubmittedReceipts("00")
	test.AssertNotError(t, err, "getSubmittedReceipts('00') failed")
	test.AssertEquals(t, len(receipts), 0)

	// Add one SCT
	sct := core.SignedCertificateTimestamp{
		SCTVersion:        0,
		LogID:             testLogAID,
		Timestamp:         0,
		Extensions:        []byte{},
		Signature:         []byte{0},
		CertificateSerial: "00",
	}
	err = sa.AddSCTReceipt(ctx, sct)
	test.AssertNotError(t, err, "Failed to AddSCTReceipt")

	// After adding one SCTs, there should be one receipt for log "test"
	receipts, err = updater.getSubmittedReceipts("00")
	test.AssertNotError(t, err, "getSubmittedReceipts('00') failed")
	test.AssertEquals(t, len(receipts), 1)
	test.AssertEquals(t, receipts[0], testLogAID)

	// Add another SCT
	sct = core.SignedCertificateTimestamp{
		SCTVersion:        0,
		LogID:             testLogBID,
		Timestamp:         0,
		Extensions:        []byte{},
		Signature:         []byte{0},
		CertificateSerial: "00",
	}
	err = sa.AddSCTReceipt(ctx, sct)
	test.AssertNotError(t, err, "Failed to AddSCTReceipt")

	// After adding a second SCTs, there should be two receipts for logs "test"
	// and "test2"
	receipts, err = updater.getSubmittedReceipts("00")
	test.AssertNotError(t, err, "getSubmittedReceipts('00') failed")
	test.AssertEquals(t, len(receipts), 2)
	test.AssertEquals(t, receipts[0], testLogAID)
	test.AssertEquals(t, receipts[1], testLogBID)
}

func TestMissingLogs(t *testing.T) {
	updater, _, _, _, cleanUp := setup(t)
	defer cleanUp()

	noLogs := []*ctLog{}
	oneLog := []*ctLog{
		&ctLog{
			uri:   "test",
			key:   testLogAPK,
			logID: testLogAID,
		},
	}
	twoLogs := []*ctLog{
		oneLog[0],
		&ctLog{
			uri:   "test2",
			key:   testLogBPK,
			logID: testLogBID,
		},
	}

	testCases := []struct {
		Logs                []*ctLog
		GivenIDs            []string
		ExpectedMissingLogs []*ctLog
	}{
		// With `nil` logs, no log IDs are ever missing
		{
			Logs:                nil,
			GivenIDs:            []string{testLogAID, testLogBID},
			ExpectedMissingLogs: []*ctLog{},
		},
		// No configured logs, no log IDs are ever missing
		{
			Logs:                noLogs,
			GivenIDs:            []string{testLogAID, testLogBID},
			ExpectedMissingLogs: []*ctLog{},
		},
		// One configured log, given no log IDs, one is missing
		{
			Logs:                oneLog,
			GivenIDs:            []string{},
			ExpectedMissingLogs: []*ctLog{oneLog[0]},
		},
		// One configured log, given `nil` log IDs, one is missing
		{
			Logs:                oneLog,
			GivenIDs:            nil,
			ExpectedMissingLogs: []*ctLog{oneLog[0]},
		},
		// One configured log, given that log ID, none are missing
		{
			Logs:                oneLog,
			GivenIDs:            []string{testLogAID},
			ExpectedMissingLogs: []*ctLog{},
		},
		// Two configured logs, given one log ID, one is missing
		{
			Logs:                twoLogs,
			GivenIDs:            []string{testLogAID},
			ExpectedMissingLogs: []*ctLog{twoLogs[1]},
		},
		// Two configured logs, given no log IDs, two are missing
		{
			Logs:                twoLogs,
			GivenIDs:            []string{},
			ExpectedMissingLogs: []*ctLog{twoLogs[0], twoLogs[1]},
		},
		// Two configured logs, given two matching log IDs, none are missing
		{
			Logs:                twoLogs,
			GivenIDs:            []string{testLogAID, testLogBID},
			ExpectedMissingLogs: []*ctLog{},
		},
		// Two configured logs, given unknown log, two are missing
		{
			Logs:                twoLogs,
			GivenIDs:            []string{"wha?"},
			ExpectedMissingLogs: []*ctLog{twoLogs[0], twoLogs[1]},
		},
		// Two configured logs, given one unknown log, one known, one is missing
		{
			Logs:                twoLogs,
			GivenIDs:            []string{"wha?", testLogBID},
			ExpectedMissingLogs: []*ctLog{twoLogs[0]},
		},
	}

	for _, tc := range testCases {
		updater.logs = tc.Logs
		missingLogs := updater.missingLogs(tc.GivenIDs)
		test.AssertEquals(t, len(missingLogs), len(tc.ExpectedMissingLogs))
		for i, expectedLog := range tc.ExpectedMissingLogs {
			test.AssertEquals(t, missingLogs[i].uri, expectedLog.uri)
			test.AssertEquals(t, missingLogs[i].key, expectedLog.key)
			test.AssertEquals(t, missingLogs[i].logID, expectedLog.logID)
		}
	}
}

func TestReverseBytes(t *testing.T) {
	a := []byte{0, 1, 2, 3}
	test.AssertDeepEquals(t, reverseBytes(a), []byte{3, 2, 1, 0})
}

func TestGenerateOCSPCacheKeys(t *testing.T) {
	der := []byte{105, 239, 255}
	test.AssertDeepEquals(
		t,
		generateOCSPCacheKeys(der, "ocsp.invalid/"),
		[]string{
			"ocsp.invalid/?body-md5=d6101198a9d9f1f6",
			"ocsp.invalid/ae/",
			"ocsp.invalid/ae%2F%2F",
		},
	)
}
