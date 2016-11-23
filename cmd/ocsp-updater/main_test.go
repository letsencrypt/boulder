package main

import (
	"crypto/x509"
	"database/sql"
	"errors"
	"testing"
	"time"

	"golang.org/x/net/context"

	"github.com/golang/mock/gomock"
	"github.com/jmhodges/clock"
	"gopkg.in/gorp.v1"

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

type mockCA struct{}

func (ca *mockCA) IssueCertificate(_ context.Context, csr x509.CertificateRequest, regID int64) (core.Certificate, error) {
	return core.Certificate{}, nil
}

func (ca *mockCA) GenerateOCSP(_ context.Context, xferObj core.OCSPSigningRequest) (ocsp []byte, err error) {
	ocsp = []byte{1, 2, 3}
	return
}

type mockPub struct {
	sa   core.StorageAuthority
	logs []cmd.LogDescription
}

func (p *mockPub) SubmitToCT(_ context.Context, _ []byte) error {
	// Add an SCT for every configured log
	for _, log := range p.logs {
		sct := core.SignedCertificateTimestamp{
			SCTVersion:        0,
			LogID:             log.Key,
			Timestamp:         0,
			Extensions:        []byte{},
			Signature:         []byte{0},
			CertificateSerial: "00",
		}
		err := p.sa.AddSCTReceipt(ctx, sct)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *mockPub) SubmitToSingleCT(_ context.Context, logID string, _ []byte) error {
	// Add an SCT for the provided log ID
	sct := core.SignedCertificateTimestamp{
		SCTVersion:        0,
		LogID:             logID,
		Timestamp:         0,
		Extensions:        []byte{},
		Signature:         []byte{0},
		CertificateSerial: "00",
	}
	err := p.sa.AddSCTReceipt(ctx, sct)
	return err
}

var log = blog.UseMock()

func setup(t *testing.T) (*OCSPUpdater, core.StorageAuthority, *gorp.DbMap, clock.FakeClock, func()) {
	dbMap, err := sa.NewDbMap(vars.DBConnSA, 0)
	test.AssertNotError(t, err, "Failed to create dbMap")
	sa.SetSQLDebug(dbMap, log)

	fc := clock.NewFake()
	fc.Add(1 * time.Hour)

	sa, err := sa.NewSQLStorageAuthority(dbMap, fc, log)
	test.AssertNotError(t, err, "Failed to create SA")

	cleanUp := test.ResetSATestDatabase(t)

	logs := []cmd.LogDescription{
		cmd.LogDescription{
			URI: "test",
			Key: "test",
		},
		cmd.LogDescription{
			URI: "test2",
			Key: "test2",
		},
		cmd.LogDescription{
			URI: "test3",
			Key: "test3",
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

	return updater, sa, dbMap, fc, cleanUp
}

func TestGenerateAndStoreOCSPResponse(t *testing.T) {
	updater, sa, _, _, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID)
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
	updater, sa, _, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID)
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")
	parsedCert, err = core.LoadCert("test-cert-b.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID)
	test.AssertNotError(t, err, "Couldn't add test-cert-b.pem")

	earliest := fc.Now().Add(-time.Hour)
	certs, err := updater.findStaleOCSPResponses(earliest, 10)
	test.AssertNotError(t, err, "Couldn't find stale responses")
	test.AssertEquals(t, len(certs), 2)

	err = updater.generateOCSPResponses(ctx, certs)
	test.AssertNotError(t, err, "Couldn't generate OCSP responses")

	certs, err = updater.findStaleOCSPResponses(earliest, 10)
	test.AssertNotError(t, err, "Failed to find stale responses")
	test.AssertEquals(t, len(certs), 0)
}

func TestFindStaleOCSPResponses(t *testing.T) {
	updater, sa, _, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID)
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")

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

func TestGetCertificatesWithMissingResponses(t *testing.T) {
	updater, sa, _, _, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	cert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	_, err = sa.AddCertificate(ctx, cert.Raw, reg.ID)
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
	_, err = sa.AddCertificate(ctx, cert.Raw, reg.ID)
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
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID)
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
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID)
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")

	updater.ocspMinTimeToExpiry = 1 * time.Hour
	err = updater.oldOCSPResponsesTick(ctx, 10)
	test.AssertNotError(t, err, "Couldn't run oldOCSPResponsesTick")

	certs, err := updater.findStaleOCSPResponses(fc.Now().Add(-updater.ocspMinTimeToExpiry), 10)
	test.AssertNotError(t, err, "Failed to find stale responses")
	test.AssertEquals(t, len(certs), 0)
}

func TestMissingReceiptsTick(t *testing.T) {
	updater, sa, _, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	fc.Set(parsedCert.NotBefore.Add(time.Minute))
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID)
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
	test.AssertEquals(t, logIDs[0], "test")
	test.AssertEquals(t, logIDs[1], "test2")
	test.AssertEquals(t, logIDs[2], "test3")

	// make sure we don't spin forever after reducing the
	// number of logs we submit to
	updater.logs = []cmd.LogDescription{
		cmd.LogDescription{
			URI: "test",
			Key: "test",
		},
	}
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
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID)
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
		LogID:             "test2",
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
	mockPub.EXPECT().SubmitToSingleCT(ctx, "test", parsedCert.Raw)
	mockPub.EXPECT().SubmitToSingleCT(ctx, "test3", parsedCert.Raw)

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
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID)
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
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID)
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
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID)
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")

	// Before adding any SCTs, there should be no receipts or errors for serial 00
	receipts, err := updater.getSubmittedReceipts("00")
	test.AssertNotError(t, err, "getSubmittedReceipts('00') failed")
	test.AssertEquals(t, len(receipts), 0)

	// Add one SCT
	sct := core.SignedCertificateTimestamp{
		SCTVersion:        0,
		LogID:             "test",
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
	test.AssertEquals(t, receipts[0], "test")

	// Add another SCT
	sct = core.SignedCertificateTimestamp{
		SCTVersion:        0,
		LogID:             "test2",
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
	test.AssertEquals(t, receipts[0], "test")
	test.AssertEquals(t, receipts[1], "test2")
}

func TestMissingLogIDs(t *testing.T) {
	updater, _, _, _, cleanUp := setup(t)
	defer cleanUp()

	noLogs := []cmd.LogDescription{}
	oneLog := []cmd.LogDescription{
		cmd.LogDescription{
			URI: "test",
			Key: "test",
		},
	}
	twoLogs := []cmd.LogDescription{
		oneLog[0],
		cmd.LogDescription{
			URI: "test2",
			Key: "test2",
		},
	}

	testCases := []struct {
		Logs               []cmd.LogDescription
		GivenIDs           []string
		ExpectedMissingIDs []string
	}{
		// No configured logs, no log IDs are ever missing
		{
			Logs:               noLogs,
			GivenIDs:           []string{"test", "test2"},
			ExpectedMissingIDs: []string{},
		},
		// One configured log, given that log ID, none are missing
		{
			Logs:               oneLog,
			GivenIDs:           []string{"test"},
			ExpectedMissingIDs: []string{},
		},
		// One configured log, given no log IDs, one is missing
		{
			Logs:               oneLog,
			GivenIDs:           []string{},
			ExpectedMissingIDs: []string{"test"},
		},
		// Two configured logs, given one log ID, one is missing
		{
			Logs:               twoLogs,
			GivenIDs:           []string{"test"},
			ExpectedMissingIDs: []string{"test2"},
		},
		// Two configured logs, given no log IDs, two are missing
		{
			Logs:               twoLogs,
			GivenIDs:           []string{},
			ExpectedMissingIDs: []string{"test", "test2"},
		},
		// Two configured logs, given two matching log IDs, none are missing
		{
			Logs:               twoLogs,
			GivenIDs:           []string{"test", "test2"},
			ExpectedMissingIDs: []string{},
		},
		// Two configured logs, given unknown log, two are missing
		{
			Logs:               twoLogs,
			GivenIDs:           []string{"wha?"},
			ExpectedMissingIDs: []string{"test", "test2"},
		},
		// Two configured logs, given one unknown log, one known, one is missing
		{
			Logs:               twoLogs,
			GivenIDs:           []string{"wha?", "test2"},
			ExpectedMissingIDs: []string{"test"},
		},
	}

	for _, tc := range testCases {
		updater.logs = tc.Logs
		missingIDs := updater.missingLogIDs(tc.GivenIDs)
		test.AssertEquals(t, len(missingIDs), len(tc.ExpectedMissingIDs))
		for i, expectedID := range tc.ExpectedMissingIDs {
			test.AssertEquals(t, missingIDs[i], expectedID)
		}
	}
}
