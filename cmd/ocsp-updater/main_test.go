package main

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"golang.org/x/net/context"

	"github.com/cactus/go-statsd-client/statsd"
	"github.com/jmhodges/clock"
	"gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
	x509csr "github.com/letsencrypt/go/src/crypto/x509"
)

var ctx = context.Background()

type mockCA struct{}

func (ca *mockCA) IssueCertificate(_ context.Context, csr x509csr.CertificateRequest, regID int64) (core.Certificate, error) {
	return core.Certificate{}, nil
}

func (ca *mockCA) GenerateOCSP(_ context.Context, xferObj core.OCSPSigningRequest) (ocsp []byte, err error) {
	ocsp = []byte{1, 2, 3}
	return
}

type mockPub struct {
	sa core.StorageAuthority
}

func (p *mockPub) SubmitToCT(_ context.Context, _ []byte) error {
	sct := core.SignedCertificateTimestamp{
		SCTVersion:        0,
		LogID:             "id",
		Timestamp:         0,
		Extensions:        []byte{},
		Signature:         []byte{0},
		CertificateSerial: "00",
	}
	err := p.sa.AddSCTReceipt(ctx, sct)
	if err != nil {
		return err
	}
	sct.LogID = "another-id"
	return p.sa.AddSCTReceipt(ctx, sct)
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

	stats, _ := statsd.NewNoopClient(nil)

	updater, err := newUpdater(
		stats,
		fc,
		dbMap,
		&mockCA{},
		&mockPub{sa},
		sa,
		cmd.OCSPUpdaterConfig{
			NewCertificateBatchSize: 1,
			OldOCSPBatchSize:        1,
			MissingSCTBatchSize:     1,
			NewCertificateWindow:    cmd.ConfigDuration{Duration: time.Second},
			OldOCSPWindow:           cmd.ConfigDuration{Duration: time.Second},
			MissingSCTWindow:        cmd.ConfigDuration{Duration: time.Second},
		},
		0,
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

	err = sa.MarkCertificateRevoked(ctx, core.SerialToString(cert.SerialNumber), core.RevocationCode(1))
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

	updater.numLogs = 1
	updater.oldestIssuedSCT = 2 * time.Hour

	serials, err := updater.getSerialsIssuedSince(fc.Now().Add(-2*time.Hour), 1)
	test.AssertNotError(t, err, "Failed to retrieve serials")
	test.AssertEquals(t, len(serials), 1)

	err = updater.missingReceiptsTick(ctx, 5)
	test.AssertNotError(t, err, "Failed to run missingReceiptsTick")

	count, err := updater.getNumberOfReceipts("00")
	test.AssertNotError(t, err, "Couldn't get number of receipts")
	test.AssertEquals(t, count, 2)

	// make sure we don't spin forever after reducing the
	// number of logs we submit to
	updater.numLogs = 1
	err = updater.missingReceiptsTick(ctx, 10)
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
	updater.numLogs = 1
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

	err = sa.MarkCertificateRevoked(ctx, core.SerialToString(parsedCert.SerialNumber), core.RevocationCode(1))
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
	stats, _ := statsd.NewNoopClient(nil)
	l := looper{
		clk:                  fc,
		stats:                stats,
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
