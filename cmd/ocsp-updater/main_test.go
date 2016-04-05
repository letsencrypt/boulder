package main

import (
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
)

type mockCA struct{}

func (ca *mockCA) IssueCertificate(csr x509.CertificateRequest, regID int64) (core.Certificate, error) {
	return core.Certificate{}, nil
}

func (ca *mockCA) GenerateOCSP(xferObj core.OCSPSigningRequest) (ocsp []byte, err error) {
	ocsp = []byte{1, 2, 3}
	return
}

type mockPub struct {
	sa core.StorageAuthority
}

func (p *mockPub) SubmitToCT(_ []byte) error {
	sct := core.SignedCertificateTimestamp{
		SCTVersion:        0,
		LogID:             "id",
		Timestamp:         0,
		Extensions:        []byte{},
		Signature:         []byte{0},
		CertificateSerial: "00",
	}
	err := p.sa.AddSCTReceipt(sct)
	if err != nil {
		return err
	}
	sct.LogID = "another-id"
	return p.sa.AddSCTReceipt(sct)
}

var log = mocks.UseMockLog()

func setup(t *testing.T) (*OCSPUpdater, core.StorageAuthority, *gorp.DbMap, clock.FakeClock, func()) {
	dbMap, err := sa.NewDbMap(vars.DBConnSA)
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
	)

	return updater, sa, dbMap, fc, cleanUp
}

func TestGenerateAndStoreOCSPResponse(t *testing.T) {
	updater, sa, _, _, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	_, err = sa.AddCertificate(parsedCert.Raw, reg.ID)
	test.AssertNotError(t, err, "Couldn't add www.eff.org.der")

	status, err := sa.GetCertificateStatus(core.SerialToString(parsedCert.SerialNumber))
	test.AssertNotError(t, err, "Couldn't get the core.CertificateStatus from the database")

	meta, err := updater.generateResponse(status)
	test.AssertNotError(t, err, "Couldn't generate OCSP response")
	err = updater.storeResponse(meta)
	test.AssertNotError(t, err, "Couldn't store certificate status")

	secondMeta, err := updater.generateRevokedResponse(status)
	test.AssertNotError(t, err, "Couldn't generate revoked OCSP response")
	err = updater.storeResponse(secondMeta)
	test.AssertNotError(t, err, "Couldn't store certificate status")

	newStatus, err := sa.GetCertificateStatus(status.Serial)
	test.AssertNotError(t, err, "Couldn't retrieve certificate status")
	test.AssertByteEquals(t, meta.OCSPResponse, newStatus.OCSPResponse)
}

func TestGenerateOCSPResponses(t *testing.T) {
	updater, sa, _, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	_, err = sa.AddCertificate(parsedCert.Raw, reg.ID)
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")
	parsedCert, err = core.LoadCert("test-cert-b.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	_, err = sa.AddCertificate(parsedCert.Raw, reg.ID)
	test.AssertNotError(t, err, "Couldn't add test-cert-b.pem")

	earliest := fc.Now().Add(-time.Hour)
	certs, err := updater.findStaleOCSPResponses(earliest, 10)
	test.AssertNotError(t, err, "Couldn't find stale responses")
	test.AssertEquals(t, len(certs), 2)

	updater.generateOCSPResponses(certs)

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
	_, err = sa.AddCertificate(parsedCert.Raw, reg.ID)
	test.AssertNotError(t, err, "Couldn't add www.eff.org.der")

	earliest := fc.Now().Add(-time.Hour)
	certs, err := updater.findStaleOCSPResponses(earliest, 10)
	test.AssertNotError(t, err, "Couldn't find certificate")
	test.AssertEquals(t, len(certs), 1)

	status, err := sa.GetCertificateStatus(core.SerialToString(parsedCert.SerialNumber))
	test.AssertNotError(t, err, "Couldn't get the core.Certificate from the database")

	meta, err := updater.generateResponse(status)
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
	_, err = sa.AddCertificate(cert.Raw, reg.ID)
	test.AssertNotError(t, err, "Couldn't add www.eff.org.der")

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
	_, err = sa.AddCertificate(cert.Raw, reg.ID)
	test.AssertNotError(t, err, "Couldn't add www.eff.org.der")

	statuses, err := updater.findRevokedCertificatesToUpdate(10)
	test.AssertNotError(t, err, "Failed to find revoked certificates")
	test.AssertEquals(t, len(statuses), 0)

	err = sa.MarkCertificateRevoked(core.SerialToString(cert.SerialNumber), core.RevocationCode(1))
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
	_, err = sa.AddCertificate(parsedCert.Raw, reg.ID)
	test.AssertNotError(t, err, "Couldn't add www.eff.org.der")

	prev := fc.Now().Add(-time.Hour)
	updater.newCertificateTick(10)

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
	_, err = sa.AddCertificate(parsedCert.Raw, reg.ID)
	test.AssertNotError(t, err, "Couldn't add www.eff.org.der")

	updater.ocspMinTimeToExpiry = 1 * time.Hour
	updater.oldOCSPResponsesTick(10)

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
	_, err = sa.AddCertificate(parsedCert.Raw, reg.ID)
	test.AssertNotError(t, err, "Couldn't add www.eff.org.der")

	updater.numLogs = 1
	updater.oldestIssuedSCT = 2 * time.Hour

	serials, err := updater.getSerialsIssuedSince(fc.Now().Add(-2*time.Hour), 1)
	test.AssertNotError(t, err, "Failed to retrieve serials")
	test.AssertEquals(t, len(serials), 1)

	updater.missingReceiptsTick(5)

	count, err := updater.getNumberOfReceipts("00")
	test.AssertNotError(t, err, "Couldn't get number of receipts")
	test.AssertEquals(t, count, 2)

	// make sure we don't spin forever after reducing the
	// number of logs we submit to
	updater.numLogs = 1
	updater.missingReceiptsTick(10)
}

func TestRevokedCertificatesTick(t *testing.T) {
	updater, sa, _, _, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	_, err = sa.AddCertificate(parsedCert.Raw, reg.ID)
	test.AssertNotError(t, err, "Couldn't add www.eff.org.der")

	err = sa.MarkCertificateRevoked(core.SerialToString(parsedCert.SerialNumber), core.RevocationCode(1))
	test.AssertNotError(t, err, "Failed to revoke certificate")

	statuses, err := updater.findRevokedCertificatesToUpdate(10)
	test.AssertNotError(t, err, "Failed to find revoked certificates")
	test.AssertEquals(t, len(statuses), 1)

	updater.revokedCertificatesTick(10)

	status, err := sa.GetCertificateStatus(core.SerialToString(parsedCert.SerialNumber))
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
	_, err = sa.AddCertificate(parsedCert.Raw, reg.ID)
	test.AssertNotError(t, err, "Couldn't add www.eff.org.der")

	status, err := sa.GetCertificateStatus(core.SerialToString(parsedCert.SerialNumber))
	test.AssertNotError(t, err, "Failed to get certificate status")

	err = sa.MarkCertificateRevoked(core.SerialToString(parsedCert.SerialNumber), 0)
	test.AssertNotError(t, err, "Failed to revoked certificate")

	// Attempt to update OCSP response where status.Status is good but stored status
	// is revoked, this should fail silently
	status.OCSPResponse = []byte{0, 1, 1}
	err = updater.storeResponse(&status)
	test.AssertNotError(t, err, "Failed to update certificate status")

	// Make sure the OCSP response hasn't actually changed
	unchangedStatus, err := sa.GetCertificateStatus(core.SerialToString(parsedCert.SerialNumber))
	test.AssertNotError(t, err, "Failed to get certificate status")
	test.AssertEquals(t, len(unchangedStatus.OCSPResponse), 0)

	// Changing the status to the stored status should allow the update to occur
	status.Status = core.OCSPStatusRevoked
	err = updater.storeResponse(&status)
	test.AssertNotError(t, err, "Failed to updated certificate status")

	// Make sure the OCSP response has been updated
	changedStatus, err := sa.GetCertificateStatus(core.SerialToString(parsedCert.SerialNumber))
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
		tickFunc:             func(_ int) error { return errors.New("baddie") },
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

	l.tickFunc = func(_ int) error { return nil }
	start = l.clk.Now()
	l.tick()
	test.AssertEquals(t, l.failures, 0)
	test.AssertEquals(t, l.clk.Now(), start)
}
