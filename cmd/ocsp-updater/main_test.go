package main

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/akamai"
	caPB "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/revocation"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
	"golang.org/x/net/context"
	"gopkg.in/go-gorp/gorp.v2"
)

var ctx = context.Background()

type mockCA struct {
	sleepTime time.Duration
}

func (ca *mockCA) IssueCertificate(_ context.Context, _ *caPB.IssueCertificateRequest) (core.Certificate, error) {
	return core.Certificate{}, nil
}

func (ca *mockCA) IssuePrecertificate(_ context.Context, _ *caPB.IssueCertificateRequest) (*caPB.IssuePrecertificateResponse, error) {
	return nil, errors.New("IssuePrecertificate is not implemented by mockCA")
}

func (ca *mockCA) IssueCertificateForPrecertificate(_ context.Context, _ *caPB.IssueCertificateForPrecertificateRequest) (core.Certificate, error) {
	return core.Certificate{}, errors.New("IssueCertificateForPrecertificate is not implemented by mockCA")
}

func (ca *mockCA) GenerateOCSP(_ context.Context, xferObj core.OCSPSigningRequest) (ocsp []byte, err error) {
	ocsp = []byte{1, 2, 3}
	time.Sleep(ca.sleepTime)
	return
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

	sa, err := sa.NewSQLStorageAuthority(dbMap, fc, log, metrics.NewNoopScope(), 1)
	test.AssertNotError(t, err, "Failed to create SA")

	cleanUp := test.ResetSATestDatabase(t)

	updater, err := newUpdater(
		metrics.NewNoopScope(),
		fc,
		dbMap,
		&mockCA{},
		sa,
		cmd.OCSPUpdaterConfig{
			NewCertificateBatchSize:     1,
			OldOCSPBatchSize:            1,
			MissingSCTBatchSize:         1,
			RevokedCertificateBatchSize: 1,
			NewCertificateWindow:        cmd.ConfigDuration{Duration: time.Second},
			OldOCSPWindow:               cmd.ConfigDuration{Duration: time.Second},
			MissingSCTWindow:            cmd.ConfigDuration{Duration: time.Second},
			RevokedCertificateWindow:    cmd.ConfigDuration{Duration: time.Second},
		},
		"",
		blog.NewMock(),
	)
	test.AssertNotError(t, err, "Failed to create newUpdater")

	return updater, sa, dbMap, fc, cleanUp
}

func TestGenerateAndStoreOCSPResponse(t *testing.T) {
	updater, sa, _, fc, cleanUp := setup(t)
	defer cleanUp()
	updater.ccu = &akamai.CachePurgeClient{}
	issuer, err := core.LoadCert("../../test/test-ca2.pem")
	test.AssertNotError(t, err, "Couldn't read test issuer certificate")
	updater.issuer = issuer

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	issued := fc.Now()
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID, nil, &issued)
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")

	status, err := sa.GetCertificateStatus(ctx, core.SerialToString(parsedCert.SerialNumber))
	test.AssertNotError(t, err, "Couldn't get the core.CertificateStatus from the database")

	meta, err := updater.generateResponse(ctx, status)
	test.AssertNotError(t, err, "Couldn't generate OCSP response")
	err = updater.storeResponse(meta)
	test.AssertNotError(t, err, "Couldn't store certificate status")

	secondMeta, purgeURLs, err := updater.generateRevokedResponse(ctx, status)
	test.AssertNotError(t, err, "Couldn't generate revoked OCSP response")
	err = updater.storeResponse(secondMeta)
	test.AssertNotError(t, err, "Couldn't store certificate status")
	test.AssertDeepEquals(t, purgeURLs, []string{
		// akamai magic POST format
		"http://127.0.0.1:4002/?body-md5=1f00f751a981b76c",
		// GET format with // replaced with /
		"http://127.0.0.1:4002/MFQwUjBQME4wTDAJBgUrDgMCGgUABBRBJaTET3lGgf1uVfnmEsA5Rr8viQQU+3hPEvlgFYMsnxd/NBmzLjbqQYkCEwD/ajxemKXeOt+gQo15uy0YcQs=",
		// GET format with url-encoding
		"http://127.0.0.1:4002/MFQwUjBQME4wTDAJBgUrDgMCGgUABBRBJaTET3lGgf1uVfnmEsA5Rr8viQQU%2B3hPEvlgFYMsnxd%2FNBmzLjbqQYkCEwD%2FajxemKXeOt%2BgQo15uy0YcQs%3D",
	})

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
	issued := fc.Now()
	_, err = sa.AddCertificate(ctx, parsedCertA.Raw, reg.ID, nil, &issued)
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")
	parsedCertB, err := core.LoadCert("test-cert-b.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	_, err = sa.AddCertificate(ctx, parsedCertB.Raw, reg.ID, nil, &issued)
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
	issued := fc.Now()
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID, nil, &issued)
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
	issued := fc.Now()
	_, err = sa.AddCertificate(ctx, parsedCertA.Raw, reg.ID, nil, &issued)
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")
	parsedCertB, err := core.LoadCert("test-cert-b.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	_, err = sa.AddCertificate(ctx, parsedCertB.Raw, reg.ID, nil, &issued)
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
	updater, sa, _, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	cert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	issued := fc.Now()
	_, err = sa.AddCertificate(ctx, cert.Raw, reg.ID, nil, &issued)
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")

	statuses, err := updater.getCertificatesWithMissingResponses(10)
	test.AssertNotError(t, err, "Couldn't get status")
	test.AssertEquals(t, len(statuses), 1)
}

func TestFindRevokedCertificatesToUpdate(t *testing.T) {
	updater, sa, _, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	cert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	issued := fc.Now()
	_, err = sa.AddCertificate(ctx, cert.Raw, reg.ID, nil, &issued)
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
	issued := fc.Now()
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID, nil, &issued)
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
	issued := fc.Now()
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID, nil, &issued)
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
	issued := fc.Now()
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID, nil, &issued)
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

func TestRevokedCertificatesTick(t *testing.T) {
	updater, sa, _, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	issued := fc.Now()
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID, nil, &issued)
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
	updater, sa, _, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	issued := fc.Now()
	_, err = sa.AddCertificate(ctx, parsedCert.Raw, reg.ID, nil, &issued)
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

	assertBetween := func(a, b, c int64) {
		t.Helper()
		if a < b || a > c {
			t.Fatalf("%d is not between %d and %d", a, b, c)
		}
	}
	start := l.clk.Now()
	l.tick()
	// Expected to sleep for 1m
	backoff := float64(60000000000)
	assertBetween(l.clk.Now().Sub(start).Nanoseconds(), int64(backoff*0.8), int64(backoff*1.2))

	start = l.clk.Now()
	l.tick()
	// Expected to sleep for 1m30s
	backoff = 90000000000
	assertBetween(l.clk.Now().Sub(start).Nanoseconds(), int64(backoff*0.8), int64(backoff*1.2))

	l.failures = 6
	start = l.clk.Now()
	l.tick()
	// Expected to sleep for 11m23.4375s, should be truncated to 10m
	backoff = 600000000000
	assertBetween(l.clk.Now().Sub(start).Nanoseconds(), int64(backoff*0.8), int64(backoff*1.2))

	l.tickFunc = func(context.Context, int) error { return nil }
	start = l.clk.Now()
	l.tick()
	test.AssertEquals(t, l.failures, 0)
	test.AssertEquals(t, l.clk.Now(), start)
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
