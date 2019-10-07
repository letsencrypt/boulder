package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	akamaiProto "github.com/letsencrypt/boulder/akamai/proto"
	caPB "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/sa"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
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
		nil,
		OCSPUpdaterConfig{
			OldOCSPBatchSize: 1,
			OldOCSPWindow:    cmd.ConfigDuration{Duration: time.Second},
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
	issuer, err := core.LoadCert("../../test/test-ca2.pem")
	test.AssertNotError(t, err, "Couldn't read test issuer certificate")
	updater.issuer = issuer
	updater.purgerService = akamaiProto.NewAkamaiPurgerClient(nil)

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

	serialStr := core.SerialToString(parsedCert.SerialNumber)
	reason := int64(0)
	revokedDate := fc.Now().UnixNano()
	err = sa.RevokeCertificate(context.Background(), &sapb.RevokeCertificateRequest{
		Serial: &serialStr,
		Reason: &reason,
		Date:   &revokedDate,
	})
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

func TestGenerateOCSPResponsePrecert(t *testing.T) {
	// The schema required to insert a precertificate is only available in
	// config-next at the time of writing.
	if !strings.HasSuffix(os.Getenv("BOULDER_CONFIG_DIR"), "config-next") {
		return
	}

	updater, sa, dbMap, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)

	// Use AddPrecertificate to set up a precertificate, serials, and
	// certificateStatus row for the testcert.
	certDER, err := ioutil.ReadFile("../../test/test-ca.der")
	test.AssertNotError(t, err, "Couldn't read example cert DER")
	serial := "00000000000000000000000000000000124d"
	ocspResp := []byte{0, 0, 1}
	regID := reg.ID
	issuedTime := fc.Now().UnixNano()
	_, err = sa.AddPrecertificate(ctx, &sapb.AddCertificateRequest{
		Der:    certDER,
		RegID:  &regID,
		Ocsp:   ocspResp,
		Issued: &issuedTime,
	})
	test.AssertNotError(t, err, "Couldn't add test-cert2.der")

	// We need to set a fake "ocspLastUpdated" value for the precert we created
	// in order to satisfy the "ocspStaleMaxAge" constraint.
	fakeLastUpdate := fc.Now().Add(-time.Hour * 24 * 3)
	_, err = dbMap.Exec(
		"UPDATE certificateStatus SET ocspLastUpdated = ? WHERE serial = ?",
		fakeLastUpdate,
		serial)
	test.AssertNotError(t, err, "Couldn't update ocspLastUpdated")

	// There should be one stale ocsp response found for the precert
	earliest := fc.Now().Add(-time.Hour)
	certs, err := updater.findStaleOCSPResponses(earliest, 10)
	test.AssertNotError(t, err, "Couldn't find stale responses")
	test.AssertEquals(t, len(certs), 1)
	test.AssertEquals(t, certs[0].Serial, serial)

	// Disable PrecertificateOCSP.
	err = features.Set(map[string]bool{"PrecertificateOCSP": false})
	test.AssertNotError(t, err, "setting PrecertificateOCSP feature to off")

	// Directly call generateResponse with the result, when the PrecertificateOCSP
	// feature flag is disabled we expect this to error because no matching
	// certificates row will be found.
	updater.cac = &mockCA{time.Second}
	_, err = updater.generateResponse(ctx, certs[0])
	test.AssertError(t, err, "generateResponse for precert without PrecertificateOCSP did not error")

	// Now enable PrecertificateOCSP.
	err = features.Set(map[string]bool{"PrecertificateOCSP": true})
	test.AssertNotError(t, err, "setting PrecertificateOCSP feature to off")

	// Directly call generateResponse again with the same result. It should not
	// error and should instead update the precertificate's OCSP status even
	// though no certificate row exists.
	_, err = updater.generateResponse(ctx, certs[0])
	test.AssertNotError(t, err, "generateResponse for precert with PrecertificateOCSP errored")
}
