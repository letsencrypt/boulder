package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	akamaiProto "github.com/letsencrypt/boulder/akamai/proto"
	caPB "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/db"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/sa"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
	"google.golang.org/grpc"
)

var ctx = context.Background()

type mockOCSP struct {
	sleepTime time.Duration
}

func (ca *mockOCSP) GenerateOCSP(_ context.Context, req *caPB.GenerateOCSPRequest, _ ...grpc.CallOption) (*caPB.OCSPResponse, error) {
	time.Sleep(ca.sleepTime)
	return &caPB.OCSPResponse{Response: []byte{1, 2, 3}}, nil
}

var log = blog.UseMock()

func setup(t *testing.T) (*OCSPUpdater, core.StorageAuthority, *db.WrappedMap, clock.FakeClock, func()) {
	dbMap, err := sa.NewDbMap(vars.DBConnSA, 0)
	test.AssertNotError(t, err, "Failed to create dbMap")
	sa.SetSQLDebug(dbMap, log)

	fc := clock.NewFake()
	fc.Add(1 * time.Hour)

	sa, err := sa.NewSQLStorageAuthority(dbMap, fc, log, metrics.NoopRegisterer, 1)
	test.AssertNotError(t, err, "Failed to create SA")

	cleanUp := test.ResetSATestDatabase(t)

	updater, err := newUpdater(
		metrics.NoopRegisterer,
		fc,
		dbMap,
		&mockOCSP{},
		sa,
		nil,
		OCSPUpdaterConfig{
			OldOCSPBatchSize:         1,
			OldOCSPWindow:            cmd.ConfigDuration{Duration: time.Second},
			SignFailureBackoffFactor: 1.5,
			SignFailureBackoffMax: cmd.ConfigDuration{
				Duration: time.Minute,
			},
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
	issued := fc.Now().UnixNano()
	_, err = sa.AddPrecertificate(ctx, &sapb.AddCertificateRequest{
		Der:    parsedCert.Raw,
		RegID:  &reg.ID,
		Ocsp:   nil,
		Issued: &issued,
	})
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")

	status, err := sa.GetCertificateStatus(ctx, core.SerialToString(parsedCert.SerialNumber))
	test.AssertNotError(t, err, "Couldn't get the core.CertificateStatus from the database")

	meta, err := updater.generateResponse(ctx, status)
	test.AssertNotError(t, err, "Couldn't generate OCSP response")
	err = updater.storeResponse(meta)
	test.AssertNotError(t, err, "Couldn't store certificate status")
}

func TestGenerateOCSPResponses(t *testing.T) {
	updater, sa, _, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCertA, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	issued := fc.Now().UnixNano()
	_, err = sa.AddPrecertificate(ctx, &sapb.AddCertificateRequest{
		Der:    parsedCertA.Raw,
		RegID:  &reg.ID,
		Ocsp:   nil,
		Issued: &issued,
	})
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")
	parsedCertB, err := core.LoadCert("test-cert-b.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	_, err = sa.AddPrecertificate(ctx, &sapb.AddCertificateRequest{
		Der:    parsedCertB.Raw,
		RegID:  &reg.ID,
		Ocsp:   nil,
		Issued: &issued,
	})
	test.AssertNotError(t, err, "Couldn't add test-cert-b.pem")

	// Jump time forward by 2 hours so the ocspLastUpdate value will be older than
	// the earliest lastUpdate time we care about.
	fc.Set(fc.Now().Add(2 * time.Hour))
	earliest := fc.Now().Add(-time.Hour)

	// We should have 2 stale responses now.
	statuses, err := updater.findStaleOCSPResponses(earliest, 10)
	test.AssertNotError(t, err, "Couldn't find stale responses")
	test.AssertEquals(t, len(statuses), 2)

	// Hacky test of parallelism: Make each request to the CA take 1 second, and
	// produce 2 requests to the CA. If the pair of requests complete in about a
	// second, they were made in parallel.
	// Note that this test also tests the basic functionality of
	// generateOCSPResponses.
	start := time.Now()
	updater.ogc = &mockOCSP{time.Second}
	updater.parallelGenerateOCSPRequests = 10
	err = updater.generateOCSPResponses(ctx, statuses)
	test.AssertNotError(t, err, "Couldn't generate OCSP responses")
	elapsed := time.Since(start)
	if elapsed > 1500*time.Millisecond {
		t.Errorf("generateOCSPResponses took too long, expected it to make calls in parallel.")
	}

	// generateOCSPResponses should have updated the ocspLastUpdate for each
	// cert, so there shouldn't be any stale responses anymore.
	statuses, err = updater.findStaleOCSPResponses(earliest, 10)
	test.AssertNotError(t, err, "Failed to find stale responses")
	test.AssertEquals(t, len(statuses), 0)
}

func TestFindStaleOCSPResponses(t *testing.T) {
	updater, sa, _, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	issued := fc.Now().UnixNano()
	_, err = sa.AddPrecertificate(ctx, &sapb.AddCertificateRequest{
		Der:    parsedCert.Raw,
		RegID:  &reg.ID,
		Ocsp:   nil,
		Issued: &issued,
	})
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")

	// Jump time forward by 2 hours so the ocspLastUpdate value will be older than
	// the earliest lastUpdate time we care about.
	fc.Set(fc.Now().Add(2 * time.Hour))
	earliest := fc.Now().Add(-time.Hour)

	// We should have 1 stale response now.
	statuses, err := updater.findStaleOCSPResponses(earliest, 10)
	test.AssertNotError(t, err, "Couldn't find status")
	test.AssertEquals(t, len(statuses), 1)

	status, err := sa.GetCertificateStatus(ctx, core.SerialToString(parsedCert.SerialNumber))
	test.AssertNotError(t, err, "Couldn't get the core.Certificate from the database")

	// Generate and store an updated response, which will update the
	// ocspLastUpdate field for this cert.
	meta, err := updater.generateResponse(ctx, status)
	test.AssertNotError(t, err, "Couldn't generate OCSP response")
	err = updater.storeResponse(meta)
	test.AssertNotError(t, err, "Couldn't store OCSP response")

	// We should have 0 stale responses now.
	statuses, err = updater.findStaleOCSPResponses(earliest, 10)
	test.AssertNotError(t, err, "Failed to find stale responses")
	test.AssertEquals(t, len(statuses), 0)
}

func TestFindStaleOCSPResponsesRevokedReason(t *testing.T) {
	updater, sa, dbMap, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	issued := fc.Now().UnixNano()
	_, err = sa.AddPrecertificate(ctx, &sapb.AddCertificateRequest{
		Der:    parsedCert.Raw,
		RegID:  &reg.ID,
		Ocsp:   nil,
		Issued: &issued,
	})
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")

	// Set a revokedReason to ensure it gets written into the OCSPResponse.
	_, err = dbMap.Exec(
		"UPDATE certificateStatus SET revokedReason = 1 WHERE serial = ?",
		core.SerialToString(parsedCert.SerialNumber))
	test.AssertNotError(t, err, "Couldn't update revokedReason")

	// Jump time forward by 2 hours so the ocspLastUpdate value will be older than
	// the earliest lastUpdate time we care about.
	fc.Set(fc.Now().Add(2 * time.Hour))
	earliest := fc.Now().Add(-time.Hour)

	statuses, err := updater.findStaleOCSPResponses(earliest, 10)
	test.AssertNotError(t, err, "Couldn't find status")
	test.AssertEquals(t, len(statuses), 1)
	test.AssertEquals(t, int(statuses[0].RevokedReason), 1)
}

func TestOldOCSPResponsesTick(t *testing.T) {
	updater, sa, _, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	issued := fc.Now().UnixNano()
	_, err = sa.AddPrecertificate(ctx, &sapb.AddCertificateRequest{
		Der:    parsedCert.Raw,
		RegID:  &reg.ID,
		Ocsp:   nil,
		Issued: &issued,
	})
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")

	updater.ocspMinTimeToExpiry = 1 * time.Hour
	err = updater.updateOCSPResponses(ctx, 10)
	test.AssertNotError(t, err, "Couldn't run updateOCSPResponses")

	certs, err := updater.findStaleOCSPResponses(fc.Now().Add(-updater.ocspMinTimeToExpiry), 10)
	test.AssertNotError(t, err, "Failed to find stale responses")
	test.AssertEquals(t, len(certs), 0)
}

// TestOldOCSPResponsesTickIsExpired checks that the old OCSP responses tick
// updates the `IsExpired` field opportunistically as it encounters certificates
// that are expired but whose certificate status rows do not have `IsExpired`
// set, and that expired certs don't show up as having stale responses.
func TestOldOCSPResponsesTickIsExpired(t *testing.T) {
	updater, sa, _, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	serial := core.SerialToString(parsedCert.SerialNumber)

	// Add a new test certificate
	issued := fc.Now().UnixNano()
	_, err = sa.AddPrecertificate(ctx, &sapb.AddCertificateRequest{
		Der:    parsedCert.Raw,
		RegID:  &reg.ID,
		Ocsp:   nil,
		Issued: &issued,
	})
	test.AssertNotError(t, err, "Couldn't add test-cert.pem")

	// Jump time forward by 2 hours so the ocspLastUpdate value will be older than
	// the earliest lastUpdate time we care about.
	fc.Set(fc.Now().Add(2 * time.Hour))
	earliest := fc.Now().Add(-time.Hour)

	// The certificate isn't expired, so the certificate status should have
	// a false `IsExpired` and it should show up as stale.
	cs, err := sa.GetCertificateStatus(ctx, serial)
	test.AssertNotError(t, err, fmt.Sprintf("Couldn't get certificate status for %q", serial))
	test.AssertEquals(t, cs.IsExpired, false)
	statuses, err := updater.findStaleOCSPResponses(earliest, 10)
	test.AssertNotError(t, err, "Couldn't find status")
	test.AssertEquals(t, len(statuses), 1)

	// Advance the clock to the point that the certificate we added is now expired
	fc.Set(parsedCert.NotAfter.Add(2 * time.Hour))
	earliest = fc.Now().Add(-time.Hour)

	// Run the updateOCSPResponses so that it can have a chance to find expired
	// certificates
	updater.ocspMinTimeToExpiry = 1 * time.Hour
	err = updater.updateOCSPResponses(ctx, 10)
	test.AssertNotError(t, err, "Couldn't run updateOCSPResponses")

	// Since we advanced the fakeclock beyond our test certificate's NotAfter we
	// expect the certificate status has been updated to have a true `IsExpired`
	cs, err = sa.GetCertificateStatus(ctx, serial)
	test.AssertNotError(t, err, fmt.Sprintf("Couldn't get certificate status for %q", serial))
	test.AssertEquals(t, cs.IsExpired, true)
	statuses, err = updater.findStaleOCSPResponses(earliest, 10)
	test.AssertNotError(t, err, "Couldn't find status")
	test.AssertEquals(t, len(statuses), 0)
}

func TestStoreResponseGuard(t *testing.T) {
	updater, sa, _, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)
	parsedCert, err := core.LoadCert("test-cert.pem")
	test.AssertNotError(t, err, "Couldn't read test certificate")
	issued := fc.Now().UnixNano()
	_, err = sa.AddPrecertificate(ctx, &sapb.AddCertificateRequest{
		Der:    parsedCert.Raw,
		RegID:  &reg.ID,
		Ocsp:   nil,
		Issued: &issued,
	})
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

func TestGenerateOCSPResponsePrecert(t *testing.T) {
	updater, sa, _, fc, cleanUp := setup(t)
	defer cleanUp()

	reg := satest.CreateWorkingRegistration(t, sa)

	// Create a throw-away self signed certificate with some names
	serial, testCert := test.ThrowAwayCert(t, 5)

	// Use AddPrecertificate to set up a precertificate, serials, and
	// certificateStatus row for the testcert.
	ocspResp := []byte{0, 0, 1}
	regID := reg.ID
	issuedTime := fc.Now().UnixNano()
	_, err := sa.AddPrecertificate(ctx, &sapb.AddCertificateRequest{
		Der:    testCert.Raw,
		RegID:  &regID,
		Ocsp:   ocspResp,
		Issued: &issuedTime,
	})
	test.AssertNotError(t, err, "Couldn't add test-cert2.der")

	// Jump time forward by 2 hours so the ocspLastUpdate value will be older than
	// the earliest lastUpdate time we care about.
	fc.Set(fc.Now().Add(2 * time.Hour))
	earliest := fc.Now().Add(-time.Hour)

	// There should be one stale ocsp response found for the precert
	certs, err := updater.findStaleOCSPResponses(earliest, 10)
	test.AssertNotError(t, err, "Couldn't find stale responses")
	test.AssertEquals(t, len(certs), 1)
	test.AssertEquals(t, certs[0].Serial, serial)

	// Directly call generateResponse again with the same result. It should not
	// error and should instead update the precertificate's OCSP status even
	// though no certificate row exists.
	_, err = updater.generateResponse(ctx, certs[0])
	test.AssertNotError(t, err, "generateResponse for precert errored")
}

type mockOCSPRecordIssuer struct {
	gotIssuer bool
}

func (ca *mockOCSPRecordIssuer) GenerateOCSP(_ context.Context, req *caPB.GenerateOCSPRequest, _ ...grpc.CallOption) (*caPB.OCSPResponse, error) {
	ca.gotIssuer = req.IssuerID != nil && req.Serial != nil
	return &caPB.OCSPResponse{Response: []byte{1, 2, 3}}, nil
}

func TestIssuerInfo(t *testing.T) {
	updater, sa, _, fc, cleanUp := setup(t)
	defer cleanUp()
	m := mockOCSPRecordIssuer{}
	updater.ogc = &m
	reg := satest.CreateWorkingRegistration(t, sa)
	_ = features.Set(map[string]bool{"StoreIssuerInfo": true})

	k, err := rsa.GenerateKey(rand.Reader, 512)
	test.AssertNotError(t, err, "rsa.GenerateKey failed")
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"example.com"},
	}
	certA, err := x509.CreateCertificate(rand.Reader, template, template, &k.PublicKey, k)
	test.AssertNotError(t, err, "x509.CreateCertificate failed")
	template.SerialNumber = big.NewInt(2)
	certB, err := x509.CreateCertificate(rand.Reader, template, template, &k.PublicKey, k)
	test.AssertNotError(t, err, "x509.CreateCertificate failed")

	now := fc.Now().UnixNano()
	id := int64(1234)
	_, err = sa.AddPrecertificate(context.Background(), &sapb.AddCertificateRequest{
		Der:      certA,
		RegID:    &reg.ID,
		Ocsp:     []byte{1, 2, 3},
		Issued:   &now,
		IssuerID: &id,
	})
	test.AssertNotError(t, err, "sa.AddPrecertificate failed")
	_, err = sa.AddPrecertificate(context.Background(), &sapb.AddCertificateRequest{
		Der:    certB,
		RegID:  &reg.ID,
		Ocsp:   []byte{1, 2, 3},
		Issued: &now,
	})
	test.AssertNotError(t, err, "sa.AddPrecertificate failed")

	fc.Add(time.Hour * 24 * 4)
	statuses, err := updater.findStaleOCSPResponses(fc.Now().Add(-time.Hour), 10)
	test.AssertNotError(t, err, "findStaleOCSPResponses failed")
	test.AssertEquals(t, len(statuses), 2)
	test.AssertEquals(t, *statuses[0].IssuerID, id)
	test.Assert(t, statuses[1].IssuerID == nil, "second status doesn't have nil IssuerID")

	_, err = updater.generateResponse(context.Background(), statuses[0])
	test.AssertNotError(t, err, "generateResponse failed")
	test.Assert(t, m.gotIssuer, "generateResponse didn't send issuer information and serial")
	_, err = updater.generateResponse(context.Background(), statuses[1])
	test.AssertNotError(t, err, "generateResponse failed")
	test.Assert(t, !m.gotIssuer, "generateResponse did send issuer information and serial when it shouldn't")
}

type brokenDB struct{}

func (bdb *brokenDB) Select(i interface{}, query string, args ...interface{}) ([]interface{}, error) {
	return nil, errors.New("broken")
}
func (bdb *brokenDB) SelectOne(holder interface{}, query string, args ...interface{}) error {
	return errors.New("broken")
}
func (bdb *brokenDB) Exec(query string, args ...interface{}) (sql.Result, error) {
	return nil, errors.New("broken")
}

func TestTickSleep(t *testing.T) {
	updater, _, dbMap, fc, cleanUp := setup(t)
	defer cleanUp()
	m := &brokenDB{}
	updater.dbMap = m

	// Test when updateOCSPResponses fails the failure counter is incremented
	// and the clock moved forward by more than updater.tickWindow
	updater.tickFailures = 2
	before := fc.Now()
	updater.tick()
	test.AssertEquals(t, updater.tickFailures, 3)
	took := fc.Since(before)
	test.Assert(t, took > updater.tickWindow, "Clock didn't move forward enough")

	// Test when updateOCSPResponses works the failure counter is reset to zero
	// and the clock only moves by updater.tickWindow
	updater.dbMap = dbMap
	before = fc.Now()
	updater.tick()
	test.AssertEquals(t, updater.tickFailures, 0)
	took = fc.Since(before)
	test.AssertEquals(t, took, updater.tickWindow)

}
