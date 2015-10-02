package main

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"
	"github.com/letsencrypt/boulder/core"

	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
)

type mockCA struct{}

func (ca *mockCA) IssueCertificate(csr x509.CertificateRequest, regID int64) (core.Certificate, error) {
	return core.Certificate{}, nil
}

func (ca *mockCA) GenerateOCSP(xferObj core.OCSPSigningRequest) (ocsp []byte, err error) {
	ocsp = []byte{1, 2, 3}
	return
}

func (ca *mockCA) RevokeCertificate(serial string, reasonCode core.RevocationCode) (err error) {
	return
}

const dbConnStr = "mysql+tcp://boulder@localhost:3306/boulder_sa_test"

func setup(t *testing.T) (OCSPUpdater, core.StorageAuthority, *gorp.DbMap, clock.FakeClock, func()) {
	dbMap, err := sa.NewDbMap(dbConnStr)
	test.AssertNotError(t, err, "Failed to create dbMap")

	fc := clock.NewFake()
	fc.Add(1 * time.Hour)

	sa, err := sa.NewSQLStorageAuthority(dbMap, fc)
	test.AssertNotError(t, err, "Failed to create SA")

	cleanUp := test.ResetTestDatabase(t, dbMap.Db)

	stats, _ := statsd.NewNoopClient(nil)

	updater := OCSPUpdater{
		dbMap: dbMap,
		clk:   fc,
		cac:   &mockCA{},
		stats: stats,
	}

	return updater, sa, dbMap, fc, cleanUp
}

func TestGenerateAndStoreOCSPResponse(t *testing.T) {
	updater, sa, dbMap, _, cleanUp := setup(t)
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
	tx, err := dbMap.Begin()
	test.AssertNotError(t, err, "Couldn't open a transaction")
	err = updater.storeResponse(tx, meta)
	test.AssertNotError(t, err, "Couldn't store OCSP response")
	err = tx.Commit()
	test.AssertNotError(t, err, "Couldn't close transaction")

	var ocspResponse core.OCSPResponse
	err = dbMap.SelectOne(
		&ocspResponse,
		"SELECT * from ocspResponses WHERE serial = :serial ORDER BY id DESC LIMIT 1;",
		map[string]interface{}{"serial": status.Serial},
	)
	test.AssertNotError(t, err, "Couldn't get OCSP response from database")
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
	updater, sa, dbMap, fc, cleanUp := setup(t)
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
	tx, err := dbMap.Begin()
	test.AssertNotError(t, err, "Couldn't open a transaction")
	err = updater.storeResponse(tx, meta)
	test.AssertNotError(t, err, "Couldn't store OCSP response")
	err = tx.Commit()
	test.AssertNotError(t, err, "Couldn't close transaction")

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
