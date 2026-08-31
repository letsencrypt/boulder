package updater

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
)

func TestRunOnce(t *testing.T) {
	e1, err := issuance.LoadCertificate("../../test/hierarchy/int-e1.cert.pem")
	test.AssertNotError(t, err, "loading test issuer")
	r3, err := issuance.LoadCertificate("../../test/hierarchy/int-r3.cert.pem")
	test.AssertNotError(t, err, "loading test issuer")

	mockLog := blog.NewMock()
	clk := clock.NewFake()
	clk.Set(time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC))
	fsa := &fakeSAC{revokedCerts: revokedCertsStream{err: errors.New("db no worky")}, maxNotAfter: clk.Now().Add(90 * 24 * time.Hour)}
	cu, err := NewUpdater(
		[]*issuance.Certificate{e1, r3},
		2, 18*time.Hour, 24*time.Hour, 0,
		6*time.Hour, time.Minute, 1, 1,
		"stale-if-error=60",
		5*time.Minute,
		true, fsa,
		&fakeCA{gcc: generateCRLStream{}},
		&fakeStorer{uploaderStream: &noopUploader{}},
		metrics.NoopRegisterer, mockLog, clk,
	)
	test.AssertNotError(t, err, "building test crlUpdater")

	// An error that affects all issuers should have every issuer reflected in the
	// combined error message.
	err = cu.RunOnce(context.Background())
	test.AssertError(t, err, "database error")
	test.AssertContains(t, err.Error(), "one or more errors")
	test.AssertEquals(t, len(mockLog.GetAllMatching("Generating CRL failed")), 4)
	cu.tickHistogram.Reset()
}

func TestRunOnceLagFactor(t *testing.T) {
	e1, err := issuance.LoadCertificate("../../test/hierarchy/int-e1.cert.pem")
	test.AssertNotError(t, err, "loading test issuer")

	clk := clock.NewFake()
	clk.Set(time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC))
	fsa := &fakeSAC{revokedCerts: revokedCertsStream{}, maxNotAfter: clk.Now().Add(90 * 24 * time.Hour)}
	cu, err := NewUpdater(
		[]*issuance.Certificate{e1},
		1, 18*time.Hour, 24*time.Hour, 5*time.Minute,
		6*time.Hour, time.Minute, 1, 1,
		"stale-if-error=60",
		5*time.Minute,
		true, fsa,
		&fakeCA{gcc: generateCRLStream{}},
		&fakeStorer{uploaderStream: &noopUploader{}},
		metrics.NoopRegisterer, blog.NewMock(), clk,
	)
	test.AssertNotError(t, err, "building test crlUpdater")

	// The freshness check's revocation cutoff is lagFactor earlier than the
	// CRL's thisUpdate.
	err = cu.RunOnce(context.Background())
	test.AssertNotError(t, err, "running updater")
	test.AssertEquals(t, len(fsa.latestReqs), 1)
	test.Assert(t, fsa.latestReqs[0].RevokedBefore.AsTime().Equal(clk.Now().Add(-5*time.Minute)), "freshness check's cutoff should be lagFactor earlier than the CRL's")
}

func TestRunOnceNewIssuer(t *testing.T) {
	e1, err := issuance.LoadCertificate("../../test/hierarchy/int-e1.cert.pem")
	test.AssertNotError(t, err, "loading test issuer")

	clk := clock.NewFake()
	clk.Set(time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC))
	uploader := &recordingUploader{}
	// The zero-value fakeSAC streams no revoked certs and returns NotFound
	// from GetLatestRevokedCertByShard.
	fsa := &fakeSAC{}
	cu, err := NewUpdater(
		[]*issuance.Certificate{e1},
		1, 18*time.Hour, 24*time.Hour, 5*time.Minute,
		6*time.Hour, time.Minute, 1, 1,
		"stale-if-error=60",
		5*time.Minute,
		true, fsa,
		&fakeCA{gcc: generateCRLStream{}},
		&fakeStorer{uploaderStream: uploader},
		metrics.NoopRegisterer, blog.NewMock(), clk,
	)
	test.AssertNotError(t, err, "building test crlUpdater")

	err = cu.RunOnce(context.Background())
	test.AssertNotError(t, err, "new issuer with no revocations must still publish CRLs")
	test.AssertEquals(t, uploader.number, clk.Now().UnixNano())
}
