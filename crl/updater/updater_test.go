package updater

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/jmhodges/clock"
	capb "github.com/letsencrypt/boulder/ca/proto"
	corepb "github.com/letsencrypt/boulder/core/proto"
	cspb "github.com/letsencrypt/boulder/crl/storer/proto"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/mocks"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/test"
	"github.com/prometheus/client_golang/prometheus"
)

// fakeGRCC is a fake sapb.StorageAuthority_GetRevokedCertsClient which can be
// populated with some CRL entries or an error for use as the return value of
// a faked GetRevokedCerts call.
type fakeGRCC struct {
	grpc.ClientStream
	entries []*corepb.CRLEntry
	nextIdx int
	err     error
}

func (f *fakeGRCC) Recv() (*corepb.CRLEntry, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.nextIdx < len(f.entries) {
		res := f.entries[f.nextIdx]
		f.nextIdx++
		return res, nil
	}
	return nil, io.EOF
}

// fakeSAC is a fake sapb.StorageAuthorityClient which can be populated with a
// fakeGRCC to be used as the return value for calls to GetRevokedCerts.
type fakeSAC struct {
	mocks.StorageAuthority
	grcc fakeGRCC
}

func (f *fakeSAC) GetRevokedCerts(ctx context.Context, _ *sapb.GetRevokedCertsRequest, _ ...grpc.CallOption) (sapb.StorageAuthority_GetRevokedCertsClient, error) {
	return &f.grcc, nil
}

// fakeGCC is a fake capb.CRLGenerator_GenerateCRLClient which can be
// populated with some CRL entries or an error for use as the return value of
// a faked GenerateCRL call.
type fakeGCC struct {
	grpc.ClientStream
	chunks  [][]byte
	nextIdx int
	sendErr error
	recvErr error
}

func (f *fakeGCC) Send(*capb.GenerateCRLRequest) error {
	return f.sendErr
}

func (f *fakeGCC) CloseSend() error {
	return nil
}

func (f *fakeGCC) Recv() (*capb.GenerateCRLResponse, error) {
	if f.recvErr != nil {
		return nil, f.recvErr
	}
	if f.nextIdx < len(f.chunks) {
		res := f.chunks[f.nextIdx]
		f.nextIdx++
		return &capb.GenerateCRLResponse{Chunk: res}, nil
	}
	return nil, io.EOF
}

// fakeCGC is a fake capb.CRLGeneratorClient which can be populated with a
// fakeGCC to be used as the return value for calls to GenerateCRL.
type fakeCGC struct {
	gcc fakeGCC
}

func (f *fakeCGC) GenerateCRL(ctx context.Context, opts ...grpc.CallOption) (capb.CRLGenerator_GenerateCRLClient, error) {
	return &f.gcc, nil
}

// fakeUCC is a fake cspb.CRLStorer_UploadCRLClient which can be populated with
// an error for use as the return value of a faked UploadCRL call.
type fakeUCC struct {
	grpc.ClientStream
	sendErr error
	recvErr error
}

func (f *fakeUCC) Send(*cspb.UploadCRLRequest) error {
	return f.sendErr
}

func (f *fakeUCC) CloseAndRecv() (*emptypb.Empty, error) {
	if f.recvErr != nil {
		return nil, f.recvErr
	}
	return &emptypb.Empty{}, nil
}

// fakeCSC is a fake cspb.CRLStorerClient which can be populated with a
// fakeUCC for use as the return value for calls to UploadCRL.
type fakeCSC struct {
	ucc fakeUCC
}

func (f *fakeCSC) UploadCRL(ctx context.Context, opts ...grpc.CallOption) (cspb.CRLStorer_UploadCRLClient, error) {
	return &f.ucc, nil
}

func TestTickShard(t *testing.T) {
	e1, err := issuance.LoadCertificate("../../test/hierarchy/int-e1.cert.pem")
	test.AssertNotError(t, err, "loading test issuer")
	r3, err := issuance.LoadCertificate("../../test/hierarchy/int-r3.cert.pem")
	test.AssertNotError(t, err, "loading test issuer")

	sentinelErr := errors.New("oops")

	cu, err := NewUpdater(
		[]*issuance.Certificate{e1, r3}, 2, 10*24*time.Hour, 24*time.Hour, 0, 1,
		&fakeSAC{grcc: fakeGRCC{}},
		&fakeCGC{gcc: fakeGCC{}},
		&fakeCSC{ucc: fakeUCC{}},
		metrics.NoopRegisterer, blog.NewMock(), clock.NewFake(),
	)
	test.AssertNotError(t, err, "building test crlUpdater")

	// Ensure that getting no results from the SA still works.
	err = cu.tickShard(context.Background(), cu.clk.Now(), e1.NameID(), 0)
	test.AssertNotError(t, err, "empty CRL")
	test.AssertMetricWithLabelsEquals(t, cu.updatedCounter, prometheus.Labels{
		"issuer": "(TEST) Elegant Elephant E1", "result": "success",
	}, 1)
	cu.updatedCounter.Reset()

	// Errors closing the Storer upload stream should bubble up.
	cu.cs = &fakeCSC{ucc: fakeUCC{recvErr: sentinelErr}}
	err = cu.tickShard(context.Background(), cu.clk.Now(), e1.NameID(), 0)
	test.AssertError(t, err, "storer error")
	test.AssertContains(t, err.Error(), "closing CRLStorer upload stream")
	test.AssertErrorIs(t, err, sentinelErr)
	test.AssertMetricWithLabelsEquals(t, cu.updatedCounter, prometheus.Labels{
		"issuer": "(TEST) Elegant Elephant E1", "result": "failed",
	}, 1)
	cu.updatedCounter.Reset()

	// Errors sending to the Storer should bubble up sooner.
	cu.cs = &fakeCSC{ucc: fakeUCC{sendErr: sentinelErr}}
	err = cu.tickShard(context.Background(), cu.clk.Now(), e1.NameID(), 0)
	test.AssertError(t, err, "storer error")
	test.AssertContains(t, err.Error(), "sending CRLStorer metadata")
	test.AssertErrorIs(t, err, sentinelErr)
	test.AssertMetricWithLabelsEquals(t, cu.updatedCounter, prometheus.Labels{
		"issuer": "(TEST) Elegant Elephant E1", "result": "failed",
	}, 1)
	cu.updatedCounter.Reset()

	// Errors reading from the CA should bubble up sooner.
	cu.ca = &fakeCGC{gcc: fakeGCC{recvErr: sentinelErr}}
	err = cu.tickShard(context.Background(), cu.clk.Now(), e1.NameID(), 0)
	test.AssertError(t, err, "CA error")
	test.AssertContains(t, err.Error(), "receiving CRL bytes")
	test.AssertErrorIs(t, err, sentinelErr)
	test.AssertMetricWithLabelsEquals(t, cu.updatedCounter, prometheus.Labels{
		"issuer": "(TEST) Elegant Elephant E1", "result": "failed",
	}, 1)
	cu.updatedCounter.Reset()

	// Errors sending to the CA should bubble up sooner.
	cu.ca = &fakeCGC{gcc: fakeGCC{sendErr: sentinelErr}}
	err = cu.tickShard(context.Background(), cu.clk.Now(), e1.NameID(), 0)
	test.AssertError(t, err, "CA error")
	test.AssertContains(t, err.Error(), "sending CA metadata")
	test.AssertErrorIs(t, err, sentinelErr)
	test.AssertMetricWithLabelsEquals(t, cu.updatedCounter, prometheus.Labels{
		"issuer": "(TEST) Elegant Elephant E1", "result": "failed",
	}, 1)
	cu.updatedCounter.Reset()

	// Errors reading from the SA should bubble up soonest.
	cu.sa = &fakeSAC{grcc: fakeGRCC{err: sentinelErr}}
	err = cu.tickShard(context.Background(), cu.clk.Now(), e1.NameID(), 0)
	test.AssertError(t, err, "database error")
	test.AssertContains(t, err.Error(), "retrieving entry from SA")
	test.AssertErrorIs(t, err, sentinelErr)
	test.AssertMetricWithLabelsEquals(t, cu.updatedCounter, prometheus.Labels{
		"issuer": "(TEST) Elegant Elephant E1", "result": "failed",
	}, 1)
	cu.updatedCounter.Reset()
}

func TestTickIssuer(t *testing.T) {
	e1, err := issuance.LoadCertificate("../../test/hierarchy/int-e1.cert.pem")
	test.AssertNotError(t, err, "loading test issuer")
	r3, err := issuance.LoadCertificate("../../test/hierarchy/int-r3.cert.pem")
	test.AssertNotError(t, err, "loading test issuer")

	mockLog := blog.NewMock()
	cu, err := NewUpdater(
		[]*issuance.Certificate{e1, r3}, 2, 10*24*time.Hour, 24*time.Hour, 0, 1,
		&fakeSAC{grcc: fakeGRCC{err: errors.New("db no worky")}},
		&fakeCGC{gcc: fakeGCC{}},
		&fakeCSC{ucc: fakeUCC{}},
		metrics.NoopRegisterer, mockLog, clock.NewFake(),
	)
	test.AssertNotError(t, err, "building test crlUpdater")

	// An error that affects all shards should have every shard reflected in the
	// combined error message.
	err = cu.tickIssuer(context.Background(), cu.clk.Now(), e1.NameID())
	test.AssertError(t, err, "database error")
	test.AssertContains(t, err.Error(), "2 shards failed")
	test.AssertContains(t, err.Error(), "[0 1]")
	test.AssertEquals(t, len(mockLog.GetAllMatching("Generating CRL failed:")), 2)
	test.AssertMetricWithLabelsEquals(t, cu.tickHistogram, prometheus.Labels{
		"issuer": "(TEST) Elegant Elephant E1", "result": "failed",
	}, 2)
	test.AssertMetricWithLabelsEquals(t, cu.tickHistogram, prometheus.Labels{
		"issuer": "(TEST) Elegant Elephant E1 (Overall)", "result": "failed",
	}, 1)
	cu.tickHistogram.Reset()
}

func TestTick(t *testing.T) {
	e1, err := issuance.LoadCertificate("../../test/hierarchy/int-e1.cert.pem")
	test.AssertNotError(t, err, "loading test issuer")
	r3, err := issuance.LoadCertificate("../../test/hierarchy/int-r3.cert.pem")
	test.AssertNotError(t, err, "loading test issuer")

	mockLog := blog.NewMock()
	cu, err := NewUpdater(
		[]*issuance.Certificate{e1, r3}, 2, 10*24*time.Hour, 24*time.Hour, 0, 1,
		&fakeSAC{grcc: fakeGRCC{err: errors.New("db no worky")}},
		&fakeCGC{gcc: fakeGCC{}},
		&fakeCSC{ucc: fakeUCC{}},
		metrics.NoopRegisterer, mockLog, clock.NewFake(),
	)
	test.AssertNotError(t, err, "building test crlUpdater")

	// An error that affects all issuers should have every issuer reflected in the
	// combined error message.
	now := cu.clk.Now()
	err = cu.Tick(context.Background(), now)
	test.AssertError(t, err, "database error")
	test.AssertContains(t, err.Error(), "2 issuers failed")
	test.AssertContains(t, err.Error(), "(TEST) Elegant Elephant E1")
	test.AssertContains(t, err.Error(), "(TEST) Radical Rhino R3")
	test.AssertEquals(t, len(mockLog.GetAllMatching("Generating CRL failed:")), 4)
	test.AssertEquals(t, len(mockLog.GetAllMatching("Generating CRLs for issuer failed:")), 2)
	test.AssertMetricWithLabelsEquals(t, cu.tickHistogram, prometheus.Labels{
		"issuer": "(TEST) Elegant Elephant E1 (Overall)", "result": "failed",
	}, 1)
	test.AssertMetricWithLabelsEquals(t, cu.tickHistogram, prometheus.Labels{
		"issuer": "(TEST) Radical Rhino R3 (Overall)", "result": "failed",
	}, 1)
	test.AssertMetricWithLabelsEquals(t, cu.tickHistogram, prometheus.Labels{
		"issuer": "all", "result": "failed",
	}, 1)
	cu.tickHistogram.Reset()
}

func TestGetWindowForShard(t *testing.T) {
	// Our test updater divides a 107-day window into 107 shards, resulting in a
	// shard width of 24 hours.
	tcu := crlUpdater{
		numShards:         107,
		lookbackPeriod:    7 * 24 * time.Hour,
		lookforwardPeriod: 100 * 24 * time.Hour,
	}
	zeroTime := time.Time{}

	// At just a moment past the 0 time, the zeroth shard should start at time 0,
	// and end exactly one day later.
	start, end := tcu.getShardBoundaries(zeroTime.Add(time.Minute), 0)
	test.Assert(t, start.IsZero(), "start time should be zero")
	test.AssertEquals(t, end, zeroTime.Add(24*time.Hour))

	// At the same moment, the 93rd shard should start 93 days later.
	start, end = tcu.getShardBoundaries(zeroTime.Add(time.Minute), 93)
	test.AssertEquals(t, start, zeroTime.Add(93*24*time.Hour))
	test.AssertEquals(t, end, zeroTime.Add(94*24*time.Hour))

	// If we jump 100 days into the future, now the 0th shard should start 107
	// days after the zero time.
	start, end = tcu.getShardBoundaries(zeroTime.Add(100*24*time.Hour+time.Minute), 0)
	test.AssertEquals(t, start, zeroTime.Add(107*24*time.Hour))
	test.AssertEquals(t, end, zeroTime.Add(108*24*time.Hour))

	// During day 100, the 93rd shard should still start at the same time (just
	// over 7 days ago), because we haven't fully left it behind yet. The 92nd
	// shard, however, should have jumped into the future.
	start, end = tcu.getShardBoundaries(zeroTime.Add(100*24*time.Hour+time.Minute), 93)
	test.AssertEquals(t, start, zeroTime.Add(93*24*time.Hour))
	test.AssertEquals(t, end, zeroTime.Add(94*24*time.Hour))
	start, end = tcu.getShardBoundaries(zeroTime.Add(100*24*time.Hour+time.Minute), 92)
	test.AssertEquals(t, start, zeroTime.Add(199*24*time.Hour))
	test.AssertEquals(t, end, zeroTime.Add(200*24*time.Hour))
}
