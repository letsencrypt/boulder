package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"

	capb "github.com/letsencrypt/boulder/ca/proto"
	corepb "github.com/letsencrypt/boulder/core/proto"
	cspb "github.com/letsencrypt/boulder/crl/storer/proto"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/revocation"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/test"
)

// revokedCertsStream is a fake grpc.ClientStreamingClient which can be
// populated with some CRL entries or an error for use as the return value of
// a faked GetRevokedCertsByShard call.
type revokedCertsStream struct {
	grpc.ClientStream
	entries []*corepb.CRLEntry
	nextIdx int
	err     error
}

func (f *revokedCertsStream) Recv() (*corepb.CRLEntry, error) {
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
// fakeGRCC to be used as the return value for calls to GetRevokedCertsByShard,
// and a fake timestamp to serve as the database's maximum notAfter value.
type fakeSAC struct {
	sapb.StorageAuthorityClient
	revokedCerts revokedCertsStream
	maxNotAfter  time.Time
	leaseError   error
}

// Return the configured stream.
func (f *fakeSAC) GetRevokedCertsByShard(ctx context.Context, req *sapb.GetRevokedCertsByShardRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[corepb.CRLEntry], error) {
	return &f.revokedCerts, nil
}

func (f *fakeSAC) LeaseCRLShard(_ context.Context, req *sapb.LeaseCRLShardRequest, _ ...grpc.CallOption) (*sapb.LeaseCRLShardResponse, error) {
	if f.leaseError != nil {
		return nil, f.leaseError
	}
	return &sapb.LeaseCRLShardResponse{IssuerNameID: req.IssuerNameID, ShardIdx: req.MinShardIdx}, nil
}

// generateCRLStream implements the streaming API returned from GenerateCRL.
//
// Specifically it implements grpc.BidiStreamingClient.
//
// If it has non-nil error fields, it returns those on Send() or Recv().
//
// When it receives a CRL entry (on Send()), it records that entry internally, JSON serialized,
// with a newline between JSON objects.
//
// When it is asked for bytes of a signed CRL (Recv()), it sends those JSON serialized contents.
//
// We use JSON instead of CRL format because we're not testing the signing and formatting done
// by the CA, just the plumbing of different components together done by the crl-updater.
type generateCRLStream struct {
	grpc.ClientStream
	chunks  [][]byte
	nextIdx int
	sendErr error
	recvErr error
}

type crlEntry struct {
	Serial    string
	Reason    int32
	RevokedAt time.Time
}

func (f *generateCRLStream) Send(req *capb.GenerateCRLRequest) error {
	if f.sendErr != nil {
		return f.sendErr
	}
	if t, ok := req.Payload.(*capb.GenerateCRLRequest_Entry); ok {
		jsonBytes, err := json.Marshal(crlEntry{
			Serial:    t.Entry.Serial,
			Reason:    t.Entry.Reason,
			RevokedAt: t.Entry.RevokedAt.AsTime(),
		})
		if err != nil {
			return err
		}
		f.chunks = append(f.chunks, jsonBytes)
		f.chunks = append(f.chunks, []byte("\n"))
	}
	return f.sendErr
}

func (f *generateCRLStream) CloseSend() error {
	return nil
}

func (f *generateCRLStream) Recv() (*capb.GenerateCRLResponse, error) {
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

// fakeCA acts as a fake CA (specifically implementing capb.CRLGeneratorClient).
//
// It always returns its field in response to `GenerateCRL`. Because this is a streaming
// RPC, that return value is responsible for most of the work.
type fakeCA struct {
	gcc generateCRLStream
}

func (f *fakeCA) GenerateCRL(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[capb.GenerateCRLRequest, capb.GenerateCRLResponse], error) {
	return &f.gcc, nil
}

// recordingUploader acts as the streaming part of UploadCRL.
//
// Records all uploaded chunks in crlBody.
type recordingUploader struct {
	grpc.ClientStream

	crlBody []byte
}

func (r *recordingUploader) Send(req *cspb.UploadCRLRequest) error {
	if t, ok := req.Payload.(*cspb.UploadCRLRequest_CrlChunk); ok {
		r.crlBody = append(r.crlBody, t.CrlChunk...)
	}
	return nil
}

func (r *recordingUploader) CloseAndRecv() (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

// noopUploader is a fake grpc.ClientStreamingClient which can be populated with
// an error for use as the return value of a faked UploadCRL call.
//
// It does nothing with uploaded contents.
type noopUploader struct {
	grpc.ClientStream
	sendErr error
	recvErr error
}

func (f *noopUploader) Send(*cspb.UploadCRLRequest) error {
	return f.sendErr
}

func (f *noopUploader) CloseAndRecv() (*emptypb.Empty, error) {
	if f.recvErr != nil {
		return nil, f.recvErr
	}
	return &emptypb.Empty{}, nil
}

// fakeStorer is a fake cspb.CRLStorerClient which can be populated with an
// uploader stream for use as the return value for calls to UploadCRL.
type fakeStorer struct {
	uploaderStream grpc.ClientStreamingClient[cspb.UploadCRLRequest, emptypb.Empty]
}

func (f *fakeStorer) UploadCRL(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[cspb.UploadCRLRequest, emptypb.Empty], error) {
	return f.uploaderStream, nil
}

func TestUpdateShard(t *testing.T) {
	e1, err := issuance.LoadCertificate("../../test/hierarchy/int-e1.cert.pem")
	test.AssertNotError(t, err, "loading test issuer")
	r3, err := issuance.LoadCertificate("../../test/hierarchy/int-r3.cert.pem")
	test.AssertNotError(t, err, "loading test issuer")

	sentinelErr := errors.New("oops")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	clk := clock.NewFake()
	clk.Set(time.Date(2020, time.January, 18, 0, 0, 0, 0, time.UTC))
	cu, err := NewUpdater(
		[]*issuance.Certificate{e1, r3},
		2,
		18*time.Hour, // shardWidth
		24*time.Hour, // lookbackPeriod
		6*time.Hour,  // updatePeriod
		time.Minute,  // updateTimeout
		1, 1,
		"stale-if-error=60",
		5*time.Minute,
		&fakeSAC{
			revokedCerts: revokedCertsStream{},
			maxNotAfter:  clk.Now().Add(90 * 24 * time.Hour),
		},
		&fakeCA{gcc: generateCRLStream{}},
		&fakeStorer{uploaderStream: &noopUploader{}},
		metrics.NoopRegisterer, blog.NewMock(), clk,
	)
	test.AssertNotError(t, err, "building test crlUpdater")

	// Ensure that getting no results from the SA still works.
	err = cu.updateShard(ctx, cu.clk.Now(), e1.NameID(), 1)
	test.AssertNotError(t, err, "empty CRL")
	test.AssertMetricWithLabelsEquals(t, cu.updatedCounter, prometheus.Labels{
		"issuer": "(TEST) Elegant Elephant E1", "result": "success",
	}, 1)

	// Make a CRL with actual contents. Verify that the information makes it through
	// each of the steps:
	//  - read from SA
	//  - write to CA and read the response
	//  - upload with CRL storer
	//
	// The final response should show up in the bytes recorded by our fake storer.
	recordingUploader := &recordingUploader{}
	now := timestamppb.Now()
	cu.cs = &fakeStorer{uploaderStream: recordingUploader}
	cu.sa = &fakeSAC{
		revokedCerts: revokedCertsStream{
			entries: []*corepb.CRLEntry{
				{
					Serial:    "0311b5d430823cfa25b0fc85d14c54ee35",
					Reason:    int32(revocation.KeyCompromise),
					RevokedAt: now,
				},
				{
					Serial:    "037d6a05a0f6a975380456ae605cee9889",
					Reason:    int32(revocation.AffiliationChanged),
					RevokedAt: now,
				},
				{
					Serial:    "03aa617ab8ee58896ba082bfa25199c884",
					Reason:    int32(revocation.Unspecified),
					RevokedAt: now,
				},
			},
		},
		maxNotAfter: clk.Now().Add(90 * 24 * time.Hour),
	}
	// We ask for shard 2 specifically because GetRevokedCertsByShard only returns our
	// certificate for that shard.
	err = cu.updateShard(ctx, cu.clk.Now(), e1.NameID(), 2)
	test.AssertNotError(t, err, "updateShard")

	expectedEntries := map[string]int32{
		"0311b5d430823cfa25b0fc85d14c54ee35": int32(revocation.KeyCompromise),
		"037d6a05a0f6a975380456ae605cee9889": int32(revocation.AffiliationChanged),
		"03aa617ab8ee58896ba082bfa25199c884": int32(revocation.Unspecified),
	}
	for r := range bytes.SplitSeq(recordingUploader.crlBody, []byte("\n")) {
		if len(r) == 0 {
			continue
		}
		var entry crlEntry
		err := json.Unmarshal(r, &entry)
		if err != nil {
			t.Fatalf("unmarshaling JSON: %s", err)
		}
		expectedReason, ok := expectedEntries[entry.Serial]
		if !ok {
			t.Errorf("CRL entry for %s was unexpected", entry.Serial)
		}
		if entry.Reason != expectedReason {
			t.Errorf("CRL entry for %s had reason=%d, want %d", entry.Serial, entry.Reason, expectedReason)
		}
		delete(expectedEntries, entry.Serial)
	}
	// At this point the expectedEntries map should be empty; if it's not, emit an error
	// for each remaining expectation.
	for k, v := range expectedEntries {
		t.Errorf("expected cert %s to be revoked for reason=%d, but it was not on the CRL", k, v)
	}

	cu.updatedCounter.Reset()

	// Ensure that getting no results from the SA still works.
	err = cu.updateShard(ctx, cu.clk.Now(), e1.NameID(), 1)
	test.AssertNotError(t, err, "empty CRL")
	test.AssertMetricWithLabelsEquals(t, cu.updatedCounter, prometheus.Labels{
		"issuer": "(TEST) Elegant Elephant E1", "result": "success",
	}, 1)
	cu.updatedCounter.Reset()

	// Errors closing the Storer upload stream should bubble up.
	cu.cs = &fakeStorer{uploaderStream: &noopUploader{recvErr: sentinelErr}}
	err = cu.updateShard(ctx, cu.clk.Now(), e1.NameID(), 1)
	test.AssertError(t, err, "storer error")
	test.AssertContains(t, err.Error(), "closing CRLStorer upload stream")
	test.AssertErrorIs(t, err, sentinelErr)
	test.AssertMetricWithLabelsEquals(t, cu.updatedCounter, prometheus.Labels{
		"issuer": "(TEST) Elegant Elephant E1", "result": "failed",
	}, 1)
	cu.updatedCounter.Reset()

	// Errors sending to the Storer should bubble up sooner.
	cu.cs = &fakeStorer{uploaderStream: &noopUploader{sendErr: sentinelErr}}
	err = cu.updateShard(ctx, cu.clk.Now(), e1.NameID(), 1)
	test.AssertError(t, err, "storer error")
	test.AssertContains(t, err.Error(), "sending CRLStorer metadata")
	test.AssertErrorIs(t, err, sentinelErr)
	test.AssertMetricWithLabelsEquals(t, cu.updatedCounter, prometheus.Labels{
		"issuer": "(TEST) Elegant Elephant E1", "result": "failed",
	}, 1)
	cu.updatedCounter.Reset()

	// Errors reading from the CA should bubble up sooner.
	cu.ca = &fakeCA{gcc: generateCRLStream{recvErr: sentinelErr}}
	err = cu.updateShard(ctx, cu.clk.Now(), e1.NameID(), 1)
	test.AssertError(t, err, "CA error")
	test.AssertContains(t, err.Error(), "receiving CRL bytes")
	test.AssertErrorIs(t, err, sentinelErr)
	test.AssertMetricWithLabelsEquals(t, cu.updatedCounter, prometheus.Labels{
		"issuer": "(TEST) Elegant Elephant E1", "result": "failed",
	}, 1)
	cu.updatedCounter.Reset()

	// Errors sending to the CA should bubble up sooner.
	cu.ca = &fakeCA{gcc: generateCRLStream{sendErr: sentinelErr}}
	err = cu.updateShard(ctx, cu.clk.Now(), e1.NameID(), 1)
	test.AssertError(t, err, "CA error")
	test.AssertContains(t, err.Error(), "sending CA metadata")
	test.AssertErrorIs(t, err, sentinelErr)
	test.AssertMetricWithLabelsEquals(t, cu.updatedCounter, prometheus.Labels{
		"issuer": "(TEST) Elegant Elephant E1", "result": "failed",
	}, 1)
	cu.updatedCounter.Reset()

	// Errors reading from the SA should bubble up soonest.
	cu.sa = &fakeSAC{revokedCerts: revokedCertsStream{err: sentinelErr}, maxNotAfter: clk.Now().Add(90 * 24 * time.Hour)}
	err = cu.updateShard(ctx, cu.clk.Now(), e1.NameID(), 1)
	test.AssertError(t, err, "database error")
	test.AssertContains(t, err.Error(), "retrieving entry from SA")
	test.AssertErrorIs(t, err, sentinelErr)
	test.AssertMetricWithLabelsEquals(t, cu.updatedCounter, prometheus.Labels{
		"issuer": "(TEST) Elegant Elephant E1", "result": "failed",
	}, 1)
	cu.updatedCounter.Reset()
}

func TestUpdateShardWithRetry(t *testing.T) {
	e1, err := issuance.LoadCertificate("../../test/hierarchy/int-e1.cert.pem")
	test.AssertNotError(t, err, "loading test issuer")
	r3, err := issuance.LoadCertificate("../../test/hierarchy/int-r3.cert.pem")
	test.AssertNotError(t, err, "loading test issuer")

	sentinelErr := errors.New("oops")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	clk := clock.NewFake()
	clk.Set(time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC))

	// Build an updater that will always fail when it talks to the SA.
	cu, err := NewUpdater(
		[]*issuance.Certificate{e1, r3},
		2, 18*time.Hour, 24*time.Hour,
		6*time.Hour, time.Minute, 1, 1,
		"stale-if-error=60",
		5*time.Minute,
		&fakeSAC{revokedCerts: revokedCertsStream{err: sentinelErr}, maxNotAfter: clk.Now().Add(90 * 24 * time.Hour)},
		&fakeCA{gcc: generateCRLStream{}},
		&fakeStorer{uploaderStream: &noopUploader{}},
		metrics.NoopRegisterer, blog.NewMock(), clk,
	)
	test.AssertNotError(t, err, "building test crlUpdater")

	// Ensure that having MaxAttempts set to 1 results in the clock not moving
	// forward at all.
	startTime := cu.clk.Now()
	err = cu.updateShardWithRetry(ctx, cu.clk.Now(), e1.NameID(), 1)
	test.AssertError(t, err, "database error")
	test.AssertErrorIs(t, err, sentinelErr)
	test.AssertEquals(t, cu.clk.Now(), startTime)

	// Ensure that having MaxAttempts set to 5 results in the clock moving forward
	// by 1+2+4+8=15 seconds. The core.RetryBackoff system has 20% jitter built
	// in, so we have to be approximate.
	cu.maxAttempts = 5
	startTime = cu.clk.Now()
	err = cu.updateShardWithRetry(ctx, cu.clk.Now(), e1.NameID(), 1)
	test.AssertError(t, err, "database error")
	test.AssertErrorIs(t, err, sentinelErr)
	t.Logf("start: %v", startTime)
	t.Logf("now: %v", cu.clk.Now())
	test.Assert(t, startTime.Add(15*0.8*time.Second).Before(cu.clk.Now()), "retries didn't sleep enough")
	test.Assert(t, startTime.Add(15*1.2*time.Second).After(cu.clk.Now()), "retries slept too much")
}
