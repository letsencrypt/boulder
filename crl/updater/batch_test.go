package updater

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	sapb "github.com/letsencrypt/boulder/sa/proto"
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
	cu, err := NewUpdater(
		[]*issuance.Certificate{e1, r3},
		2, 18*time.Hour, 24*time.Hour,
		6*time.Hour, time.Minute, 1, 1,
		"stale-if-error=60",
		5*time.Minute,
		&fakeSAC{revokedCerts: revokedCertsStream{err: errors.New("db no worky")}, maxNotAfter: clk.Now().Add(90 * 24 * time.Hour)},
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

// blockingSAC is a fake StorageAuthorityClient whose LeaseCRLShard signals once
// a worker has entered the shard-update path and then blocks until its context
// is cancelled, simulating a slow RPC.
type blockingSAC struct {
	*fakeSAC
	leaseStarted chan struct{}
	once         sync.Once
}

func (b *blockingSAC) LeaseCRLShard(ctx context.Context, _ *sapb.LeaseCRLShardRequest, _ ...grpc.CallOption) (*sapb.LeaseCRLShardResponse, error) {
	b.once.Do(func() { close(b.leaseStarted) })
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestRunOnceContextCancellation exercises RunOnce's context-cancellation
// branch, where the dispatcher is blocked handing work to a busy worker when
// the context is cancelled. The existing TestRunOnce only covers normal
// completion (it never cancels), so this guards the close(inputs) + wg.Wait()
// unwind path: a worker that failed to honor cancellation would leave RunOnce
// hung in wg.Wait(), which the timeout below would catch.
func TestRunOnceContextCancellation(t *testing.T) {
	e1, err := issuance.LoadCertificate("../../test/hierarchy/int-e1.cert.pem")
	test.AssertNotError(t, err, "loading test issuer")
	r3, err := issuance.LoadCertificate("../../test/hierarchy/int-r3.cert.pem")
	test.AssertNotError(t, err, "loading test issuer")

	sa := &blockingSAC{
		fakeSAC:      &fakeSAC{},
		leaseStarted: make(chan struct{}),
	}

	// Use a real clock so the per-attempt deadline that updateShardWithRetry
	// derives from clk.Now() lies in the future. A fake clock pinned to 2020
	// would make every derived context already-expired, so the worker would
	// never actually block waiting for our cancellation.
	cu, err := NewUpdater(
		[]*issuance.Certificate{e1, r3},
		2, 18*time.Hour, 24*time.Hour,
		6*time.Hour, time.Minute, // updatePeriod, updateTimeout
		1, 1, // maxParallelism (single worker), maxAttempts
		"stale-if-error=60",
		5*time.Minute,
		sa,
		&fakeCA{gcc: generateCRLStream{}},
		&fakeStorer{uploaderStream: &noopUploader{}},
		metrics.NoopRegisterer, blog.NewMock(), clock.New(),
	)
	test.AssertNotError(t, err, "building test crlUpdater")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- cu.RunOnce(ctx)
	}()

	// Wait until the single worker is busy inside a shard update. With one
	// worker and four shards queued on an unbuffered channel, the dispatcher is
	// now blocked trying to hand off the next work item.
	<-sa.leaseStarted

	// Cancel mid-dispatch and confirm RunOnce unwinds cleanly: the dispatcher
	// takes its ctx.Done() branch, closes the input channel, and wg.Wait()
	// returns once the worker observes cancellation.
	cancel()

	select {
	case err = <-errCh:
		test.AssertErrorIs(t, err, context.Canceled)
	case <-time.After(10 * time.Second):
		t.Fatal("RunOnce did not return within 10s of context cancellation; a worker likely leaked")
	}
}
