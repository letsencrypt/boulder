package updater

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/test"
)

// countingSAC wraps fakeSAC to count LeaseCRLShard calls (so a test can observe
// that shard workers actually did work) and to implement UpdateCRLShard, which
// the full updateShardWithRetry success path calls but fakeSAC does not.
type countingSAC struct {
	*fakeSAC
	leases atomic.Int64
}

func (c *countingSAC) LeaseCRLShard(ctx context.Context, req *sapb.LeaseCRLShardRequest, opts ...grpc.CallOption) (*sapb.LeaseCRLShardResponse, error) {
	c.leases.Add(1)
	return c.fakeSAC.LeaseCRLShard(ctx, req, opts...)
}

func (c *countingSAC) UpdateCRLShard(_ context.Context, _ *sapb.UpdateCRLShardRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

// TestRun exercises the long-lived crlUpdater.Run loop inside a synctest bubble.
//
// Run starts one goroutine per shard, each of which sleeps a random fraction of
// updatePeriod and then updates its shard on every tick until the context is
// cancelled. This test verifies two things deterministically:
//
//  1. Each worker performs at least one update within the first updatePeriod
//     (advanced via the bubble's fake clock, with no real sleeping).
//  2. Cancelling the context causes Run to return promptly and every worker
//     goroutine to exit. If any worker leaked (e.g. stopped honoring
//     ctx.Done(), or left a timer/ticker goroutine alive), synctest panics when
//     the bubble's root goroutine returns with blocked goroutines remaining.
func TestRun(t *testing.T) {
	e1, err := issuance.LoadCertificate("../../test/hierarchy/int-e1.cert.pem")
	test.AssertNotError(t, err, "loading test issuer")
	r3, err := issuance.LoadCertificate("../../test/hierarchy/int-r3.cert.pem")
	test.AssertNotError(t, err, "loading test issuer")
	issuers := []*issuance.Certificate{e1, r3}

	const numShards = 2
	const updatePeriod = 6 * time.Hour
	numWorkers := int64(len(issuers) * numShards)

	sa := &countingSAC{fakeSAC: &fakeSAC{
		revokedCerts: revokedCertsStream{},
	}}

	// Build the updater outside the bubble. In particular blog.NewMock() starts
	// a long-lived background goroutine; constructing it here keeps that
	// fixture goroutine out of the bubble so synctest's leak check only judges
	// the goroutines that Run itself starts.
	cu, err := NewUpdater(
		issuers,
		numShards,
		18*time.Hour,  // shardWidth
		24*time.Hour,  // lookbackPeriod (>= 2 * updatePeriod)
		updatePeriod,  // updatePeriod
		time.Minute,   // updateTimeout (< updatePeriod)
		1,             // maxParallelism
		1,             // maxAttempts (so RetryBackoff sleeps for 0s)
		"stale-if-error=60",
		5*time.Minute, // expiresMargin
		sa,
		&fakeCA{gcc: generateCRLStream{}},
		&fakeStorer{uploaderStream: &noopUploader{}},
		// Inside a synctest bubble the real time package is faked, so the real
		// clock returned by clock.New() is driven by the bubble's fake clock. (A
		// jmhodges fake clock keeps its own timers, which the bubble cannot see,
		// so it must not be used here.)
		metrics.NoopRegisterer, blog.NewMock(), clock.New(),
	)
	test.AssertNotError(t, err, "building test crlUpdater")

	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		errCh := make(chan error, 1)
		go func() {
			errCh <- cu.Run(ctx)
		}()

		// Let every worker reach its initial randomized wait timer, then advance
		// the fake clock by a full updatePeriod. Because each worker's initial
		// wait is strictly less than updatePeriod, all of them must have woken
		// and leased their shard at least once.
		synctest.Wait()
		time.Sleep(updatePeriod)
		synctest.Wait()

		test.Assert(t, sa.leases.Load() >= numWorkers,
			"expected each shard worker to lease its shard at least once")

		// Cancel and confirm Run returns. The receive blocks (durably, in the
		// bubble) until Run's wg.Wait() observes every worker exit, so this also
		// proves there is no hung worker.
		cancel()
		err = <-errCh
		test.AssertErrorIs(t, err, context.Canceled)
	})
}
