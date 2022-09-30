package updater

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"

	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/crl"
	cspb "github.com/letsencrypt/boulder/crl/storer/proto"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

type crlUpdater struct {
	issuers           map[issuance.IssuerNameID]*issuance.Certificate
	numShards         int
	lookbackPeriod    time.Duration
	lookforwardPeriod time.Duration
	updatePeriod      time.Duration
	updateOffset      time.Duration
	maxParallelism    int

	sa sapb.StorageAuthorityClient
	ca capb.CRLGeneratorClient
	cs cspb.CRLStorerClient

	tickHistogram  *prometheus.HistogramVec
	updatedCounter *prometheus.CounterVec

	log blog.Logger
	clk clock.Clock
}

func NewUpdater(
	issuers []*issuance.Certificate,
	numShards int,
	certLifetime time.Duration,
	updatePeriod time.Duration,
	updateOffset time.Duration,
	maxParallelism int,
	sa sapb.StorageAuthorityClient,
	ca capb.CRLGeneratorClient,
	cs cspb.CRLStorerClient,
	stats prometheus.Registerer,
	log blog.Logger,
	clk clock.Clock,
) (*crlUpdater, error) {
	issuersByNameID := make(map[issuance.IssuerNameID]*issuance.Certificate, len(issuers))
	for _, issuer := range issuers {
		issuersByNameID[issuer.NameID()] = issuer
	}

	if numShards < 1 {
		return nil, fmt.Errorf("must have positive number of shards, got: %d", numShards)
	}

	if updatePeriod >= 7*24*time.Hour {
		return nil, fmt.Errorf("must update CRLs at least every 7 days, got: %s", updatePeriod)
	}

	if updateOffset >= updatePeriod {
		return nil, fmt.Errorf("update offset must be less than period: %s !< %s", updateOffset, updatePeriod)
	}

	// Set the lookback period to be significantly greater than the update period.
	// This guarantees that a certificate which was revoked very shortly before it
	// expired will still appear on at least one CRL, as required by RFC 5280
	// Section 3.3.
	lookbackPeriod := 4 * updatePeriod

	// Set the lookforward period to be greater than the lifetime of the longest
	// currently-valid certificate. Ensure it overshoots by more than the width
	// of one shard. See comment on getShardBoundaries for details.
	tentativeShardWidth := (lookbackPeriod + certLifetime).Nanoseconds() / int64(numShards)
	lookforwardPeriod := certLifetime + time.Duration(4*tentativeShardWidth)

	// Ensure that the total window (lookback + lookforward) is evenly divisible
	// by the number of shards, to make shard boundary calculations easy.
	window := lookbackPeriod + lookforwardPeriod
	offset := window.Nanoseconds() % int64(numShards)
	if offset != 0 {
		lookforwardPeriod += time.Duration(int64(numShards) - offset)
	}

	if maxParallelism <= 0 {
		maxParallelism = 1
	}

	tickHistogram := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "crl_updater_ticks",
		Help:    "A histogram of crl-updater tick latencies labeled by issuer and result",
		Buckets: []float64{0.01, 0.2, 0.5, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000},
	}, []string{"issuer", "result"})
	stats.MustRegister(tickHistogram)

	updatedCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "crl_updater_generated",
		Help: "A counter of CRL generation calls labeled by result",
	}, []string{"issuer", "result"})
	stats.MustRegister(updatedCounter)

	return &crlUpdater{
		issuersByNameID,
		numShards,
		lookbackPeriod,
		lookforwardPeriod,
		updatePeriod,
		updateOffset,
		maxParallelism,
		sa,
		ca,
		cs,
		tickHistogram,
		updatedCounter,
		log,
		clk,
	}, nil
}

// Run causes the crlUpdater to enter its processing loop. It waits until the
// next scheduled run time based on the current time and the updateOffset, then
// begins running once every updatePeriod.
func (cu *crlUpdater) Run(ctx context.Context) error {
	// We don't want the times at which crlUpdater runs to be dependent on when
	// the process starts. So wait until the appropriate time before kicking off
	// the first run and the main ticker loop.
	currOffset := cu.clk.Now().UnixNano() % cu.updatePeriod.Nanoseconds()
	var waitNanos int64
	if currOffset <= cu.updateOffset.Nanoseconds() {
		waitNanos = cu.updateOffset.Nanoseconds() - currOffset
	} else {
		waitNanos = cu.updatePeriod.Nanoseconds() - currOffset + cu.updateOffset.Nanoseconds()
	}
	cu.log.Infof("Running, next tick in %ds", waitNanos*int64(time.Nanosecond)/int64(time.Second))
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Duration(waitNanos)):
	}

	// Tick once immediately, but create the ticker first so that it starts
	// counting from the appropriate time.
	ticker := time.NewTicker(cu.updatePeriod)
	cu.Tick(ctx, cu.clk.Now())

	for {
		// If we have overrun *and* been canceled, both of the below cases could be
		// selectable at the same time, so check for context cancellation first.
		if ctx.Err() != nil {
			ticker.Stop()
			return ctx.Err()
		}
		select {
		case <-ticker.C:
			atTime := cu.clk.Now()
			err := cu.Tick(ctx, atTime)
			if err != nil {
				// We only log, rather than return, so that the long-lived process can
				// continue and try again at the next tick.
				cu.log.AuditErrf(
					"Generating CRLs failed: number=[%d] err=[%s]",
					crl.Number(atTime), err)
			}
		case <-ctx.Done():
			ticker.Stop()
			return ctx.Err()
		}
	}
}

// Tick runs the entire update process once immediately. It processes each
// configured issuer serially, and processes all of them even if an early one
// encounters an error. All errors encountered are returned as a single combined
// error at the end.
func (cu *crlUpdater) Tick(ctx context.Context, atTime time.Time) (err error) {
	defer func() {
		// This func closes over the named return value `err`, so can reference it.
		result := "success"
		if err != nil {
			result = "failed"
		}
		cu.tickHistogram.WithLabelValues("all", result).Observe(cu.clk.Since(atTime).Seconds())
	}()
	cu.log.Debugf("Ticking at time %s", atTime)

	var errIssuers []string
	for id := range cu.issuers {
		// For now, process each issuer serially. This keeps the worker pool system
		// simple, and processing all of the issuers in parallel likely wouldn't
		// meaningfully speed up the overall process.
		err := cu.tickIssuer(ctx, atTime, id)
		if err != nil {
			cu.log.AuditErrf(
				"Generating CRLs for issuer failed: number=[%d] issuer=[%s] err=[%s]",
				crl.Number(atTime), cu.issuers[id].Subject.CommonName, err)
			errIssuers = append(errIssuers, cu.issuers[id].Subject.CommonName)
		}
	}

	if len(errIssuers) != 0 {
		return fmt.Errorf("%d issuers failed: %v", len(errIssuers), strings.Join(errIssuers, ", "))
	}
	return nil
}

// tickIssuer performs the full CRL issuance cycle for a single issuer cert. It
// processes all of the shards of this issuer's CRL concurrently, and processes
// all of them even if an early one encounters an error. All errors encountered
// are returned as a single combined error at the end.
func (cu *crlUpdater) tickIssuer(ctx context.Context, atTime time.Time, issuerNameID issuance.IssuerNameID) (err error) {
	start := cu.clk.Now()
	defer func() {
		// This func closes over the named return value `err`, so can reference it.
		result := "success"
		if err != nil {
			result = "failed"
		}
		cu.tickHistogram.WithLabelValues(cu.issuers[issuerNameID].Subject.CommonName+" (Overall)", result).Observe(cu.clk.Since(start).Seconds())
	}()
	cu.log.Debugf("Ticking issuer %d at time %s", issuerNameID, atTime)

	type shardResult struct {
		shardIdx int
		err      error
	}

	shardWorker := func(in <-chan int, out chan<- shardResult) {
		for idx := range in {
			select {
			case <-ctx.Done():
				return
			default:
				out <- shardResult{
					shardIdx: idx,
					err:      cu.tickShard(ctx, atTime, issuerNameID, idx),
				}
			}
		}
	}

	shardIdxs := make(chan int, cu.numShards)
	shardResults := make(chan shardResult, cu.numShards)
	for i := 0; i < cu.maxParallelism; i++ {
		go shardWorker(shardIdxs, shardResults)
	}

	for shardIdx := 0; shardIdx < cu.numShards; shardIdx++ {
		shardIdxs <- shardIdx
	}
	close(shardIdxs)

	var errShards []int
	for i := 0; i < cu.numShards; i++ {
		res := <-shardResults
		if res.err != nil {
			cu.log.AuditErrf(
				"Generating CRL failed: id=[%s] err=[%s]",
				crl.Id(issuerNameID, crl.Number(atTime), res.shardIdx), res.err)
			errShards = append(errShards, res.shardIdx)
		}
	}

	if len(errShards) != 0 {
		sort.Ints(errShards)
		return fmt.Errorf("%d shards failed: %v", len(errShards), errShards)
	}
	return nil
}

// tickShard processes a single shard. It computes the shard's boundaries, gets
// the list of revoked certs in that shard from the SA, gets the CA to sign the
// resulting CRL, and gets the crl-storer to upload it. It returns an error if
// any of these operations fail.
func (cu *crlUpdater) tickShard(ctx context.Context, atTime time.Time, issuerNameID issuance.IssuerNameID, shardIdx int) (err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	crlID := crl.Id(issuerNameID, crl.Number(atTime), shardIdx)

	start := cu.clk.Now()
	defer func() {
		// This func closes over the named return value `err`, so can reference it.
		result := "success"
		if err != nil {
			result = "failed"
		}
		cu.tickHistogram.WithLabelValues(cu.issuers[issuerNameID].Subject.CommonName, result).Observe(cu.clk.Since(start).Seconds())
		cu.updatedCounter.WithLabelValues(cu.issuers[issuerNameID].Subject.CommonName, result).Inc()
	}()

	expiresAfter, expiresBefore := cu.getShardBoundaries(atTime, shardIdx)
	cu.log.Infof(
		"Generating CRL shard: id=[%s] expiresAfter=[%s] expiresBefore=[%s]",
		crlID, expiresAfter, expiresBefore)

	// Get the full list of CRL Entries for this shard from the SA.
	saStream, err := cu.sa.GetRevokedCerts(ctx, &sapb.GetRevokedCertsRequest{
		IssuerNameID:  int64(issuerNameID),
		ExpiresAfter:  expiresAfter.UnixNano(),
		ExpiresBefore: expiresBefore.UnixNano(),
		RevokedBefore: atTime.UnixNano(),
	})
	if err != nil {
		return fmt.Errorf("connecting to SA: %w", err)
	}

	var crlEntries []*proto.CRLEntry
	for {
		entry, err := saStream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("retrieving entry from SA: %w", err)
		}
		crlEntries = append(crlEntries, entry)
	}

	cu.log.Infof("Queried SA for CRL shard: id=[%s] numEntries=[%s]")

	// Send the full list of CRL Entries to the CA.
	caStream, err := cu.ca.GenerateCRL(ctx)
	if err != nil {
		return fmt.Errorf("connecting to CA: %w", err)
	}

	err = caStream.Send(&capb.GenerateCRLRequest{
		Payload: &capb.GenerateCRLRequest_Metadata{
			Metadata: &capb.CRLMetadata{
				IssuerNameID: int64(issuerNameID),
				ThisUpdate:   atTime.UnixNano(),
				ShardIdx:     int64(shardIdx),
			},
		},
	})
	if err != nil {
		return fmt.Errorf("sending CA metadata: %w", err)
	}

	for _, entry := range crlEntries {
		err = caStream.Send(&capb.GenerateCRLRequest{
			Payload: &capb.GenerateCRLRequest_Entry{
				Entry: entry,
			},
		})
		if err != nil {
			return fmt.Errorf("sending entry to CA: %w", err)
		}
	}

	err = caStream.CloseSend()
	if err != nil {
		return fmt.Errorf("closing CA request stream: %w", err)
	}

	// Receive the full bytes of the signed CRL from the CA.
	crlLen := 0
	crlHash := sha256.New()
	var crlChunks [][]byte
	for {
		out, err := caStream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("receiving CRL bytes: %w", err)
		}

		crlLen += len(out.Chunk)
		crlHash.Write(out.Chunk)
		crlChunks = append(crlChunks, out.Chunk)
	}

	// Send the full bytes of the signed CRL to the Storer.
	csStream, err := cu.cs.UploadCRL(ctx)
	if err != nil {
		return fmt.Errorf("connecting to CRLStorer: %w", err)
	}

	err = csStream.Send(&cspb.UploadCRLRequest{
		Payload: &cspb.UploadCRLRequest_Metadata{
			Metadata: &cspb.CRLMetadata{
				IssuerNameID: int64(issuerNameID),
				Number:       atTime.UnixNano(),
				ShardIdx:     int64(shardIdx),
			},
		},
	})
	if err != nil {
		return fmt.Errorf("sending CRLStorer metadata: %w", err)
	}

	for _, chunk := range crlChunks {
		err = csStream.Send(&cspb.UploadCRLRequest{
			Payload: &cspb.UploadCRLRequest_CrlChunk{
				CrlChunk: chunk,
			},
		})
		if err != nil {
			return fmt.Errorf("uploading CRL bytes: %w", err)
		}
	}

	_, err = csStream.CloseAndRecv()
	if err != nil {
		return fmt.Errorf("closing CRLStorer upload stream: %w", err)
	}

	cu.log.Infof(
		"Generated CRL shard: id=[%s] size=[%d] hash=[%x]",
		crlID, crlLen, crlHash.Sum(nil))
	return nil
}

// getShardBoundaries computes the start (inclusive) and end (exclusive) times
// for a given integer-indexed CRL shard. The idea here is that shards should be
// stable. Picture a timeline, divided into chunks. Number those chunks from 0
// to cu.numShards, then repeat the cycle when you run out of numbers:
//
//	   chunk:  5     0     1     2     3     4     5     0     1     2     3
//	...-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----...
//	                         ^  ^-atTime                         ^
//	   atTime-lookbackPeriod-┘          atTime+lookforwardPeriod-┘
//
// The width of each chunk is determined by dividing the total time window we
// care about (lookbackPeriod+lookforwardPeriod) by the number of shards we
// want (numShards).
//
// Even as "now" (atTime) moves forward, and the total window of expiration
// times that we care about moves forward, the boundaries of each chunk remain
// stable:
//
//	   chunk:  5     0     1     2     3     4     5     0     1     2     3
//	...-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----...
//	                                 ^  ^-atTime                         ^
//	           atTime-lookbackPeriod-┘          atTime+lookforwardPeriod-┘
//
// However, note that at essentially all times the window includes parts of two
// different instances of the chunk which appears at its ends. For example,
// in the second diagram above, the window includes almost all of the middle
// chunk labeled "3", but also includes just a little bit of the rightmost chunk
// also labeled "3".
//
// In order to handle this case, this function always treats the *leftmost*
// (i.e. earliest) chunk with the given ID that has *any* overlap with the
// current window as the current shard. It returns the boundaries of this chunk
// as the boundaries of the desired shard. In the diagram below, even though
// there is another chunk with ID "1" near the right-hand edge of the window,
// that chunk is ignored.
//
//	   shard:           |  1  |  2  |  3  |  4  |  5  |  0  |
//	...-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----...
//	                         ^  ^-atTime                         ^
//	   atTime-lookbackPeriod-┘          atTime+lookforwardPeriod-┘
//
// This means that the lookforwardPeriod MUST be configured large enough that
// there is a buffer of at least one whole chunk width between the actual
// furthest-future expiration (generally atTime+90d) and the right-hand edge of
// the window (atTime+lookforwardPeriod).
func (cu *crlUpdater) getShardBoundaries(atTime time.Time, shardIdx int) (time.Time, time.Time) {
	// Ensure that the given shard index falls within the space of acceptable indices.
	shardIdx = shardIdx % cu.numShards

	// Compute the width of the full window.
	windowWidth := cu.lookbackPeriod + cu.lookforwardPeriod
	// Compute the amount of time between the left-hand edge of the most recent
	// "0" chunk and the current time.
	atTimeOffset := time.Duration(atTime.Sub(time.Time{}).Nanoseconds() % windowWidth.Nanoseconds())
	// Compute the left-hand edge of the most recent "0" chunk.
	zeroStart := atTime.Add(-atTimeOffset)

	// Compute the width of a single shard.
	shardWidth := time.Duration(windowWidth.Nanoseconds() / int64(cu.numShards))
	// Compute the amount of time between the left-hand edge of the most recent
	// "0" chunk and the left-hand edge of the desired chunk.
	shardOffset := time.Duration(int64(shardIdx) * shardWidth.Nanoseconds())
	// Compute the left-hand edge of the most recent chunk with the given index.
	shardStart := zeroStart.Add(shardOffset)
	// Compute the right-hand edge of the most recent chunk with the given index.
	shardEnd := shardStart.Add(shardWidth)

	// But the shard boundaries we just computed might be for a chunk that is
	// completely behind the left-hand edge of our current window. If they are,
	// bump them forward by one window width to bring them inside our window.
	if shardEnd.Before(atTime.Add(-cu.lookbackPeriod)) {
		shardStart = shardStart.Add(windowWidth)
		shardEnd = shardEnd.Add(windowWidth)
	}
	return shardStart, shardEnd
}
