package updater

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/letsencrypt/boulder/crl"
	"github.com/letsencrypt/boulder/issuance"
)

// RunOnce runs the entire update process once immediately. It processes each
// configured issuer serially, and processes all of them even if an early one
// encounters an error. All errors encountered are returned as a single combined
// error at the end.
func (cu *crlUpdater) RunOnce(ctx context.Context, atTime time.Time) (err error) {
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
		err := cu.updateIssuer(ctx, atTime, id)
		if err != nil {
			cu.log.AuditErrf(
				"Generating CRLs for issuer failed: number=[%d] issuer=[%s] err=[%s]",
				(*big.Int)(crl.Number(atTime)), cu.issuers[id].Subject.CommonName, err)
			errIssuers = append(errIssuers, cu.issuers[id].Subject.CommonName)
		}
	}

	if len(errIssuers) != 0 {
		return fmt.Errorf("%d issuers failed: %v", len(errIssuers), strings.Join(errIssuers, ", "))
	}
	return nil
}

// updateIssuer performs the full CRL issuance cycle for a single issuer cert. It
// processes all of the shards of this issuer's CRL concurrently, and processes
// all of them even if an early one encounters an error. All errors encountered
// are returned as a single combined error at the end.
func (cu *crlUpdater) updateIssuer(ctx context.Context, atTime time.Time, issuerNameID issuance.IssuerNameID) (err error) {
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

	shardMap, err := cu.getShardMappings(ctx, atTime)
	if err != nil {
		return fmt.Errorf("computing shardmap: %w", err)
	}

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
					err:      cu.updateShardWithRetry(ctx, atTime, issuerNameID, idx, shardMap[idx]),
				}
				// We want to renumber shard 0 to also be shard numShards (e.g. 128).
				// To facilitate that transition, produce the same CRL with both shard
				// indices.
				// TODO(#7007): Collapse this when we don't need to produce both anymore.
				if idx == 0 {
					out <- shardResult{
						shardIdx: cu.numShards,
						err:      cu.updateShardWithRetry(ctx, atTime, issuerNameID, cu.numShards, shardMap[idx]),
					}
				}
			}
		}
	}

	shardIdxs := make(chan int, cu.numShards)
	shardResults := make(chan shardResult, cu.numShards)
	for i := 0; i < cu.maxParallelism; i++ {
		go shardWorker(shardIdxs, shardResults)
	}

	// TODO(#7007): Iterate from 1 to numShards instead of 0 to numShards-1.
	for shardIdx := 0; shardIdx < cu.numShards; shardIdx++ {
		shardIdxs <- shardIdx
	}
	close(shardIdxs)

	var errShards []int
	// TODO(#7007): Reduce this to cu.numShards when we stop producing shard 0.
	for i := 0; i < cu.numShards+1; i++ {
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

// anchorTime is used as a universal starting point against which other times
// can be compared. This time must be less than 290 years (2^63-1 nanoseconds)
// in the past, to ensure that Go's time.Duration can represent that difference.
// The significance of 2015-06-04 11:04:38 UTC is left as an exercise to the
// reader.
func anchorTime() time.Time {
	return time.Date(2015, time.June, 04, 11, 04, 38, 0, time.UTC)
}

// chunk represents a fixed slice of time during which some certificates
// presumably expired or will expire. Its non-unique index indicates which shard
// it will be mapped to. The start boundary is inclusive, the end boundary is
// exclusive.
type chunk struct {
	start time.Time
	end   time.Time
	idx   int
}

// shardMap is a mapping of shard indices to the set of chunks which should be
// included in that shard. Under most circumstances there is a one-to-one
// mapping, but certain configuration (such as having very narrow shards, or
// having a very long lookback period) can result in more than one chunk being
// mapped to a single shard.
type shardMap [][]chunk

// getShardMappings determines which chunks are currently relevant, based on
// the current time, the configured lookbackPeriod, and the farthest-future
// certificate expiration in the database. It then maps all of those chunks to
// their corresponding shards, and returns that mapping.
//
// The idea here is that shards should be stable. Picture a timeline, divided
// into chunks. Number those chunks from 0 (starting at the anchor time) up to
// numShards, then repeat the cycle when you run out of numbers:
//
//	chunk:  0     1     2     3     4     0     1     2     3     4     0
//	     |-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----...
//	     ^-anchorTime
//
// The total time window we care about goes from atTime-lookbackPeriod, forward
// through the time of the farthest-future notAfter date found in the database.
// The lookbackPeriod must be larger than the updatePeriod, to ensure that any
// certificates which were both revoked *and* expired since the last time we
// issued CRLs get included in this generation. Because these times are likely
// to fall in the middle of chunks, we include the whole chunks surrounding
// those times in our output CRLs:
//
//	included chunk:     4     0     1     2     3     4     0     1
//	      ...--|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----...
//	atTime-lookbackPeriod-^   ^-atTime                lastExpiry-^
//
// Because this total period of time may include multiple chunks with the same
// number, we then coalesce these chunks into a single shard. Ideally, this
// will never happen: it should only happen if the lookbackPeriod is very
// large, or if the shardWidth is small compared to the lastExpiry (such that
// numShards * shardWidth is less than lastExpiry - atTime). In this example,
// shards 0, 1, and 4 all get the contents of two chunks mapped to them, while
// shards 2 and 3 get only one chunk each.
//
//	included chunk:     4     0     1     2     3     4     0     1
//	      ...--|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----...
//	                    │     │     │     │     │     │     │     │
//	shard 0: <────────────────┘─────────────────────────────┘     │
//	shard 1: <──────────────────────┘─────────────────────────────┘
//	shard 2: <────────────────────────────┘     │     │
//	shard 3: <──────────────────────────────────┘     │
//	shard 4: <──────────┘─────────────────────────────┘
//
// Under this scheme, the shard to which any given certificate will be mapped is
// a function of only three things: that certificate's notAfter timestamp, the
// chunk width, and the number of shards.
func (cu *crlUpdater) getShardMappings(ctx context.Context, atTime time.Time) (shardMap, error) {
	res := make(shardMap, cu.numShards)

	// Get the farthest-future expiration timestamp to ensure we cover everything.
	lastExpiry, err := cu.sa.GetMaxExpiration(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}

	// Find the id number and boundaries of the earliest chunk we care about.
	first := atTime.Add(-cu.lookbackPeriod)
	c, err := cu.getChunkAtTime(first)
	if err != nil {
		return nil, err
	}

	// Iterate over chunks until we get completely beyond the farthest-future
	// expiration.
	for c.start.Before(lastExpiry.AsTime()) {
		res[c.idx] = append(res[c.idx], c)
		c = chunk{
			start: c.end,
			end:   c.end.Add(cu.shardWidth),
			idx:   (c.idx + 1) % cu.numShards,
		}
	}

	return res, nil
}

// getChunkAtTime returns the chunk whose boundaries contain the given time.
// It is broken out solely for the purpose of unit testing.
func (cu *crlUpdater) getChunkAtTime(atTime time.Time) (chunk, error) {
	// Compute the amount of time between the current time and the anchor time.
	timeSinceAnchor := atTime.Sub(anchorTime())
	if timeSinceAnchor == time.Duration(math.MaxInt64) || timeSinceAnchor < 0 {
		return chunk{}, errors.New("shard boundary math broken: anchor time too far away")
	}

	// Determine how many full chunks fit within that time, and from that the
	// index number of the desired chunk.
	chunksSinceAnchor := timeSinceAnchor.Nanoseconds() / cu.shardWidth.Nanoseconds()
	chunkIdx := int(chunksSinceAnchor) % cu.numShards

	// Determine the boundaries of the chunk.
	timeSinceChunk := time.Duration(timeSinceAnchor.Nanoseconds() % cu.shardWidth.Nanoseconds())
	left := atTime.Add(-timeSinceChunk)
	right := left.Add(cu.shardWidth)

	return chunk{left, right, chunkIdx}, nil
}
