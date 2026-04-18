package updater

import (
	"context"
	"log/slog"
	"math/big"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/letsencrypt/boulder/blog"
	"github.com/letsencrypt/boulder/crl"
	"github.com/letsencrypt/boulder/issuance"
)

// Run causes the crlUpdater to enter its processing loop. It starts one
// goroutine for every shard it intends to update, each of which will wake at
// the appropriate interval.
func (cu *crlUpdater) Run(ctx context.Context) error {
	var wg sync.WaitGroup

	shardWorker := func(ctx context.Context, issuerNameID issuance.NameID, shardIdx int) {
		defer wg.Done()

		// Wait for a random number of nanoseconds less than the updatePeriod, so
		// that process restarts do not skip or delay shards deterministically.
		waitTimer := time.NewTimer(time.Duration(rand.Int64N(cu.updatePeriod.Nanoseconds())))
		defer waitTimer.Stop()
		select {
		case <-waitTimer.C:
			// Continue to ticker loop
		case <-ctx.Done():
			return
		}

		// Do work, then sleep for updatePeriod. Rinse, and repeat.
		ticker := time.NewTicker(cu.updatePeriod)
		defer ticker.Stop()
		for {
			// Check for context cancellation before we do any real work, in case we
			// overran the last tick and both cases were selectable at the same time.
			if ctx.Err() != nil {
				return
			}

			atTime := cu.clk.Now()
			var num *big.Int = crl.Number(atTime)
			ctx = blog.ContextWith(ctx, slog.String("number", num.String()))
			err := cu.updateShardWithRetry(ctx, atTime, issuerNameID, shardIdx)
			if err != nil {
				// We only log, rather than return, so that the long-lived process can
				// continue and try again at the next tick.
				cu.log.AuditError(ctx, "Generating CRL failed", err)
			}

			select {
			case <-ticker.C:
				continue
			case <-ctx.Done():
				return
			}
		}
	}

	// Start one shard worker per shard this updater is responsible for.
	for _, issuer := range cu.issuers {
		for i := 1; i <= cu.numShards; i++ {
			wg.Add(1)
			ctx = blog.ContextWith(ctx,
				slog.String("issuer", issuer.Subject.CommonName),
				slog.Int("shard", i),
			)
			go shardWorker(ctx, issuer.NameID(), i)
		}
	}

	// Wait for all of the shard workers to exit, which will happen when their
	// contexts are cancelled, probably by a SIGTERM.
	wg.Wait()
	return ctx.Err()
}
