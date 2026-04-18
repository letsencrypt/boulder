package updater

import (
	"context"
	"errors"
	"log/slog"
	"math/big"
	"sync"

	"github.com/letsencrypt/boulder/blog"
	"github.com/letsencrypt/boulder/crl"
	"github.com/letsencrypt/boulder/issuance"
)

// RunOnce causes the crlUpdater to update every shard immediately, then exit.
// It will run as many simultaneous goroutines as the configured maxParallelism.
func (cu *crlUpdater) RunOnce(ctx context.Context) error {
	var wg sync.WaitGroup
	atTime := cu.clk.Now()
	var crlNumber *big.Int = crl.Number(atTime)

	type workItem struct {
		issuer   *issuance.Certificate
		shardIdx int
	}

	var anyErr bool
	var once sync.Once

	shardWorker := func(in <-chan workItem) {
		defer wg.Done()

		for {
			select {
			case <-ctx.Done():
				return
			case work, ok := <-in:
				if !ok {
					return
				}

				ctx = blog.ContextWith(ctx,
					slog.String("issuer", work.issuer.Subject.CommonName),
					slog.Int("shard", work.shardIdx),
					slog.String("number", crlNumber.String()),
				)
				err := cu.updateShardWithRetry(ctx, atTime, work.issuer.NameID(), work.shardIdx)
				if err != nil {
					cu.log.AuditError(ctx, "Generating CRL failed", err)
					once.Do(func() { anyErr = true })
				}
			}
		}
	}

	inputs := make(chan workItem)

	for range cu.maxParallelism {
		wg.Add(1)
		go shardWorker(inputs)
	}

	for _, issuer := range cu.issuers {
		for i := range cu.numShards {
			select {
			case <-ctx.Done():
				close(inputs)
				wg.Wait()
				return ctx.Err()
			case inputs <- workItem{issuer: issuer, shardIdx: i + 1}:
			}
		}
	}
	close(inputs)

	wg.Wait()
	if anyErr {
		return errors.New("one or more errors encountered, see logs")
	}
	return ctx.Err()
}
