package updater

import (
	"context"
	"errors"
	"sync"

	"github.com/letsencrypt/boulder/crl"
	"github.com/letsencrypt/boulder/issuance"
)

// RunOnce causes the crlUpdater to update every shard immediately, then exit.
// It will run as many simultaneous goroutines as the configured maxParallelism.
func (cu *crlUpdater) RunOnce(ctx context.Context) error {
	var wg sync.WaitGroup
	atTime := cu.clk.Now()

	type workItem struct {
		issuerNameID issuance.IssuerNameID
		shardIdx     int
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
				err := cu.updateShardWithRetry(ctx, atTime, work.issuerNameID, work.shardIdx, nil)
				if err != nil {
					cu.log.AuditErrf(
						"Generating CRL failed: id=[%s] err=[%s]",
						crl.Id(work.issuerNameID, work.shardIdx, crl.Number(atTime)), err)
					once.Do(func() { anyErr = true })
				}
			}
		}
	}

	inputs := make(chan workItem)

	for i := 0; i < cu.maxParallelism; i++ {
		wg.Add(1)
		go shardWorker(inputs)
	}

	for _, issuer := range cu.issuers {
		for i := 1; i <= cu.numShards; i++ {
			select {
			case <-ctx.Done():
				close(inputs)
				wg.Wait()
				return ctx.Err()
			case inputs <- workItem{issuerNameID: issuer.NameID(), shardIdx: i}:
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
