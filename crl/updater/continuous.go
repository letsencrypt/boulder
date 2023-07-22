package updater

import (
	"context"
	"math/big"
	"time"

	"github.com/letsencrypt/boulder/crl"
)

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
	atTime := cu.clk.Now()
	err := cu.Tick(ctx, atTime)
	if err != nil {
		// We only log, rather than return, so that the long-lived process can
		// continue and try again at the next tick.
		cu.log.AuditErrf(
			"Generating CRLs failed: number=[%s] err=[%s]",
			(*big.Int)(crl.Number(atTime)), err)
	}

	for {
		// If we have overrun *and* been canceled, both of the below cases could be
		// selectable at the same time, so check for context cancellation first.
		if ctx.Err() != nil {
			ticker.Stop()
			return ctx.Err()
		}
		select {
		case <-ticker.C:
			atTime = cu.clk.Now()
			err := cu.Tick(ctx, atTime)
			if err != nil {
				// We only log, rather than return, so that the long-lived process can
				// continue and try again at the next tick.
				cu.log.AuditErrf(
					"Generating CRLs failed: number=[%s] err=[%s]",
					(*big.Int)(crl.Number(atTime)), err)
			}
		case <-ctx.Done():
			ticker.Stop()
			return ctx.Err()
		}
	}
}
