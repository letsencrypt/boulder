package main

import (
	"context"
	"flag"
	"fmt"
	"sync"

	"github.com/letsencrypt/boulder/ratelimits"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

type subcommandImportOverrides struct {
	file        string
	parallelism int
}

func (*subcommandImportOverrides) Desc() string { return "Push overrides to SA" }

func (c *subcommandImportOverrides) Flags(f *flag.FlagSet) {
	f.StringVar(&c.file, "file", "", "path to YAML file containing rate limit overrides")
	f.IntVar(&c.parallelism, "parallelism", 10, "the number of concurrent RPCs to send to the SA (default: 10)")
}

func (c *subcommandImportOverrides) Run(ctx context.Context, a *admin) error {
	if c.file == "" {
		return fmt.Errorf("--file is required")
	}
	if c.parallelism <= 0 {
		return fmt.Errorf("--parallelism must be greater than 0")
	}
	overrides, err := ratelimits.LoadOverridesByBucketKey(c.file)
	if err != nil {
		return err
	}
	var overrideCount = len(overrides)

	work := make(chan *sapb.RateLimitOverride, overrideCount)
	for k, ov := range overrides {
		work <- &sapb.RateLimitOverride{
			LimitEnum: int64(ov.Name),
			BucketKey: k,
			Comment:   ov.Comment,
			Period:    durationpb.New(ov.Period.Duration),
			Count:     ov.Count,
			Burst:     ov.Burst,
		}
	}
	close(work)

	type result struct {
		ov  *sapb.RateLimitOverride
		err error
	}
	results := make(chan result, c.parallelism)

	var wg sync.WaitGroup
	for i := 0; i < c.parallelism; i++ {
		wg.Go(func() {
			for ov := range work {
				_, err := a.sac.AddRateLimitOverride(ctx, &sapb.AddRateLimitOverrideRequest{Override: ov})
				results <- result{ov: ov, err: err}
			}
		})
	}

	var errorCount int
	for range overrideCount {
		result := <-results
		if result.err != nil {
			a.log.AuditErrf("failed to add override: key=%q limit=%d: %s", result.ov.BucketKey, result.ov.LimitEnum, result.err)
			errorCount++
		}
	}

	wg.Wait()
	close(results)

	if errorCount > 0 {
		return fmt.Errorf("%d out of %d overrides failed to be added, see log message(s) for more details", errorCount, overrideCount)
	}
	a.log.Infof("Successfully added %d overrides", overrideCount)
	return nil
}
