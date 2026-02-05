package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"sync"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/letsencrypt/boulder/ratelimits"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

type subcommandImportOverrides struct {
	file        string
	parallelism int
	force       bool
}

func (*subcommandImportOverrides) Desc() string { return "Push overrides to SA" }

func (c *subcommandImportOverrides) Flags(f *flag.FlagSet) {
	f.StringVar(&c.file, "file", "", "path to YAML file containing rate limit overrides")
	f.IntVar(&c.parallelism, "parallelism", 10, "the number of concurrent RPCs to send to the SA (default: 10)")
	f.BoolVar(&c.force, "force", false, "forces an update even if the new override is lower than the existing one")
}

func (c *subcommandImportOverrides) Run(ctx context.Context, a *admin) error {
	if c.file == "" {
		return errors.New("--file is required")
	}
	if c.parallelism <= 0 {
		return errors.New("--parallelism must be greater than 0")
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
		ov   *sapb.RateLimitOverride
		resp *sapb.AddRateLimitOverrideResponse
		err  error
	}
	results := make(chan result, c.parallelism)

	var wg sync.WaitGroup
	for i := 0; i < c.parallelism; i++ {
		wg.Go(func() {
			for ov := range work {
				resp, err := a.sac.AddRateLimitOverride(ctx, &sapb.AddRateLimitOverrideRequest{Override: ov, Force: c.force})
				results <- result{ov: ov, resp: resp, err: err}
			}
		})
	}

	var errorCount int
	for range overrideCount {
		result := <-results
		if result.err != nil {
			a.log.Errf("failed to add override: key=%q limit=%d: %s", result.ov.BucketKey, result.ov.LimitEnum, result.err)
			errorCount++
			continue
		}
		if result.resp != nil && result.resp.Existing != nil {
			a.log.Errf(
				"override for limit %s bucketKey %q is lower than existing override (count=%d burst=%d period=%s), use --force to override",
				ratelimits.Name(int(result.ov.LimitEnum)),
				result.ov.BucketKey,
				result.resp.Existing.Count,
				result.resp.Existing.Burst,
				result.resp.Existing.Period.AsDuration(),
			)
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
