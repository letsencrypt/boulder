package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
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
			a.log.Error(ctx, "failed to add override", err,
				slog.Int64("limit", result.ov.LimitEnum),
				slog.String("bucketKey", result.ov.BucketKey),
			)
			errorCount++
			continue
		}
		if result.resp != nil && result.resp.Existing != nil {
			a.log.Error(ctx, "refused to update override", errors.New("new override is lower than existing override"),
				slog.Int64("limit", result.ov.LimitEnum),
				slog.String("bucketKey", result.ov.BucketKey),
				slog.Group("old",
					slog.Duration("period", result.resp.Existing.Period.AsDuration()),
					slog.Int64("count", result.resp.Existing.Count),
					slog.Int64("burst", result.resp.Existing.Burst),
				),
				slog.Group("new",
					slog.Duration("period", result.ov.Period.AsDuration()),
					slog.Int64("count", result.ov.Count),
					slog.Int64("burst", result.ov.Burst),
				),
			)
			errorCount++
		}
	}

	wg.Wait()
	close(results)

	if errorCount > 0 {
		return fmt.Errorf("%d out of %d overrides failed to be added, see log message(s) for more details", errorCount, overrideCount)
	}
	a.log.Info(ctx, "Successfully added overrides", slog.Int("count", overrideCount))
	return nil
}
