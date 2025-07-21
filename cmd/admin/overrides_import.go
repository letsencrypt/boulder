package main

import (
	"context"
	"errors"
	"flag"
	"sync"

	"github.com/letsencrypt/boulder/ratelimits"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

type subcommandImportOverrides struct {
	file        string
	parallelism uint
}

func (*subcommandImportOverrides) Desc() string { return "Push overrides to SA" }

func (c *subcommandImportOverrides) Flags(f *flag.FlagSet) {
	f.StringVar(&c.file, "file", "", "path to YAML file containing rate limit overrides")
	f.UintVar(&c.parallelism, "parallelism", 10, "the number of concurrent RPCs to send to the SA (default: 10)")
}

func (c *subcommandImportOverrides) Run(ctx context.Context, a *admin) error {
	if c.file == "" {
		return errors.New("--file is required")
	}
	overrides, err := ratelimits.LoadOverridesByBucketKey(c.file)
	if err != nil {
		return err
	}

	work := make(chan *sapb.RateLimitOverride, len(overrides))
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

	var wg sync.WaitGroup
	errChan := make(chan error, c.parallelism)
	for i := uint(0); i < c.parallelism; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ov := range work {
				_, e := a.sac.AddRateLimitOverride(ctx,
					&sapb.AddRateLimitOverrideRequest{Override: ov})
				if e != nil {
					errChan <- e
				}
			}
		}()
	}
	wg.Wait()
	close(errChan)

	e := <-errChan
	if e != nil {
		return e
	}
	return nil
}
