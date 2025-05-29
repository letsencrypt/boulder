package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/ratelimits"
	"google.golang.org/protobuf/types/known/emptypb"
)

type subcommandDumpEnabledOverrides struct {
	file string
}

func (*subcommandDumpEnabledOverrides) Desc() string {
	return "Dump all enabled rate limit overrides to a YAML file"
}

func (c *subcommandDumpEnabledOverrides) Flags(f *flag.FlagSet) {
	f.StringVar(&c.file, "file", "", "destination path for YAML output (required)")
}

func (c *subcommandDumpEnabledOverrides) Run(ctx context.Context, a *admin) error {
	if c.file == "" {
		return errors.New("--file is required")
	}

	stream, err := a.sac.GetEnabledRateLimitOverrides(ctx, &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("fetching enabled overrides: %w", err)
	}

	overrides := make(map[string]*ratelimits.Limit)
	for {
		r, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("Reading overrides stream: %w", err)
		}

		overrides[r.Override.BucketKey] = &ratelimits.Limit{
			Burst:  r.Override.Burst,
			Count:  r.Override.Count,
			Period: config.Duration{Duration: r.Override.Period.AsDuration()},
			Name:   ratelimits.Name(r.Override.LimitEnum),
			Comment: fmt.Sprintf("Last Updated: %s - %s",
				r.UpdatedAt.AsTime().Format("2006-01-02"),
				r.Override.Comment,
			),
		}
	}

	err = ratelimits.DumpOverrides(c.file, overrides)
	if err != nil {
		return fmt.Errorf("Dumping overrides: %w", err)
	}

	fmt.Printf("Wrote %d overrides to %q\n", len(overrides), c.file)
	return nil
}
