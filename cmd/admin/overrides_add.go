package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/letsencrypt/boulder/config"
	rl "github.com/letsencrypt/boulder/ratelimits"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

type subcommandAddOverride struct {
	limitEnum int64
	regID     int64
	domain    string
	domains   string
	ipAddr    string
	count     int64
	burst     int64
	period    string
	comment   string
}

func (*subcommandAddOverride) Desc() string {
	return "Add or update a rate limit override. New overrides are enabled by default. Updates to existing overrides will not change the enabled state."
}

func (c *subcommandAddOverride) Flags(f *flag.FlagSet) {
	f.Int64Var(&c.limitEnum, "limit", 0, "ratelimit enum (required)")
	f.Int64Var(&c.regID, "regid", 0, "a single registration/account ID")
	f.StringVar(&c.domain, "domain", "", "single domain (e.g. example.com)")
	f.StringVar(&c.domains, "domains", "", "comma-separated list of FQDNs (e.g. example.com,www.example.com)")
	f.StringVar(&c.ipAddr, "ip", "", "IPv4/IPv6 address")

	f.Int64Var(&c.count, "count", 0, "allowed requests per period (required)")
	f.Int64Var(&c.burst, "burst", 0, "burst size (required)")
	f.StringVar(&c.period, "period", "", "period duration (e.g. 1h, 168h) (required)")
	f.StringVar(&c.comment, "comment", "", "comment for the override (required)")
}

func (c *subcommandAddOverride) Run(ctx context.Context, a *admin) error {
	if c.limitEnum == 0 {
		return errors.New("--limit is required")
	}
	if c.count == 0 || c.burst == 0 || c.period == "" || c.comment == "" {
		return errors.New("all of --count, --burst, --period, and --comment are required")
	}

	dur, err := time.ParseDuration(c.period)
	if err != nil {
		return fmt.Errorf("invalid --period value: %s", err)
	}

	name := rl.Name(c.limitEnum)
	bucketKey, err := rl.BuildBucketKey(name, c.regID, c.domain, c.domains, c.ipAddr)
	if err != nil {
		return fmt.Errorf("building bucket key for limit %s (%s): %s", name, name.EnumString(), err)
	}

	err = rl.ValidateLimit(&rl.Limit{
		Name:   name,
		Count:  c.count,
		Burst:  c.burst,
		Period: config.Duration{Duration: dur},
	})
	if err != nil {
		return fmt.Errorf("validating override for limit %s (%s) key %q: %s", name, name.EnumString(), bucketKey, err)
	}

	resp, err := a.sac.AddRateLimitOverride(ctx, &sapb.AddRateLimitOverrideRequest{
		Override: &sapb.RateLimitOverride{
			LimitEnum: c.limitEnum,
			BucketKey: bucketKey,
			Count:     c.count,
			Burst:     c.burst,
			Period:    durationpb.New(dur),
			Comment:   c.comment,
		},
	})
	if err != nil {
		return fmt.Errorf("adding override for limit %s (%s) key %q: %s", name, name.EnumString(), bucketKey, err)
	}

	status := "disabled"
	if resp.Enabled {
		status = "enabled"
	}

	if resp.Inserted {
		fmt.Printf("Added new override for limit %s (%s) key %q, status=[%s]\n", name, name.EnumString(), bucketKey, status)
	} else {
		fmt.Printf("Updated existing override for limit %s (%s) key %q, status=[%s]\n", name, name.EnumString(), bucketKey, status)
	}
	return nil
}
