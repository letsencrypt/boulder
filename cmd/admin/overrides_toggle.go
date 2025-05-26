package main

import (
	"context"
	"errors"
	"flag"
	"fmt"

	rl "github.com/letsencrypt/boulder/ratelimits"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

type subcommandToggleOverride struct {
	enabled   bool
	limitEnum int64
	regID     int64
	domain    string
	domains   string
	ipAddr    string
}

func (*subcommandToggleOverride) Desc() string {
	return "Enable or disable a rate limit override."
}

func (c *subcommandToggleOverride) Flags(f *flag.FlagSet) {
	f.BoolVar(&c.enabled, "enabled", false, "true to enable, false to disable (default: false)")
	f.Int64Var(&c.limitEnum, "limit", 0, "ratelimit enum (required)")

	f.Int64Var(&c.regID, "regid", 0, "a single registration/account ID")
	f.StringVar(&c.domain, "domain", "", "single domain (e.g. example.com)")
	f.StringVar(&c.domains, "domains", "", "comma-separated list of FQDNs (e.g. example.com,www.example.com)")
	f.StringVar(&c.ipAddr, "ip", "", "IPv4/IPv6 address")
}

func (c *subcommandToggleOverride) Run(ctx context.Context, a *admin) error {
	if c.limitEnum == 0 {
		return errors.New("--limit is required")
	}
	name := rl.Name(c.limitEnum)

	bucketKey, err := rl.BuildBucketKey(name, c.regID, c.domain, c.domains, c.ipAddr)
	if err != nil {
		return fmt.Errorf("Building bucket key for limit %s (%s): %s", name, name.EnumString(), err)
	}

	var rpcErr error
	if c.enabled {
		_, rpcErr = a.sac.EnableRateLimitOverride(ctx, &sapb.EnableRateLimitOverrideRequest{
			LimitEnum: c.limitEnum,
			BucketKey: bucketKey,
		})
	} else {
		_, rpcErr = a.sac.DisableRateLimitOverride(ctx, &sapb.DisableRateLimitOverrideRequest{
			LimitEnum: c.limitEnum,
			BucketKey: bucketKey,
		})
	}
	if rpcErr != nil {
		return fmt.Errorf("Toggling override for limit %s (%s) key %q: %s", name, name.EnumString(), bucketKey, rpcErr)
	}

	if c.enabled {
		fmt.Printf("Enabled override for limit %s (%s) key %q\n", name, name.EnumString(), bucketKey)
	} else {
		fmt.Printf("Disabled override for limit %s (%s) key %q\n", name, name.EnumString(), bucketKey)
	}
	return nil
}
