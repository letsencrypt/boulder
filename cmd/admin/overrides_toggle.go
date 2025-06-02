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
	enabled bool
	limit   string
	regID   int64
	domain  string
	domains string
	ipAddr  string
}

func (*subcommandToggleOverride) Desc() string {
	return "Enable or disable a rate limit override."
}

func (c *subcommandToggleOverride) Flags(f *flag.FlagSet) {
	f.BoolVar(&c.enabled, "enabled", false, "true to enable, false to disable (default: false)")
	f.StringVar(&c.limit, "limit", "", "ratelimit name (required)")

	f.Int64Var(&c.regID, "regid", 0, "a single registration/account ID")
	f.StringVar(&c.domain, "domain", "", "single domain (e.g. example.com)")
	f.StringVar(&c.domains, "domains", "", "comma-separated list of FQDNs (e.g. example.com,www.example.com)")
	f.StringVar(&c.ipAddr, "ip", "", "IPv4/IPv6 address")
}

func (c *subcommandToggleOverride) Run(ctx context.Context, a *admin) error {
	if c.limit == "" {
		return errors.New("--limit is required")
	}
	name, ok := rl.StringToName[c.limit]
	if !ok {
		return fmt.Errorf("unknown limit name %q, must be one in %s", c.limit, rl.LimitNames)
	}

	bucketKey, err := rl.BuildBucketKey(name, c.regID, c.domain, c.domains, c.ipAddr)
	if err != nil {
		return fmt.Errorf("Building bucket key for limit %s: %s", name, err)
	}

	var rpcErr error
	if c.enabled {
		_, rpcErr = a.sac.EnableRateLimitOverride(ctx, &sapb.EnableRateLimitOverrideRequest{
			LimitEnum: int64(name),
			BucketKey: bucketKey,
		})
	} else {
		_, rpcErr = a.sac.DisableRateLimitOverride(ctx, &sapb.DisableRateLimitOverrideRequest{
			LimitEnum: int64(name),
			BucketKey: bucketKey,
		})
	}
	if rpcErr != nil {
		return fmt.Errorf("Toggling override for limit %s key %q: %s", name, bucketKey, rpcErr)
	}

	if c.enabled {
		a.log.Infof("Enabled override for limit %s key %q\n", name, bucketKey)
	} else {
		a.log.Infof("Disabled override for limit %s key %q\n", name, bucketKey)
	}
	return nil
}
