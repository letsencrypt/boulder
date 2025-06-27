package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"strings"

	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/policy"
	rl "github.com/letsencrypt/boulder/ratelimits"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

type subcommandToggleOverride struct {
	enabled          bool
	limit            string
	regId            int64
	singleIdentifier string
	setOfIdentifiers string
	subscriberIP     string
}

func (*subcommandToggleOverride) Desc() string {
	return "Enable or disable a rate limit override."
}

func (c *subcommandToggleOverride) Flags(f *flag.FlagSet) {
	f.BoolVar(&c.enabled, "enabled", false, "true to enable, false to disable (default: false)")
	f.StringVar(&c.limit, "limit", "", "ratelimit name (required)")
	f.Int64Var(&c.regId, "regid", 0, "a single registration/account ID")
	f.StringVar(&c.singleIdentifier, "singleIdentifier", "", "a single identifier (e.g. example.com or www.example.com or 55.66.77.88 or 2602:80a:6000::1)")
	f.StringVar(&c.setOfIdentifiers, "setOfIdentifiers", "", "comma-separated list of unique identifiers (e.g. example.com,www.example.com,55.66.77.88,2602:80a:6000::1)")
	f.StringVar(&c.subscriberIP, "subscriberIP", "", "a single IPv4/IPv6 address the subscriber uses for requests")
}

func (c *subcommandToggleOverride) Run(ctx context.Context, a *admin) error {
	if c.limit == "" {
		return errors.New("--limit is required")
	}
	name, ok := rl.StringToName[c.limit]
	if !ok {
		return fmt.Errorf("unknown limit name %q, must be one in %s", c.limit, rl.LimitNames)
	}

	var subscriberIP netip.Addr
	var err error
	if c.subscriberIP != "" {
		subscriberIP, err = netip.ParseAddr(c.subscriberIP)
		if err != nil {
			return fmt.Errorf("invalid subscriberIP %q", err)
		}
		err := policy.ValidIP(c.subscriberIP)
		if err != nil {
			return fmt.Errorf("invalid subscriberIP %q: %w", c.subscriberIP, err)
		}
	}

	singleIdent := identifier.FromString(c.singleIdentifier)
	err = validateIdentifiers(singleIdent)
	if err != nil {
		return fmt.Errorf("invalid singleIdentifier: %w", err)
	}

	var setOfIdents identifier.ACMEIdentifiers
	if c.setOfIdentifiers != "" {
		setOfIdents = identifier.FromStringSlice(strings.Split(c.setOfIdentifiers, ","))
		err := validateIdentifiers(setOfIdents...)
		if err != nil {
			return fmt.Errorf("invalid setOfIdentifiers: %w", err)
		}
	}

	bucketKey, err := rl.BuildBucketKey(name, c.regId, singleIdent, setOfIdents, subscriberIP)
	if err != nil {
		return fmt.Errorf("building bucket key for limit %s: %s", name, err)
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
		return fmt.Errorf("toggling override for limit %s key %q: %s", name, bucketKey, rpcErr)
	}

	if c.enabled {
		a.log.Infof("Enabled override for limit %s key %q\n", name, bucketKey)
	} else {
		a.log.Infof("Disabled override for limit %s key %q\n", name, bucketKey)
	}
	return nil
}
