package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/policy"
	rl "github.com/letsencrypt/boulder/ratelimits"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

type subcommandAddOverride struct {
	limit            string
	regId            int64
	singleIdentifier string
	setOfIdentifiers string
	subscriberIP     string
	count            int64
	burst            int64
	period           string
	comment          string
}

func (*subcommandAddOverride) Desc() string {
	return "Add or update a rate limit override. New overrides are enabled by default. Updates to existing overrides will not change the enabled state."
}

func (c *subcommandAddOverride) Flags(f *flag.FlagSet) {
	f.StringVar(&c.limit, "limit", "", "ratelimit name (required)")
	f.Int64Var(&c.regId, "regId", 0, "a single registration/account ID")
	f.StringVar(&c.singleIdentifier, "singleIdentifier", "", "a single identifier (e.g. example.com or www.example.com or 55.66.77.88 or 2602:80a:6000::1)")
	f.StringVar(&c.setOfIdentifiers, "setOfIdentifiers", "", "comma-separated list of unique identifiers (e.g. example.com,www.example.com,55.66.77.88,2602:80a:6000::1)")
	f.StringVar(&c.subscriberIP, "subscriberIP", "", "a single IPv4/IPv6 address the subscriber uses for requests (e.g. 55.66.77.88 or 2602:80a:6000::1)")

	f.Int64Var(&c.count, "count", 0, "allowed requests per period (required)")
	f.Int64Var(&c.burst, "burst", 0, "burst size (required)")
	f.StringVar(&c.period, "period", "", "period duration (e.g. 1h, 168h) (required)")
	f.StringVar(&c.comment, "comment", "", "comment for the override (required)")
}

// validateIdentifiers checks that the provided identifiers are valid according policy.
func validateIdentifiers(idents ...identifier.ACMEIdentifier) error {
	for _, ident := range idents {
		switch ident.Type {
		case identifier.TypeDNS:
			err := policy.ValidDomain(ident.Value)
			if err != nil {
				return fmt.Errorf("invalid domain %s: %s", ident.Value, err)
			}
		case identifier.TypeIP:
			err := policy.ValidIP(ident.Value)
			if err != nil {
				return fmt.Errorf("invalid IP address %s", ident.Value)
			}
		}
	}
	return nil
}

func (c *subcommandAddOverride) Run(ctx context.Context, a *admin) error {
	if c.limit == "" {
		return errors.New("--limit is required")
	}
	if c.count == 0 || c.burst == 0 || c.period == "" || c.comment == "" {
		return errors.New("all of --count, --burst, --period, and --comment are required")
	}

	name, ok := rl.StringToName[c.limit]
	if !ok {
		return fmt.Errorf("unknown limit name %q, must be one in %s", c.limit, rl.LimitNames)
	}

	dur, err := time.ParseDuration(c.period)
	if err != nil {
		return fmt.Errorf("invalid period value: %s", err)
	}

	var subscriberIP netip.Addr
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

	err = rl.ValidateLimit(&rl.Limit{
		Name:   name,
		Count:  c.count,
		Burst:  c.burst,
		Period: config.Duration{Duration: dur},
	})
	if err != nil {
		return fmt.Errorf("validating override for limit %s key %q: %s", name, bucketKey, err)
	}

	resp, err := a.sac.AddRateLimitOverride(ctx, &sapb.AddRateLimitOverrideRequest{
		Override: &sapb.RateLimitOverride{
			LimitEnum: int64(name),
			BucketKey: bucketKey,
			Count:     c.count,
			Burst:     c.burst,
			Period:    durationpb.New(dur),
			Comment:   c.comment,
		},
	})
	if err != nil {
		return fmt.Errorf("adding override for limit %s key %q: %s", name, bucketKey, err)
	}

	status := "disabled"
	if resp.Enabled {
		status = "enabled"
	}

	if resp.Inserted {
		a.log.Infof("Added new override for limit %s key %q, status=[%s]\n", name, bucketKey, status)
	} else {
		a.log.Infof("Updated existing override for limit %s key %q, status=[%s]\n", name, bucketKey, status)
	}
	return nil
}
