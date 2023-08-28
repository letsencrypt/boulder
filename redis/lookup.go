package redis

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"

	"github.com/redis/go-redis/v9"
)

// Lookup is a helper that keeps *redis.Ring shards up to date using SRV
// lookups.
type Lookup struct {
	// srvLookups is a list of SRV records to be looked up.
	srvLookups []cmd.ServiceDomain

	// updateFrequency is the frequency of periodic SRV lookups. Defaults to 30
	// seconds.
	updateFrequency time.Duration

	// dnsAuthority is the single <hostname|IPv4|[IPv6]>:<port> of the DNS
	// server to be used for SRV lookups. If the address contains a hostname it
	// will be resolved via the system DNS. If the port is left unspecified it
	// will default to '53'. If this field is left unspecified the system DNS
	// will be used for resolution.
	dnsAuthority string

	ring   *redis.Ring
	logger blog.Logger
}

// NewLookup returns a new Lookup helper.
func NewLookup(srvLookups []cmd.ServiceDomain, dnsAuthority string, frequency time.Duration, ring *redis.Ring, logger blog.Logger) *Lookup {
	if frequency == 0 {
		// Use default frequency.
		frequency = 30 * time.Second
	}
	if dnsAuthority != "" {
		host, port, err := net.SplitHostPort(dnsAuthority)
		if err != nil {
			// Assume only hostname or IPv4 address was specified.
			host = dnsAuthority
			port = "53"
		}
		dnsAuthority = net.JoinHostPort(host, port)
	}
	return &Lookup{
		srvLookups:      srvLookups,
		updateFrequency: frequency,
		dnsAuthority:    dnsAuthority,
		ring:            ring,
		logger:          logger,
	}
}

// getResolver returns a resolver that will be used to perform SRV lookups.
func (look *Lookup) getResolver() *net.Resolver {
	if look.dnsAuthority == "" {
		return net.DefaultResolver
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial(network, look.dnsAuthority)
		},
	}
}

// handleDNSError logs non-temporary DNS errors and returns nil. Temporary DNS
// errors are returned as-is.
func (look *Lookup) handleDNSError(err error, lookupType string, srv cmd.ServiceDomain) error {
	if err != nil {
		return nil
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && (dnsErr.IsTimeout || dnsErr.IsTemporary) {
		return err
	}
	// Non-temporary DNS errors should always be logged as they are indicative
	// of a misconfiguration.
	look.logger.Errf("resolving redis shards, %s lookup for %+v failed: %s", lookupType, srv, err)
	return nil
}

// shards performs SRV lookups for the given service name and returns the
// resolved shard addresses. An error is only returned if all lookups fail
// and/or 0 shards are resolved.
func (look *Lookup) shards(ctx context.Context) (map[string]string, error) {
	resolver := look.getResolver()

	var tempErrs []error
	newAddrs := make(map[string]string)
	for _, srv := range look.srvLookups {
		_, targets, err := resolver.LookupSRV(ctx, srv.Service, "tcp", srv.Domain)
		err = look.handleDNSError(err, "SRV", srv)
		if err != nil {
			tempErrs = append(tempErrs, err)
			// Skip to the next SRV lookup.
			continue
		}

		for _, target := range targets {
			host := strings.TrimRight(target.Target, ".")
			if look.dnsAuthority != "" {
				// Lookup A/AAAA records for the SRV target using the custom DNS
				// authority.
				hostAddrs, err := resolver.LookupHost(ctx, host)
				err = look.handleDNSError(err, "A/AAAA", srv)
				if err != nil {
					tempErrs = append(tempErrs, err)
					// Skip to the next A/AAAA lookup.
					continue
				}
				if len(hostAddrs) == 0 {
					// Skip to the next A/AAAA lookup.
					continue
				}
				// Use the first resolved IP address.
				host = hostAddrs[0]
			}
			addr := fmt.Sprintf("%s:%d", host, target.Port)
			newAddrs[addr] = addr
		}
	}
	// Only return an error if all lookups failed.
	if len(tempErrs) > 0 && len(newAddrs) == 0 {
		return nil, errors.Join(tempErrs...)
	}
	return newAddrs, nil
}

// shardsPeriodically periodically performs SRV lookups for the given service
// name and updates the ring shards accordingly.
func (look *Lookup) shardsPeriodically(ctx context.Context) {
	ticker := time.NewTicker(look.updateFrequency)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			timeoutCtx, cancel := context.WithTimeout(ctx, look.updateFrequency-look.updateFrequency/10)
			newAddrs, err := look.shards(timeoutCtx)
			cancel()
			if err != nil {
				look.logger.Warningf("resolving redis shards for %+v, temporary errors occurred: %s", look.srvLookups, err)
				continue
			}
			if len(newAddrs) == 0 {
				look.logger.Errf("0 redis shards were resolved for %+v", look.srvLookups)
				continue
			}
			look.ring.SetAddrs(newAddrs)

		case <-ctx.Done():
			return
		}
	}
}

// Start begins periodic SRV lookups and updates the ring shards accordingly.
func (look *Lookup) Start(ctx context.Context) {
	addrs, err := look.shards(ctx)
	if err != nil {
		panic(fmt.Sprintf("resolving redis shards for %+v, temporary errors occurred: %s", look.srvLookups, err))
	}
	if len(addrs) == 0 {
		panic(fmt.Sprintf("0 redis shards were resolved for %+v", look.srvLookups))
	}
	look.ring.SetAddrs(addrs)
	go look.shardsPeriodically(ctx)
}
