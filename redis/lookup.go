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

// Lookup wraps a Redis ring client by reference and keeps the Redis ring shards
// up to date via periodic SRV lookups.
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

	resolver *net.Resolver
	ring     *redis.Ring
	logger   blog.Logger
}

// NewLookup constructs and returns a new Lookup instance. An initial SRV lookup
// is performed to populate the Redis ring shards. If the initial lookup fails,
// an error is returned.
func NewLookup(srvLookups []cmd.ServiceDomain, dnsAuthority string, frequency time.Duration, ring *redis.Ring, logger blog.Logger) (*Lookup, error) {
	var lookup = &Lookup{}
	lookup.updateFrequency = frequency
	if lookup.updateFrequency == 0 {
		// Use default frequency.
		lookup.updateFrequency = 30 * time.Second
	}

	// Use the system DNS resolver by default.
	lookup.resolver = net.DefaultResolver
	if dnsAuthority != "" {
		// Setup a custom DNS resolver.
		host, port, err := net.SplitHostPort(dnsAuthority)
		if err != nil {
			// Assume only hostname or IPv4 address was specified.
			host = dnsAuthority
			port = "53"
		}
		lookup.dnsAuthority = net.JoinHostPort(host, port)
		lookup.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return net.Dial(network, lookup.dnsAuthority)
			},
		}
	}

	lookup.srvLookups = srvLookups
	lookup.ring = ring
	lookup.logger = logger

	ctx, cancel := context.WithTimeout(context.Background(), lookup.updateFrequency-lookup.updateFrequency/10)
	tempErrs, nonTempErrs := lookup.now(ctx)
	cancel()
	if tempErrs != nil || nonTempErrs != nil {
		return nil, errors.Join(tempErrs, nonTempErrs)
	}
	return lookup, nil
}

// now resolves the SRV records and updates the Redis ring shards accordingly.
// If all lookups fail or otherwise result in an empty set of resolved shards,
// the Redis ring is left unmodified and any errors are returned. If at least
// one lookup succeeds, the Redis ring is updated, and all errors are discarded.
// Non-temporary DNS errors logged as they occur, as they're likely to be
// indicative of a misconfiguration.
func (look *Lookup) now(ctx context.Context) (tempErrors, nonTempErrors error) {
	var tempErrs []error
	var nonTempErrs []error

	handleDNSError := func(err error, srv cmd.ServiceDomain) {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && (dnsErr.IsTimeout || dnsErr.IsTemporary) {
			tempErrs = append(tempErrs, err)
			return
		}
		nonTempErrs = append(nonTempErrs, err)
		look.logger.Errf("resolving service _%s._tcp.%s: %s", srv.Service, srv.Domain, err)
	}

	nextAddrs := make(map[string]string)
	for _, srv := range look.srvLookups {
		_, targets, err := look.resolver.LookupSRV(ctx, srv.Service, "tcp", srv.Domain)
		if err != nil {
			handleDNSError(err, srv)
			// Skip to the next SRV lookup.
			continue
		}
		if len(targets) <= 0 {
			tempErrs = append(tempErrs, fmt.Errorf("no targets resolved for service \"_%s._tcp.%s\"", srv.Service, srv.Domain))
			// Skip to the next SRV lookup.
			continue
		}

		for _, target := range targets {
			host := strings.TrimRight(target.Target, ".")
			if look.dnsAuthority != "" {
				// Lookup A/AAAA records for the SRV target using the custom DNS
				// authority.
				hostAddrs, err := look.resolver.LookupHost(ctx, host)
				if err != nil {
					handleDNSError(err, srv)
					// Skip to the next A/AAAA lookup.
					continue
				}
				if len(hostAddrs) <= 0 {
					tempErrs = append(tempErrs, fmt.Errorf("no host resolved for target %q of service \"_%s._tcp.%s\"", host, srv.Service, srv.Domain))
					// Skip to the next A/AAAA lookup.
					continue
				}
				// Use the first resolved IP address.
				host = hostAddrs[0]
			}
			addr := fmt.Sprintf("%s:%d", host, target.Port)
			nextAddrs[addr] = addr
		}
	}

	// Only return and error if all lookups failed.
	if len(nextAddrs) == 0 {
		return errors.Join(tempErrs...), errors.Join(nonTempErrs...)
	}

	// At least some lookups succeeded, update the ring.
	look.ring.SetAddrs(nextAddrs)

	// Discard any errors.
	return nil, nil
}

// Start starts a goroutine that keeps the Redis ring shards up to date via
// periodic SRV lookups. The goroutine will exit when the provided context is
// cancelled.
func (look *Lookup) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(look.updateFrequency)
		defer ticker.Stop()
		for {
			// Check for context cancellation before we do any work.
			if ctx.Err() != nil {
				return
			}

			timeoutCtx, cancel := context.WithTimeout(ctx, look.updateFrequency-look.updateFrequency/10)
			tempErrs, _ := look.now(timeoutCtx)
			cancel()
			if tempErrs != nil {
				look.logger.Warningf("resolving ring shards: %s", tempErrs)
				continue
			}

			select {
			case <-ticker.C:
				continue

			case <-ctx.Done():
				return
			}
		}
	}()
}
