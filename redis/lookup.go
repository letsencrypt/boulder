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

var ErrNoShardsResolved = errors.New("0 shards were resolved")

// Lookup wraps a Redis ring client by reference and keeps the Redis ring shards
// up to date via periodic SRV lookups.
type Lookup struct {
	// srvLookups is a list of SRV records to be looked up.
	srvLookups []cmd.ServiceDomain

	// updateFrequency is the frequency of periodic SRV lookups. Defaults to 30
	// seconds.
	updateFrequency time.Duration

	// updateTimeout is the timeout for each SRV lookup. Defaults to 90% of the
	// update frequency.
	updateTimeout time.Duration

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
// is performed to populate the Redis ring shards. If this lookup fails or
// otherwise results in an empty set of resolved shards, an error is returned.
func NewLookup(srvLookups []cmd.ServiceDomain, dnsAuthority string, frequency time.Duration, ring *redis.Ring, logger blog.Logger) (*Lookup, error) {
	updateFrequency := frequency
	if updateFrequency <= 0 {
		// Set default frequency.
		updateFrequency = 30 * time.Second
	}
	// Set default timeout to 90% of the update frequency.
	updateTimeout := updateFrequency - updateFrequency/10

	var lookup *Lookup
	if dnsAuthority == "" {
		// Use the system DNS resolver.
		lookup = &Lookup{
			srvLookups:      srvLookups,
			ring:            ring,
			logger:          logger,
			updateFrequency: updateFrequency,
			updateTimeout:   updateTimeout,
			resolver:        net.DefaultResolver,
			dnsAuthority:    dnsAuthority,
		}
	} else {
		// Setup a custom DNS resolver.
		lookup = &Lookup{
			srvLookups:      srvLookups,
			ring:            ring,
			logger:          logger,
			updateFrequency: updateFrequency,
			updateTimeout:   updateTimeout,
			dnsAuthority:    dnsAuthority,
		}

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
				// The custom resolver closes over the lookup.dnsAuthority field
				// so it can be swapped out in testing.
				return net.Dial(network, lookup.dnsAuthority)
			},
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()
	tempErr, nonTempErr := lookup.updateNow(ctx)

	if tempErr != nil {
		// Log and discard temporary errors, as they're likely to be transient
		// (e.g. network connectivity issues).
		logger.Warningf("resolving ring shards: %s", tempErr)
	}
	if nonTempErr != nil && errors.Is(nonTempErr, ErrNoShardsResolved) {
		// Non-temporary errors are always logged inside of updateNow(), so we
		// only need return the error here if it's ErrNoShardsResolved.
		return nil, nonTempErr
	}

	return lookup, nil
}

// updateNow resolves and updates the Redis ring shards accordingly. If all
// lookups fail or otherwise result in an empty set of resolved shards, the
// Redis ring is left unmodified and any errors are returned. If at least one
// lookup succeeds, the Redis ring is updated, and all errors are discarded.
// Non-temporary DNS errors are always logged as they occur, as they're likely
// to be indicative of a misconfiguration.
func (look *Lookup) updateNow(ctx context.Context) (tempError, nonTempError error) {
	var tempErrs []error
	handleDNSError := func(err error, srv cmd.ServiceDomain) {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && (dnsErr.IsTimeout || dnsErr.IsTemporary) {
			tempErrs = append(tempErrs, err)
			return
		}
		// Log non-temporary DNS errors as they occur, as they're likely to be
		// indicative of misconfiguration.
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
			tempErrs = append(tempErrs, fmt.Errorf("0 targets resolved for service \"_%s._tcp.%s\"", srv.Service, srv.Domain))
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
					tempErrs = append(tempErrs, fmt.Errorf("0 addrs resolved for target %q of service \"_%s._tcp.%s\"", host, srv.Service, srv.Domain))
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

	// Only return errors if we failed to resolve any shards.
	if len(nextAddrs) <= 0 {
		return errors.Join(tempErrs...), ErrNoShardsResolved
	}

	// Some shards were resolved, update the Redis ring and discard all errors.
	look.ring.SetAddrs(nextAddrs)
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

			timeoutCtx, cancel := context.WithTimeout(ctx, look.updateTimeout)
			tempErrs, nonTempErrs := look.updateNow(timeoutCtx)
			cancel()
			if tempErrs != nil {
				look.logger.Warningf("resolving ring shards, temporary errors: %s", tempErrs)
				continue
			}
			if nonTempErrs != nil {
				look.logger.Errf("resolving ring shards, non-temporary errors: %s", nonTempErrs)
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
