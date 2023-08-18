package redis

import (
	"context"
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
	// service is the symbolic name of the desired service.
	service string

	// domain is the domain name of the desired service.
	domain string

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
func NewLookup(srv cmd.ServiceDomain, dnsAuthority string, frequency time.Duration, ring *redis.Ring, logger blog.Logger) *Lookup {
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
		service:         srv.Service,
		domain:          srv.Domain,
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

// dnsName returns DNS name to look up as defined in RFC 2782.
func (look *Lookup) dnsName() string {
	return fmt.Sprintf("_%s._tcp.%s", look.service, look.domain)
}

// LookupShards performs SRV lookups for the given service name and returns the
// resolved shard addresses.
func (look *Lookup) Shards(ctx context.Context) (map[string]string, error) {
	resolver := look.getResolver()

	_, addrs, err := resolver.LookupSRV(ctx, look.service, "tcp", look.domain)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup SRV records for service %q: %w", look.dnsName(), err)
	}

	if len(addrs) <= 0 {
		return nil, fmt.Errorf("no SRV targets found for service %q", look.dnsName())
	}

	newAddrs := make(map[string]string)

	for _, srv := range addrs {
		host := strings.TrimRight(srv.Target, ".")

		if look.dnsAuthority != "" {
			// Lookup A/AAAA records for the SRV target using the custom DNS
			// authority.
			hostAddrs, err := resolver.LookupHost(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("failed to lookup A/AAAA records for %q: %w", host, err)
			}
			if len(hostAddrs) <= 0 {
				return nil, fmt.Errorf("no A/AAAA records found for %q", host)
			}
			// Use the first resolved IP address.
			host = hostAddrs[0]
		}

		addr := fmt.Sprintf("%s:%d", host, srv.Port)
		newAddrs[addr] = addr
	}
	return newAddrs, nil
}

// ShardsPeriodically periodically performs SRV lookups for the given service
// name and updates the ring shards accordingly.
func (look *Lookup) ShardsPeriodically(ctx context.Context, frequency time.Duration) {
	ticker := time.NewTicker(frequency)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			timeoutCtx, cancel := context.WithTimeout(ctx, frequency)
			newAddrs, err := look.Shards(timeoutCtx)
			cancel()
			if err != nil {
				look.logger.Errf(err.Error())
				continue
			}
			look.ring.SetAddrs(newAddrs)

		case <-ctx.Done():
			return
		}
	}
}

// Start starts the periodic SRV lookups.
func (look *Lookup) Start(ctx context.Context) {
	addrs, err := look.Shards(ctx)
	if err != nil {
		panic(err)
	}
	look.ring.SetAddrs(addrs)
	go look.ShardsPeriodically(ctx, look.updateFrequency)
}
