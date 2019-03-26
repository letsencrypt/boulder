// Package challtestsrv provides a trivially insecure acme challenge response
// server for rapidly testing HTTP-01, DNS-01 and TLS-ALPN-01 challenge types.
package challtestsrv

import (
	"fmt"
	"log"
	"os"
	"sync"
)

const (
	// Default to using localhost for both A and AAAA queries that don't match
	// more specific mock host data.
	defaultIPv4 = "127.0.0.1"
	defaultIPv6 = "::1"
)

// challengeServers offer common functionality to start up and shutdown.
type challengeServer interface {
	ListenAndServe() error
	Shutdown() error
}

// ChallSrv is a multi-purpose challenge server. Each ChallSrv may have one or
// more ACME challenges it provides servers for. It is safe to use concurrently.
type ChallSrv struct {
	log *log.Logger

	// servers are the individual challenge server listeners started in New() and
	// closed in Shutdown().
	servers []challengeServer

	// challMu is a RWMutex used to control concurrent updates to the challenge
	// response data maps below.
	challMu sync.RWMutex

	// requestHistory is a map from hostname to a map of event type to a list of
	// sequential request events
	requestHistory map[string]map[RequestEventType][]RequestEvent

	// httpOne is a map of token values to key authorizations used for HTTP-01
	// responses.
	httpOne map[string]string

	// dnsOne is a map of DNS host values to key authorizations used for DNS-01
	// responses.
	dnsOne map[string][]string

	// dnsMocks holds mock DNS data used to respond to DNS queries other than
	// DNS-01 TXT challenge lookups.
	dnsMocks mockDNSData

	// tlsALPNOne is a map of token values to key authorizations used for TLS-ALPN-01
	// responses.
	tlsALPNOne map[string]string

	// redirects is a map of paths to URLs. HTTP challenge servers respond to
	// requests for these paths with a 301 to the corresponding URL.
	redirects map[string]string
}

// mockDNSData holds mock responses for DNS A, AAAA, and CAA lookups.
type mockDNSData struct {
	// The IPv4 address used for all A record responses that don't match a host in
	// aRecords.
	defaultIPv4 string
	// The IPv6 address used for all AAAA record responses that don't match a host
	// in aaaaRecords.
	defaultIPv6 string
	// A map of host to IPv4 addresses in string form for A record responses.
	aRecords map[string][]string
	// A map of host to IPv6 addresses in string form for AAAA record responses.
	aaaaRecords map[string][]string
	// A map of host to CAA policies for CAA responses.
	caaRecords map[string][]MockCAAPolicy
	// A map of host to CNAME records.
	cnameRecords map[string]string
}

// MockCAAPolicy holds a tag and a value for a CAA record. See
// https://tools.ietf.org/html/rfc6844
type MockCAAPolicy struct {
	Tag   string
	Value string
}

// Config holds challenge server configuration
type Config struct {
	Log *log.Logger
	// HTTPOneAddrs are the HTTP-01 challenge server bind addresses/ports
	HTTPOneAddrs []string
	// HTTPSOneAddrs are the HTTPS HTTP-01 challenge server bind addresses/ports
	HTTPSOneAddrs []string
	// DNSOneAddrs are the DNS-01 challenge server bind addresses/ports
	DNSOneAddrs []string
	// TLSALPNOneAddrs are the TLS-ALPN-01 challenge server bind addresses/ports
	TLSALPNOneAddrs []string
}

// validate checks that a challenge server Config is valid. To be valid it must
// specify a bind address for at least one challenge type. If there is no
// configured log in the config a default is provided.
func (c *Config) validate() error {
	// There needs to be at least one challenge type with a bind address
	if len(c.HTTPOneAddrs) < 1 &&
		len(c.HTTPSOneAddrs) < 1 &&
		len(c.DNSOneAddrs) < 1 &&
		len(c.TLSALPNOneAddrs) < 1 {
		return fmt.Errorf(
			"config must specify at least one HTTPOneAddrs entry, one HTTPSOneAddr " +
				"entry, one DNSOneAddrs entry, or one TLSALPNOneAddrs entry")
	}
	// If there is no configured log make a default with a prefix
	if c.Log == nil {
		c.Log = log.New(os.Stdout, "challtestsrv - ", log.LstdFlags)
	}
	return nil
}

// New constructs and returns a new ChallSrv instance with the given Config.
func New(config Config) (*ChallSrv, error) {
	// Validate the provided configuration
	if err := config.validate(); err != nil {
		return nil, err
	}

	challSrv := &ChallSrv{
		log:            config.Log,
		requestHistory: make(map[string]map[RequestEventType][]RequestEvent),
		httpOne:        make(map[string]string),
		dnsOne:         make(map[string][]string),
		tlsALPNOne:     make(map[string]string),
		redirects:      make(map[string]string),
		dnsMocks: mockDNSData{
			defaultIPv4:  defaultIPv4,
			defaultIPv6:  defaultIPv6,
			aRecords:     make(map[string][]string),
			aaaaRecords:  make(map[string][]string),
			caaRecords:   make(map[string][]MockCAAPolicy),
			cnameRecords: make(map[string]string),
		},
	}

	// If there are HTTP-01 addresses configured, create HTTP-01 servers with
	// HTTPS disabled.
	for _, address := range config.HTTPOneAddrs {
		challSrv.log.Printf("Creating HTTP-01 challenge server on %s\n", address)
		challSrv.servers = append(challSrv.servers, httpOneServer(address, challSrv, false))
	}

	// If there are HTTPS HTTP-01 addresses configured, create HTTP-01 servers
	// with HTTPS enabled.
	for _, address := range config.HTTPSOneAddrs {
		challSrv.log.Printf("Creating HTTPS HTTP-01 challenge server on %s\n", address)
		challSrv.servers = append(challSrv.servers, httpOneServer(address, challSrv, true))
	}

	// If there are DNS-01 addresses configured, create DNS-01 servers
	for _, address := range config.DNSOneAddrs {
		challSrv.log.Printf("Creating TCP and UDP DNS-01 challenge server on %s\n", address)
		challSrv.servers = append(challSrv.servers,
			dnsOneServer(address, challSrv.dnsHandler)...)
	}

	// If there are TLS-ALPN-01 addresses configured, create TLS-ALPN-01 servers
	for _, address := range config.TLSALPNOneAddrs {
		challSrv.log.Printf("Creating TLS-ALPN-01 challenge server on %s\n", address)
		challSrv.servers = append(challSrv.servers, tlsALPNOneServer(address, challSrv))
	}

	return challSrv, nil
}

// Run starts each of the ChallSrv's challengeServers.
func (s *ChallSrv) Run() {
	s.log.Printf("Starting challenge servers")

	// Start each server in their own dedicated Go routine
	for _, srv := range s.servers {
		go func(srv challengeServer) {
			err := srv.ListenAndServe()
			if err != nil {
				s.log.Print(err)
			}
		}(srv)
	}
}

// Shutdown gracefully stops each of the ChallSrv's challengeServers.
func (s *ChallSrv) Shutdown() {
	for _, srv := range s.servers {
		if err := srv.Shutdown(); err != nil {
			s.log.Printf("err in Shutdown(): %s\n", err.Error())
		}
	}
}
