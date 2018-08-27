package challtestsrv

import (
	"fmt"
	"log"
	"os"
	"sync"
)

type challengeServer interface {
	ListenAndServe() error
	Shutdown() error
}

// ChallSrv is a multi-purpose challenge server. Each ChallSrv may have one or
// more ACME challenges it provides servers for.
type ChallSrv struct {
	log *log.Logger

	// challMu is a RWMutex used to control concurrent updates to challenge
	// response maps `httpOne` and `dnsOne`.
	challMu sync.RWMutex

	// servers are the individual challenge server listeners started in New() and
	// closed in Shutdown()
	servers []challengeServer

	// httpOne is a map of token values to key authorizations used for HTTP-01
	// responses
	httpOne map[string]string

	// dnsOne is a map of DNS host values to key authorizations used for DNS-01
	// responses
	dnsOne map[string][]string

	// tlsALPNOne is a map of token values to key authorizations used for TLS-ALPN-01
	// responses
	tlsALPNOne map[string]string
}

// Config holds challenge server configuration
type Config struct {
	Log *log.Logger
	// HTTPOneAddrs are the HTTP-01 challenge server bind addresses/ports
	HTTPOneAddrs []string
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
	if len(c.HTTPOneAddrs) < 1 && len(c.DNSOneAddrs) < 1 && len(c.TLSALPNOneAddrs) < 1 {
		return fmt.Errorf(
			"config must specify at least one HTTPOneAddrs entry, one DNSOneAddrs entry, or one TLSALPNOneAddrs entry")
	}
	// If there is no configured log make a default with a prefix
	if c.Log == nil {
		c.Log = log.New(os.Stdout, "challsrv - ", log.LstdFlags)
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
		log: config.Log,

		httpOne:    make(map[string]string),
		dnsOne:     make(map[string][]string),
		tlsALPNOne: make(map[string]string),
	}

	// If there are HTTP-01 addresses configured, create HTTP-01 servers
	for _, address := range config.HTTPOneAddrs {
		challSrv.log.Printf("Creating HTTP-01 challenge server on %s\n", address)
		challSrv.servers = append(challSrv.servers, httpOneServer(address, challSrv))
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
