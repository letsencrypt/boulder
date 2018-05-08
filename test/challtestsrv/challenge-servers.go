package challtestsrv

import (
	"fmt"
	"log"
	"os"
	"sync"
)

// ChallSrv is a multi-purpose challenge server. Each ChallSrv may have one or
// more ACME challenges it provides servers for.
type ChallSrv struct {
	log *log.Logger
	// Shutdown is a channel used to request the challenge server cleanly shut down
	shutdown chan bool

	// challMu is a RWMutex used to control concurrent updates to challenge
	// response maps `httpOne` and `dnsOne`.
	challMu sync.RWMutex

	// httpOneAddrs are the HTTP-01 challenge server bind address(es)/port(s). If
	// none are specified no HTTP-01 challenge server is run. If multiple are
	// specified an HTTP-01 challenge response server will be bound to each
	// address.
	httpOneAddrs []string
	// httpOne is a map of token values to key authorizations used for HTTP-01
	// responses
	httpOne map[string]string

	// dnsOneAddr are the DNS-01 challenge server bind address(es)/port(s). If
	// none are specified no DNS-01 challenge server is run. If multiple are
	// specified a DNS-01 challenge response server will be bound to each address.
	dnsOneAddrs []string
	// dnsOne is a map of DNS host values to key authorizations used for DNS-01
	// responses
	dnsOne map[string][]string
}

// Config holds challenge server configuration
type Config struct {
	Log *log.Logger
	// HTTPOneAddrs are the HTTP-01 challenge server bind addresses/ports
	HTTPOneAddrs []string
	// DNSOneAddrs are the DNS-01 challenge server bind addresses/ports
	DNSOneAddrs []string
}

// validate checks that a challenge server Config is valid. To be valid it must
// specify a bind address for at least one challenge type. If there is no
// configured log in the config a default is provided.
func (c *Config) validate() error {
	// There needs to be at least one challenge time with a bind address
	if len(c.HTTPOneAddrs) < 1 && len(c.DNSOneAddrs) < 1 {
		return fmt.Errorf(
			"config must specify at least one HTTPOneAddrs entry or one DNSOneAddrs entry")
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
	// Construct and return a challenge server
	return &ChallSrv{
		log:      config.Log,
		shutdown: make(chan bool),

		httpOne:      make(map[string]string),
		httpOneAddrs: config.HTTPOneAddrs,

		dnsOneAddrs: config.DNSOneAddrs,
		dnsOne:      make(map[string][]string),
	}, nil
}

// Run runs the configured challenge servers blocking until a shutdown request
// is received on the shutdown channel. When a shutdown occurs the configured
// challenge servers will be cleanly shutdown and the provided WaitGroup will
// have its `Done()` function called. This allows the caller to wait on the
// waitgroup and know that they will not unblock until all challenge servers are
// cleanly stopped.
func (s *ChallSrv) Run(wg *sync.WaitGroup) {
	// Cleanups collects the cleanup functions returned by the servers that are
	// started.
	var cleanups []func()

	// If there are HTTP-01 addresses configured, start HTTP-01 servers
	for _, address := range s.httpOneAddrs {
		cleanups = append(cleanups, s.httpOneServer(address))
	}

	// If there are DNS-01 addresses configured, start DNS-01 servers
	for _, address := range s.dnsOneAddrs {
		cleanups = append(cleanups, s.dnsOneServer(address))
	}

	// Block forever waiting for a shutdown request
	<-s.shutdown
	// When a shutdown occurs, call each of the cleanup routines
	s.log.Printf("Shutting down challenge servers")
	for _, cleanup := range cleanups {
		cleanup()
	}
	// When the cleanup is finished call Done() on the WG
	s.log.Printf("Challenge servers shut down")
	wg.Done()
}

// Shutdown writes a shutdown request to the challenge server's shutdown
// channel. This will unblock the Go-routine running Run(), beginning the
// cleanup process.
func (s *ChallSrv) Shutdown() {
	s.shutdown <- true
}
