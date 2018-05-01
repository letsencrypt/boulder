package challsrv

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

	// httpOneAddr is the HTTP-01 challenge server bind address/port
	httpOneAddr string
	// hoMu is a RWMutex used to control concurrent updates to the HTTP-01
	// challenges in httpOne
	hoMu sync.RWMutex
	// httpOne is a map of token values to key authorizations used for HTTP-01
	// responses
	httpOne map[string]string

	// dnsOneAddr is the DNS-01 challenge server bind address/port
	dnsOneAddr string
	// dnsMu is a RWMutex used to control concurrent updates to the DNS-01
	// challenges in dnsOne
	dnsMu sync.RWMutex
	// dnsOne is a map of DNS host values to key authorizations used for DNS-01
	// responses
	dnsOne map[string][]string
}

// Config holds challenge server configuration
type Config struct {
	Log *log.Logger
	// HTTPOneAddr is the HTTP-01 challenge server bind address/port
	HTTPOneAddr string
	// DNSOneAddr is the DNS-01 challenge server bind address/port
	DNSOneAddr string
}

// validate checks that a challenge server Config is valid. To be valid it must
// specify a bind address for at least one challenge type. If there is no
// configured log in the config a default is provided.
func (c *Config) validate() error {
	// There needs to be at least one challenge time with a bind address
	if c.HTTPOneAddr == "" && c.DNSOneAddr == "" {
		return fmt.Errorf("config specified empty HTTPOneAddr and DNSOneAddr values")
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

		httpOne:     make(map[string]string),
		httpOneAddr: config.HTTPOneAddr,

		dnsOneAddr: config.DNSOneAddr,
		dnsOne:     make(map[string][]string),
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

	// If there is an HTTP-01 address configured, start an HTTP-01 server
	if s.httpOneAddr != "" {
		s.log.Printf("Starting HTTP-01 server")
		cleanups = append(cleanups, s.httpOneServer())
	}

	// If there is a DNS-01 address configured, start a DNS-01 server
	if s.dnsOneAddr != "" {
		s.log.Printf("Starting DNS-01 server")
		cleanups = append(cleanups, s.dnsOneServer())
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
