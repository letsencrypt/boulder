package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/test/zendeskfake"
)

type config struct {
	// Addr is the address (e.g. IP:port) on which the server will listen.
	Addr string

	// ExpectedTokenEmail is the email address expected in the Authorization
	// header of each request.
	ExpectedTokenEmail string `validate:"required"`

	// ExpectedAPIToken is the API token expected in the Authorization header of
	// each request.
	ExpectedAPIToken string `validate:"required"`

	// TicketCapacity sets the in-memory store capacity. This is optional and
	// defaults to 200.
	TicketCapacity int
}

func main() {
	addr := flag.String("addr", "", "listen address override (host:port)")
	configFile := flag.String("config", "", "path to JSON config file")
	flag.Parse()

	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	if err != nil {
		cmd.FailOnError(err, "Reading JSON config file")
	}

	if *addr != "" {
		c.Addr = *addr
	}
	if c.Addr == "" {
		log.Fatalf("listen address must be provided via -addr or config file")
	}
	if c.ExpectedTokenEmail == "" || c.ExpectedAPIToken == "" {
		log.Fatalf("both ExpectedTokenEmail and ExpectedAPIToken are required (see config)")
	}

	var store *zendeskfake.Store
	if c.TicketCapacity > 0 {
		store = zendeskfake.NewStore(c.TicketCapacity)
	}
	server := zendeskfake.NewServer(c.ExpectedTokenEmail, c.ExpectedAPIToken, store)

	srv := &http.Server{
		Addr:         c.Addr,
		Handler:      server.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	log.Printf("zendesk-test-srv listening at %s", c.Addr)
	go func() {
		err := srv.ListenAndServe()
		if err != nil {
			log.Fatalf("Failed to start zendesk-test-srv: %s", err)
		}
	}()

	cmd.WaitForSignal()
}
