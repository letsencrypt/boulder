package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/test/challtestsrv"
)

// managementServer is a small HTTP server that can control a challenge server,
// adding and deleting challenge responses as required
type managementServer struct {
	// A managementServer is a http.Server
	*http.Server
	log *log.Logger
	// The challenge server that is under control by the management server
	challSrv *challtestsrv.ChallSrv
	// Shutdown is a channel used to request the management server cleanly shut down
	shutdown chan bool
}

// Run runs the management server blocking until a shutdown request is received
// on the shutdown channel. When a shutdown occurs the management HTTP server
// will be cleanly shutdown and the provided WaitGroup will have its `Done()`
// function called. This allows the caller to wait on the waitgroup and know
// that they will not unblock until the management server is cleanly stopped.
func (srv *managementServer) Run(wg *sync.WaitGroup) {
	srv.log.Printf("Starting management server")
	// Start the HTTP server in its own dedicated Go routine
	go func() {
		err := srv.ListenAndServe()
		if err != nil {
			srv.log.Print(err)
		}
	}()

	// Block forever waiting for a shutdown request
	<-srv.shutdown
	// When a shutdown request arrives cleanly stop the HTTP server
	srv.log.Printf("Shutting down management server")
	if err := srv.Server.Shutdown(context.Background()); err != nil {
		srv.log.Printf("Err shutting down management server")
	}
	// When the cleanup is finished call Done() on the WG
	wg.Done()
}

// Shutdown writes a shutdown request to the management server's shutdown
// channel. This will unblock the Go-routine running Run(), beginning the
// cleanup process.
func (srv *managementServer) Shutdown() {
	srv.shutdown <- true
}

func filterEmpty(input []string) []string {
	var output []string
	for _, val := range input {
		trimmed := strings.TrimSpace(val)
		if trimmed != "" {
			output = append(output, trimmed)
		}
	}
	return output
}

func main() {
	httpOneBind := flag.String("http01", ":5002",
		"Comma separated bind addresses/ports for HTTP-01 challenges. Set empty to disable.")
	dnsOneBind := flag.String("dns01", ":8053",
		"Comma separated bind addresses/ports for DNS-01 challenges and fake DNS data. Set empty to disable.")
	managementBind := flag.String("management", ":8056",
		"Bind address/port for management HTTP interface")

	flag.Parse()

	httpOneAddresses := filterEmpty(strings.Split(*httpOneBind, ","))
	dnsOneAddresses := filterEmpty(strings.Split(*dnsOneBind, ","))

	// Create a default logger with the challsrv binary name as a prefix
	logger := log.New(os.Stdout, "challsrv - ", log.Ldate|log.Ltime)

	// Create a new challenge server with the provided config
	srv, err := challtestsrv.New(challtestsrv.Config{
		HTTPOneAddrs: httpOneAddresses,
		DNSOneAddrs:  dnsOneAddresses,
		Log:          logger,
	})
	cmd.FailOnError(err, "Unable to construct challenge server")

	// Create a new management server with the provided config
	oobSrv := managementServer{
		Server: &http.Server{
			Addr: *managementBind,
		},
		challSrv: srv,
		log:      logger,
		shutdown: make(chan bool),
	}
	// Register handlers on the management server for adding challenge responses
	// for the configured challenges.
	if *httpOneBind != "" {
		http.HandleFunc("/add-http01", oobSrv.addHTTP01)
		http.HandleFunc("/del-http01", oobSrv.delHTTP01)
	}
	if *dnsOneBind != "" {
		http.HandleFunc("/set-txt", oobSrv.addDNS01)
		http.HandleFunc("/clear-txt", oobSrv.delDNS01)
	}

	// Create a waitgroup that can be used to know when all of the servers have
	// been cleanly shut down after a shutdown request is sent.
	wg := new(sync.WaitGroup)

	// Start the challenge servers in a Go routine
	wg.Add(1)
	go srv.Run(wg)

	// Start the OOB server in a Go routine
	wg.Add(1)
	go oobSrv.Run(wg)

	// Block the main Go routine to wait for signals to arrive from the OS
	cmd.CatchSignals(nil, func() {
		// If a signal arrives, request clean shutdowns of the challenge server(s)
		// and the management server
		logger.Printf("Caught signals. Shutting down")
		srv.Shutdown()
		oobSrv.Shutdown()
		// Block until all of shutdowns calls above have completed cleanly
		wg.Wait()
		logger.Printf("Goodbye!")
	})
}
