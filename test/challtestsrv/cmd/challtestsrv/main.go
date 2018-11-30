package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"

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

func (srv *managementServer) Run() {
	srv.log.Printf("Starting management server")
	// Start the HTTP server in its own dedicated Go routine
	go func() {
		err := srv.ListenAndServe()
		if err != nil {
			srv.log.Print(err)
		}
	}()
}

func (srv *managementServer) Shutdown() {
	srv.log.Printf("Shutting down management server")
	if err := srv.Server.Shutdown(context.Background()); err != nil {
		srv.log.Printf("Err shutting down management server")
	}
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
	tlsAlpnOneBind := flag.String("tlsalpn01", ":5001",
		"Comma separated bind addresses/ports for TLS-ALPN-01 challenges and HTTPS HTTP-01 challenges. Set empty to disable.")
	managementBind := flag.String("management", ":8055",
		"Bind address/port for management HTTP interface")

	flag.Parse()

	httpOneAddresses := filterEmpty(strings.Split(*httpOneBind, ","))
	dnsOneAddresses := filterEmpty(strings.Split(*dnsOneBind, ","))
	tlsAlpnOneAddresses := filterEmpty(strings.Split(*tlsAlpnOneBind, ","))

	logger := log.New(os.Stdout, "challtestsrv - ", log.Ldate|log.Ltime)

	// Create a new challenge server with the provided config
	srv, err := challtestsrv.New(challtestsrv.Config{
		HTTPOneAddrs:    httpOneAddresses,
		DNSOneAddrs:     dnsOneAddresses,
		TLSALPNOneAddrs: tlsAlpnOneAddresses,
		Log:             logger,
	})
	cmd.FailOnError(err, "Unable to construct challenge server")

	// Create a new management server with the provided config
	oobSrv := managementServer{
		Server: &http.Server{
			Addr: *managementBind,
		},
		challSrv: srv,
		log:      logger,
	}
	// Register handlers on the management server for adding challenge responses
	// for the configured challenges.
	if *httpOneBind != "" {
		http.HandleFunc("/add-http01", oobSrv.addHTTP01)
		http.HandleFunc("/del-http01", oobSrv.delHTTP01)
		http.HandleFunc("/add-redirect", oobSrv.addHTTPRedirect)
		http.HandleFunc("/del-redirect", oobSrv.delHTTPRedirect)
	}
	if *dnsOneBind != "" {
		http.HandleFunc("/set-txt", oobSrv.addDNS01)
		http.HandleFunc("/clear-txt", oobSrv.delDNS01)
	}
	if *tlsAlpnOneBind != "" {
		http.HandleFunc("/add-tlsalpn01", oobSrv.addTLSALPN01)
		http.HandleFunc("/del-tlsalpn01", oobSrv.delTLSALPN01)
	}

	// Start all of the sub-servers in their own Go routines so that the main Go
	// routine can spin forever looking for signals to catch.
	go srv.Run()
	go oobSrv.Run()

	cmd.CatchSignals(nil, func() {
		logger.Printf("Caught signals. Shutting down")
		srv.Shutdown()
		oobSrv.Shutdown()
		logger.Printf("Goodbye!")
	})
}
