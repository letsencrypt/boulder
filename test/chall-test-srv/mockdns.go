// addDNS01 handles an HTTP POST request to add a new DNS-01 challenge TXT
package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/letsencrypt/challtestsrv"
	"github.com/miekg/dns"
)

// setDefaultDNSIPv4 handles an HTTP POST request to set the default IPv4
// address used for all A query responses that do not match more-specific mocked
// responses.
//
// The POST body is expected to have one parameter:
// "ip" - the string representation of an IPv4 address to use for all A queries
// that do not match more specific mocks.
//
// Providing an empty string as the IP value will disable the default
// A responses.
//
// A successful POST will write http.StatusOK to the client.
func (srv *managementServer) setDefaultDNSIPv4(w http.ResponseWriter, r *http.Request) {
	var request struct {
		IP string
	}
	if err := mustParsePOST(&request, r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Set the challenge server's default IPv4 address - we allow request.IP to be
	// the empty string so that the default can be cleared using the same
	// method.
	srv.challSrv.SetDefaultDNSIPv4(request.IP)
	srv.log.Printf("Set default IPv4 address for DNS A queries to %q\n", request.IP)
	w.WriteHeader(http.StatusOK)
}

// setDefaultDNSIPv6 handles an HTTP POST request to set the default IPv6
// address used for all AAAA query responses that do not match more-specific
// mocked responses.
//
// The POST body is expected to have one parameter:
// "ip" - the string representation of an IPv6 address to use for all AAAA
// queries that do not match more specific mocks.
//
// Providing an empty string as the IP value will disable the default
// A responses.
//
// A successful POST will write http.StatusOK to the client.
func (srv *managementServer) setDefaultDNSIPv6(w http.ResponseWriter, r *http.Request) {
	var request struct {
		IP string
	}
	if err := mustParsePOST(&request, r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Set the challenge server's default IPv6 address - we allow request.IP to be
	// the empty string so that the default can be cleared using the same
	// method.
	srv.challSrv.SetDefaultDNSIPv6(request.IP)
	srv.log.Printf("Set default IPv6 address for DNS AAAA queries to %q\n", request.IP)
	w.WriteHeader(http.StatusOK)
}

// addDNSARecord handles an HTTP POST request to add a mock A query response record
// for a host.
//
// The POST body is expected to have two non-empty parameters:
// "host" - the hostname that when queried should return the mocked A record.
// "addresses" - an array of IPv4 addresses in string representation that should
// be used for the A records returned for the query.
//
// A successful POST will write http.StatusOK to the client.
func (srv *managementServer) addDNSARecord(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Host      string
		Addresses []string
	}
	if err := mustParsePOST(&request, r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// If the request has no addresses or an empty host it's a bad request
	if len(request.Addresses) == 0 || request.Host == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	srv.challSrv.AddDNSARecord(request.Host, request.Addresses)
	srv.log.Printf("Added response for DNS A queries to %q : %s\n",
		request.Host, strings.Join(request.Addresses, ", "))
	w.WriteHeader(http.StatusOK)
}

// delDNSARecord handles an HTTP POST request to delete an existing mock A
// policy record for a host.
//
// The POST body is expected to have one non-empty parameter:
// "host" - the hostname to remove the mock A record for.
//
// A successful POST will write http.StatusOK to the client.
func (srv *managementServer) delDNSARecord(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Host string
	}
	if err := mustParsePOST(&request, r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// If the request has an empty host it's a bad request
	if request.Host == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	srv.challSrv.DeleteDNSARecord(request.Host)
	srv.log.Printf("Removed response for DNS A queries to %q", request.Host)
	w.WriteHeader(http.StatusOK)
}

// addDNSAAAARecord handles an HTTP POST request to add a mock AAAA query
// response record for a host.
//
// The POST body is expected to have two non-empty parameters:
// "host" - the hostname that when queried should return the mocked A record.
// "addresses" - an array of IPv6 addresses in string representation that should
// be used for the AAAA records returned for the query.
//
// A successful POST will write http.StatusOK to the client.
func (srv *managementServer) addDNSAAAARecord(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Host      string
		Addresses []string
	}
	if err := mustParsePOST(&request, r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// If the request has no addresses or an empty host it's a bad request
	if len(request.Addresses) == 0 || request.Host == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	srv.challSrv.AddDNSAAAARecord(request.Host, request.Addresses)
	srv.log.Printf("Added response for DNS AAAA queries to %q : %s\n",
		request.Host, strings.Join(request.Addresses, ", "))
	w.WriteHeader(http.StatusOK)
}

// delDNSAAAARecord handles an HTTP POST request to delete an existing mock AAAA
// policy record for a host.
//
// The POST body is expected to have one non-empty parameter:
// "host" - the hostname to remove the mock AAAA record for.
//
// A successful POST will write http.StatusOK to the client.
func (srv *managementServer) delDNSAAAARecord(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Host string
	}
	if err := mustParsePOST(&request, r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// If the request has an empty host it's a bad request
	if request.Host == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	srv.challSrv.DeleteDNSAAAARecord(request.Host)
	srv.log.Printf("Removed response for DNS AAAA queries to %q", request.Host)
	w.WriteHeader(http.StatusOK)
}

// addDNSCAARecord handles an HTTP POST request to add a mock CAA query
// response record for a host.
//
// The POST body is expected to have two non-empty parameters:
// "host" - the hostname that when queried should return the mocked CAA record.
// "policies" - an array of CAA policy objects. Each policy object is expected
// to have two non-empty keys, "tag" and "value".
//
// A successful POST will write http.StatusOK to the client.
func (srv *managementServer) addDNSCAARecord(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Host     string
		Policies []challtestsrv.CAAPolicy
	}
	if err := mustParsePOST(&request, r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// If the request has no host or no caa policies it's a bad request
	if request.Host == "" || len(request.Policies) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	srv.challSrv.AddDNSCAARecord(request.Host, request.Policies)
	srv.log.Printf("Added response for DNS CAA queries to %q", request.Host)
	w.WriteHeader(http.StatusOK)
}

// delDNSCAARecord handles an HTTP POST request to delete an existing mock CAA
// policy record for a host.
//
// The POST body is expected to have one non-empty parameter:
// "host" - the hostname to remove the mock CAA policy for.
//
// A successful POST will write http.StatusOK to the client.
func (srv *managementServer) delDNSCAARecord(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Host string
	}
	if err := mustParsePOST(&request, r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// If the request has an empty host it's a bad request
	if request.Host == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	srv.challSrv.DeleteDNSCAARecord(request.Host)
	srv.log.Printf("Removed response for DNS CAA queries to %q", request.Host)
	w.WriteHeader(http.StatusOK)
}

// addDNSCNAMERecord handles an HTTP POST request to add a mock CNAME query
// response record and alias for a host.
//
// The POST body is expected to have two non-empty parameters:
// "host" - the hostname that should be treated as an alias to the target
// "target" - the hostname whose mocked DNS records should be returned
//
// A successful POST will write http.StatusOK to the client.
func (srv *managementServer) addDNSCNAMERecord(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Host   string
		Target string
	}
	if err := mustParsePOST(&request, r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// If the request has no host or no caa policies it's a bad request
	if request.Host == "" || request.Target == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	srv.challSrv.AddDNSCNAMERecord(request.Host, request.Target)
	srv.log.Printf("Added response for DNS CNAME queries to %q targeting %q", request.Host, request.Target)
	w.WriteHeader(http.StatusOK)
}

// delDNSCNAMERecord handles an HTTP POST request to delete an existing mock
// CNAME record for a host.
//
// The POST body is expected to have one non-empty parameters:
// "host" - the hostname to remove the mock CNAME alias for.
//
// A successful POST will write http.StatusOK to the client.
func (srv *managementServer) delDNSCNAMERecord(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Host string
	}
	if err := mustParsePOST(&request, r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// If the request has an empty host it's a bad request
	if request.Host == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	srv.challSrv.DeleteDNSCNAMERecord(request.Host)
	srv.log.Printf("Removed response for DNS CNAME queries to %q", request.Host)
	w.WriteHeader(http.StatusOK)
}

// addDNSServFailRecord handles an HTTP POST request to add a mock SERVFAIL
// response record for a host. All queries for that host will subsequently
// result in SERVFAIL responses, overriding any other mocks.
//
// The POST body is expected to have one non-empty parameter:
// "host" - the hostname that should return SERVFAIL responses.
//
// A successful POST will write http.StatusOK to the client.
func (srv *managementServer) addDNSServFailRecord(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Host string
	}
	if err := mustParsePOST(&request, r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// If the request has no host it's a bad request
	if request.Host == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	srv.challSrv.AddDNSServFailRecord(request.Host)
	srv.log.Printf("Added SERVFAIL response for DNS queries to %q", request.Host)
	w.WriteHeader(http.StatusOK)
}

// delDNSServFailRecord handles an HTTP POST request to delete an existing mock
// SERVFAIL record for a host.
//
// The POST body is expected to have one non-empty parameters:
// "host" - the hostname to remove the mock SERVFAIL response from.
//
// A successful POST will write http.StatusOK to the client.
func (srv *managementServer) delDNSServFailRecord(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Host string
	}
	if err := mustParsePOST(&request, r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// If the request has an empty host it's a bad request
	if request.Host == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	srv.challSrv.DeleteDNSServFailRecord(request.Host)
	srv.log.Printf("Removed SERVFAIL response for DNS queries to %q", request.Host)
	w.WriteHeader(http.StatusOK)
}

// addDNSHTTPSRecord handles an HTTP POST request to add a mock HTTPS record
// (RFC 9460) for a host.
//
// The POST body is expected to have two non-empty parameters:
// "host" - the hostname that should have the mock HTTPS record
// "record" - the record in presentation format, without its owner name, class,
// or type, e.g. "1 . ech=AEX+DQ..."
//
// A successful POST will write http.StatusOK to the client.
func (srv *managementServer) addDNSHTTPSRecord(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Host   string
		Record string
	}
	if err := mustParsePOST(&request, r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// If the request has no host or no record it's a bad request
	if request.Host == "" || request.Record == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	rr, err := dns.NewRR(fmt.Sprintf("%s IN HTTPS %s", dns.Fqdn(request.Host), request.Record))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	httpsRR, ok := rr.(*dns.HTTPS)
	if !ok {
		http.Error(w, "record is not an HTTPS record", http.StatusBadRequest)
		return
	}

	srv.challSrv.AddDNSHTTPSRecord(request.Host, *httpsRR)
	srv.log.Printf("Added response for DNS HTTPS queries to %q", request.Host)
	w.WriteHeader(http.StatusOK)
}

// delDNSHTTPSRecord handles an HTTP POST request to delete all mock HTTPS
// records for a host.
//
// The POST body is expected to have one non-empty parameter:
// "host" - the hostname to remove the mock HTTPS records for.
//
// A successful POST will write http.StatusOK to the client.
func (srv *managementServer) delDNSHTTPSRecord(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Host string
	}
	if err := mustParsePOST(&request, r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// If the request has an empty host it's a bad request
	if request.Host == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	srv.challSrv.DeleteDNSHTTPSRecord(request.Host)
	srv.log.Printf("Removed response for DNS HTTPS queries to %q", request.Host)
	w.WriteHeader(http.StatusOK)
}

// getECHConfig handles an HTTP request for the ECHConfigList accepted by the
// TLS-ALPN-01 and HTTPS HTTP-01 challenge servers. It writes the list in
// base64, as used in an HTTPS record's "ech" parameter, or writes
// http.StatusNotFound if ECH is disabled.
func (srv *managementServer) getECHConfig(w http.ResponseWriter, r *http.Request) {
	list := srv.challSrv.ECHConfigList()
	if list == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString(list)))
}
