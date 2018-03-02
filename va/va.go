package va

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/context"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/probs"
)

const (
	maxRedirect      = 10
	whitespaceCutset = "\n\r\t "
	// Payload should be ~87 bytes. Since it may be padded by whitespace which we previously
	// allowed accept up to 128 bytes before rejecting a response
	// (32 byte b64 encoded token + . + 32 byte b64 encoded key fingerprint)
	maxResponseSize = 128
)

// singleDialTimeout specifies how long an individual `Dial` operation may take
// before timing out. This timeout ignores the base RPC timeout and is strictly
// used for the Dial operations that take place during an
// HTTP-01/TLS-SNI-[01|02] challenge validation.
var singleDialTimeout = time.Second * 10

// RemoteVA wraps the core.ValidationAuthority interface and adds a field containing the addresses
// of the remote gRPC server since the interface (and the underlying gRPC client) doesn't
// provide a way to extract this metadata which is useful for debugging gRPC connection issues.
type RemoteVA struct {
	core.ValidationAuthority
	Addresses string
}

type vaMetrics struct {
	validationTime           *prometheus.HistogramVec
	remoteValidationTime     *prometheus.HistogramVec
	remoteValidationFailures prometheus.Counter
}

func initMetrics(stats metrics.Scope) *vaMetrics {
	validationTime := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "validation_time",
			Help:    "Time taken to validate a challenge",
			Buckets: []float64{.1, .25, .5, 1, 2.5, 5, 7.5, 10, 15, 30, 45},
		},
		[]string{"type", "result"})
	stats.MustRegister(validationTime)
	remoteValidationTime := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "remote_validation_time",
			Help:    "Time taken to remotely validate a challenge",
			Buckets: []float64{.1, .25, .5, 1, 2.5, 5, 7.5, 10, 15, 30, 45},
		},
		[]string{"type", "result"})
	stats.MustRegister(remoteValidationTime)
	remoteValidationFailures := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "remote_validation_failures",
			Help: "Number of validations failed due to remote VAs returning failure",
		})
	stats.MustRegister(remoteValidationFailures)

	return &vaMetrics{
		validationTime:           validationTime,
		remoteValidationTime:     remoteValidationTime,
		remoteValidationFailures: remoteValidationFailures,
	}
}

// ValidationAuthorityImpl represents a VA
type ValidationAuthorityImpl struct {
	log               blog.Logger
	dnsClient         bdns.DNSClient
	issuerDomain      string
	safeBrowsing      SafeBrowsing
	httpPort          int
	httpsPort         int
	tlsPort           int
	userAgent         string
	stats             metrics.Scope
	clk               clock.Clock
	remoteVAs         []RemoteVA
	maxRemoteFailures int

	metrics *vaMetrics
}

// NewValidationAuthorityImpl constructs a new VA
func NewValidationAuthorityImpl(
	pc *cmd.PortConfig,
	sbc SafeBrowsing,
	resolver bdns.DNSClient,
	remoteVAs []RemoteVA,
	maxRemoteFailures int,
	userAgent string,
	issuerDomain string,
	stats metrics.Scope,
	clk clock.Clock,
	logger blog.Logger,
) *ValidationAuthorityImpl {

	return &ValidationAuthorityImpl{
		log:               logger,
		dnsClient:         resolver,
		issuerDomain:      issuerDomain,
		safeBrowsing:      sbc,
		httpPort:          pc.HTTPPort,
		httpsPort:         pc.HTTPSPort,
		tlsPort:           pc.TLSPort,
		userAgent:         userAgent,
		stats:             stats,
		clk:               clk,
		metrics:           initMetrics(stats),
		remoteVAs:         remoteVAs,
		maxRemoteFailures: maxRemoteFailures,
	}
}

// Used for audit logging
type verificationRequestEvent struct {
	ID                string                  `json:",omitempty"`
	Requester         int64                   `json:",omitempty"`
	Hostname          string                  `json:",omitempty"`
	ValidationRecords []core.ValidationRecord `json:",omitempty"`
	Challenge         core.Challenge          `json:",omitempty"`
	RequestTime       time.Time               `json:",omitempty"`
	ResponseTime      time.Time               `json:",omitempty"`
	Error             string                  `json:",omitempty"`
}

// getAddr will query for all A/AAAA records associated with hostname and return
// the preferred address, the first net.IP in the addrs slice, and all addresses
// resolved. This is the same choice made by the Go internal resolution library
// used by net/http.
func (va ValidationAuthorityImpl) getAddr(ctx context.Context, hostname string) (net.IP, []net.IP, *probs.ProblemDetails) {
	addrs, err := va.dnsClient.LookupHost(ctx, hostname)
	if err != nil {
		va.log.Debug(fmt.Sprintf("%s DNS failure: %s", hostname, err))
		problem := probs.ConnectionFailure(err.Error())
		return net.IP{}, nil, problem
	}

	if len(addrs) == 0 {
		problem := probs.UnknownHost(
			fmt.Sprintf("No valid IP addresses found for %s", hostname),
		)
		return net.IP{}, nil, problem
	}
	addr := addrs[0]
	va.log.Debug(fmt.Sprintf("Resolved addresses for %s [using %s]: %s", hostname, addr, addrs))
	return addr, addrs, nil
}

// http01Dialer is a struct that exists to provide a dialer like object with
// a `Dial` method that can be given to an http.Transport for HTTP-01
// validation. The primary purpose of the http01Dialer's Dial method is to
// circumvent traditional DNS lookup and to use the IP addresses provided in the
// inner `record` member populated by the `resolveAndConstructDialer` function.
type http01Dialer struct {
	record      core.ValidationRecord
	stats       metrics.Scope
	dialerCount int
}

// realDialer is used to create a true `net.Dialer` that can be used once an IP
// address to connect to is determined. It increments the `dialerCount` integer
// to track how many "fresh" dialer instances have been created during a `Dial`
// for testing purposes.
func (d *http01Dialer) realDialer() *net.Dialer {
	// Record that we created a new instance of a real net.Dialer
	d.dialerCount++
	return &net.Dialer{Timeout: singleDialTimeout}
}

// Dial processes the IP addresses from the inner validation record, using
// `realDialer` to make connections as required. If `features.IPv6First` is
// enabled then for dual-homed hosts an initial IPv6 connection will be made
// followed by a IPv4 connection if there is a failure with the IPv6 connection.
func (d *http01Dialer) Dial(_, _ string) (net.Conn, error) {
	var realDialer *net.Dialer

	// Split the available addresses into v4 and v6 addresses
	v4, v6 := availableAddresses(d.record)

	// If the IPv6 first feature isn't enabled then combine available IPv4 and
	// IPv6 addresses and connect to the first IP in the combined list
	if !features.Enabled(features.IPv6First) {
		addresses := append(v4, v6...)
		// This shouldn't happen, but be defensive about it anyway
		if len(addresses) < 1 {
			return nil, fmt.Errorf("no IP addresses found for %q", d.record.Hostname)
		}
		address := net.JoinHostPort(addresses[0].String(), d.record.Port)
		d.record.AddressUsed = addresses[0]
		realDialer = d.realDialer()
		return realDialer.Dial("tcp", address)
	}

	// If the IPv6 first feature is enabled and there is at least one IPv6 address
	// then try it first
	if features.Enabled(features.IPv6First) && len(v6) > 0 {
		address := net.JoinHostPort(v6[0].String(), d.record.Port)
		d.record.AddressUsed = v6[0]
		realDialer = d.realDialer()
		conn, err := realDialer.Dial("tcp", address)

		// If there is no error, return immediately
		if err == nil {
			return conn, err
		}

		// Otherwise, we note that we tried an address and fall back to trying IPv4
		d.record.AddressesTried = append(d.record.AddressesTried, d.record.AddressUsed)
		d.stats.Inc("IPv4Fallback", 1)
	}

	// If there are no IPv4 addresses and we tried an IPv6 address return an
	// error - there's nothing left to try
	if len(v4) == 0 && len(d.record.AddressesTried) > 0 {
		return nil,
			fmt.Errorf("Unable to contact %q at %q, no IPv4 addresses to try as fallback",
				d.record.Hostname, d.record.AddressesTried[0])
	} else if len(v4) == 0 && len(d.record.AddressesTried) == 0 {
		// It shouldn't be possible that there are no IPv4 addresses and no previous
		// attempts at an IPv6 address connection but be defensive about it anyway
		return nil, fmt.Errorf("no IP addresses found for %q", d.record.Hostname)
	}

	// Otherwise if there are no IPv6 addresses, or there was an error
	// talking to the first IPv6 address, try the first IPv4 address
	address := net.JoinHostPort(v4[0].String(), d.record.Port)
	d.record.AddressUsed = v4[0]
	realDialer = d.realDialer()
	return realDialer.Dial("tcp", address)
}

// availableAddresses takes a ValidationRecord and splits the AddressesResolved
// into a list of IPv4 and IPv6 addresses.
func availableAddresses(rec core.ValidationRecord) (v4 []net.IP, v6 []net.IP) {
	for _, addr := range rec.AddressesResolved {
		if addr.To4() != nil {
			v4 = append(v4, addr)
		} else {
			v6 = append(v6, addr)
		}
	}
	return
}

// resolveAndConstructDialer gets the preferred address using va.getAddr and returns
// the chosen address and dialer for that address and correct port.
func (va *ValidationAuthorityImpl) resolveAndConstructDialer(ctx context.Context, name string, port int) (http01Dialer, *probs.ProblemDetails) {
	d := http01Dialer{
		record: core.ValidationRecord{
			Hostname: name,
			Port:     strconv.Itoa(port),
		},
		stats: va.stats,
	}

	addr, allAddrs, err := va.getAddr(ctx, name)
	if err != nil {
		return d, err
	}
	d.record.AddressesResolved = allAddrs
	d.record.AddressUsed = addr
	return d, nil
}

// Validation methods

func (va *ValidationAuthorityImpl) fetchHTTP(ctx context.Context, identifier core.AcmeIdentifier, path string, useTLS bool, input core.Challenge) ([]byte, []core.ValidationRecord, *probs.ProblemDetails) {
	challenge := input

	host := identifier.Value
	scheme := "http"
	port := va.httpPort
	if useTLS {
		scheme = "https"
		port = va.httpsPort
	}

	urlHost := host
	if !((scheme == "http" && port == 80) ||
		(scheme == "https" && port == 443)) {
		urlHost = net.JoinHostPort(host, strconv.Itoa(port))
	}

	url := &url.URL{
		Scheme: scheme,
		Host:   urlHost,
		Path:   path,
	}

	va.log.AuditInfo(fmt.Sprintf("Attempting to validate %s for %s", challenge.Type, url))
	httpRequest, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		va.log.Info(fmt.Sprintf("Failed to parse URL '%s'. err=[%#v] errStr=[%s]", identifier, err, err))
		return nil, nil, probs.Malformed("URL provided for HTTP was invalid")
	}

	if va.userAgent != "" {
		httpRequest.Header["User-Agent"] = []string{va.userAgent}
	}

	dialer, prob := va.resolveAndConstructDialer(ctx, host, port)
	dialer.record.URL = url.String()
	// Start with an empty validation record list - we will add a record after
	// each dialer.Dial()
	var validationRecords []core.ValidationRecord
	if prob != nil {
		return nil, []core.ValidationRecord{dialer.record}, prob
	}

	tr := &http.Transport{
		// We are talking to a client that does not yet have a certificate,
		// so we accept a temporary, invalid one.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		// We don't expect to make multiple requests to a client, so close
		// connection immediately.
		DisableKeepAlives: true,
		// Intercept Dial in order to connect to the IP address we
		// select.
		Dial: dialer.Dial,
	}

	// Some of our users use mod_security. Mod_security sees a lack of Accept
	// headers as bot behavior and rejects requests. While this is a bug in
	// mod_security's rules (given that the HTTP specs disagree with that
	// requirement), we add the Accept header now in order to fix our
	// mod_security users' mysterious breakages. See
	// <https://github.com/SpiderLabs/owasp-modsecurity-crs/issues/265> and
	// <https://github.com/letsencrypt/boulder/issues/1019>. This was done
	// because it's a one-line fix with no downside. We're not likely to want to
	// do many more things to satisfy misunderstandings around HTTP.
	httpRequest.Header.Set("Accept", "*/*")

	logRedirect := func(req *http.Request, via []*http.Request) error {
		if len(validationRecords) >= maxRedirect {
			return fmt.Errorf("Too many redirects")
		}

		// Set Accept header for mod_security (see the other place the header is
		// set)
		req.Header.Set("Accept", "*/*")
		if va.userAgent != "" {
			req.Header["User-Agent"] = []string{va.userAgent}
		}

		urlHost = req.URL.Host
		reqHost := req.URL.Host
		var reqPort int
		if h, p, err := net.SplitHostPort(reqHost); err == nil {
			reqHost = h
			reqPort, err = strconv.Atoi(p)
			if err != nil {
				return err
			}
			if reqPort != va.httpPort && reqPort != va.httpsPort {
				return berrors.ConnectionFailureError(
					"Invalid port in redirect target. Only ports %d and %d are supported, not %d",
					va.httpPort, va.httpsPort, reqPort)
			}
		} else if strings.ToLower(req.URL.Scheme) == "https" {
			reqPort = va.httpsPort
		} else {
			reqPort = va.httpPort
		}

		dialer, err := va.resolveAndConstructDialer(ctx, reqHost, reqPort)
		dialer.record.URL = req.URL.String()
		// A subsequent dialing from a redirect means adding another validation
		// record
		validationRecords = append(validationRecords, dialer.record)
		if err != nil {
			return err
		}
		tr.Dial = dialer.Dial
		va.log.Debug(fmt.Sprintf("%s [%s] redirect from %q to %q [%s]", challenge.Type, identifier, via[len(via)-1].URL.String(), req.URL.String(), dialer.record.AddressUsed))
		return nil
	}
	client := http.Client{
		Transport:     tr,
		CheckRedirect: logRedirect,
		Timeout:       singleDialTimeout,
	}
	httpResponse, err := client.Do(httpRequest)
	// Append a validation record now that we have dialed the dialer
	validationRecords = append(validationRecords, dialer.record)
	if err != nil {
		va.log.Info(fmt.Sprintf("HTTP request to %s failed. err=[%#v] errStr=[%s]", url, err, err))
		return nil, validationRecords, detailedError(err)
	}

	body, err := ioutil.ReadAll(&io.LimitedReader{R: httpResponse.Body, N: maxResponseSize})
	closeErr := httpResponse.Body.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		va.log.Info(fmt.Sprintf("Error reading HTTP response body from %s. err=[%#v] errStr=[%s]", url.String(), err, err))
		return nil, validationRecords, probs.Unauthorized(fmt.Sprintf("Error reading HTTP response body: %v", err))
	}
	// io.LimitedReader will silently truncate a Reader so if the
	// resulting payload is the same size as maxResponseSize fail
	if len(body) >= maxResponseSize {
		return nil, validationRecords, probs.Unauthorized(fmt.Sprintf("Invalid response from %s: \"%s\"", url.String(), body))
	}

	if httpResponse.StatusCode != 200 {
		va.log.Info(fmt.Sprintf("Non-200 status code from HTTP: %s returned %d", url.String(), httpResponse.StatusCode))
		return nil, validationRecords, probs.Unauthorized(fmt.Sprintf("Invalid response from %s [%s]: %d",
			url.String(), dialer.record.AddressUsed, httpResponse.StatusCode))
	}

	return body, validationRecords, nil
}

// certNames collects up all of a certificate's subject names (Subject CN and
// Subject Alternate Names) and reduces them to a unique, sorted set, typically for an
// error message
func certNames(cert *x509.Certificate) []string {
	var names []string
	if cert.Subject.CommonName != "" {
		names = append(names, cert.Subject.CommonName)
	}
	names = append(names, cert.DNSNames...)
	names = core.UniqueLowerNames(names)
	return names
}

func (va *ValidationAuthorityImpl) tryGetTLSSNICerts(ctx context.Context, identifier core.AcmeIdentifier, challenge core.Challenge, zName string) ([]*x509.Certificate, []core.ValidationRecord, *probs.ProblemDetails) {
	addr, allAddrs, problem := va.getAddr(ctx, identifier.Value)
	validationRecords := []core.ValidationRecord{
		{
			Hostname:          identifier.Value,
			AddressesResolved: allAddrs,
			AddressUsed:       addr,
			Port:              strconv.Itoa(va.tlsPort),
		},
	}
	if problem != nil {
		return nil, validationRecords, problem
	}
	thisRecord := &validationRecords[0]

	// Split the available addresses into v4 and v6 addresses
	v4, v6 := availableAddresses(*thisRecord)
	addresses := append(v4, v6...)

	// This shouldn't happen, but be defensive about it anyway
	if len(addresses) < 1 {
		return nil, validationRecords, probs.Malformed(
			fmt.Sprintf("no IP addresses found for %q", identifier.Value))
	}

	// If the IPv6 first feature isn't enabled then combine available IPv4 and
	// IPv6 addresses and connect to the first IP in the combined list
	if !features.Enabled(features.IPv6First) {
		address := net.JoinHostPort(addresses[0].String(), thisRecord.Port)
		thisRecord.AddressUsed = addresses[0]
		certs, err := va.getTLSSNICerts(address, identifier, challenge, zName)
		return certs, validationRecords, err
	}

	// If the IPv6 first feature is enabled and there is at least one IPv6 address
	// then try it first
	if features.Enabled(features.IPv6First) && len(v6) > 0 {
		address := net.JoinHostPort(v6[0].String(), thisRecord.Port)
		thisRecord.AddressUsed = v6[0]

		certs, err := va.getTLSSNICerts(address, identifier, challenge, zName)

		// If there is no error, return immediately
		if err == nil {
			return certs, validationRecords, err
		}

		// Otherwise, we note that we tried an address and fall back to trying IPv4
		thisRecord.AddressesTried = append(thisRecord.AddressesTried, thisRecord.AddressUsed)
		va.stats.Inc("IPv4Fallback", 1)
	}

	// If there are no IPv4 addresses and we tried an IPv6 address return
	// an error - there's nothing left to try
	if len(v4) == 0 && len(thisRecord.AddressesTried) > 0 {
		return nil, validationRecords, probs.Malformed(
			fmt.Sprintf("Unable to contact %q at %q, no IPv4 addresses to try as fallback",
				thisRecord.Hostname, thisRecord.AddressesTried[0]))
	} else if len(v4) == 0 && len(thisRecord.AddressesTried) == 0 {
		// It shouldn't be possible that there are no IPv4 addresses and no previous
		// attempts at an IPv6 address connection but be defensive about it anyway
		return nil, validationRecords, probs.Malformed(
			fmt.Sprintf("No IP addresses found for %q", thisRecord.Hostname))
	}

	// Otherwise if there are no IPv6 addresses, or there was an error
	// talking to the first IPv6 address, try the first IPv4 address
	address := net.JoinHostPort(v4[0].String(), thisRecord.Port)
	thisRecord.AddressUsed = v4[0]
	certs, err := va.getTLSSNICerts(address, identifier, challenge, zName)
	return certs, validationRecords, err
}

func (va *ValidationAuthorityImpl) validateTLSSNI01WithZName(ctx context.Context, identifier core.AcmeIdentifier, challenge core.Challenge, zName string) ([]core.ValidationRecord, *probs.ProblemDetails) {
	certs, validationRecords, problem := va.tryGetTLSSNICerts(ctx, identifier, challenge, zName)
	if problem != nil {
		return validationRecords, problem
	}

	leafCert := certs[0]
	for _, name := range leafCert.DNSNames {
		if subtle.ConstantTimeCompare([]byte(name), []byte(zName)) == 1 {
			return validationRecords, nil
		}
	}

	hostPort := net.JoinHostPort(validationRecords[0].AddressUsed.String(), validationRecords[0].Port)
	names := certNames(leafCert)
	errText := fmt.Sprintf(
		"Incorrect validation certificate for %s challenge. "+
			"Requested %s from %s. Received %d certificate(s), "+
			"first certificate had names %q",
		challenge.Type, zName, hostPort, len(certs), strings.Join(names, ", "))
	va.log.Info(fmt.Sprintf("Remote host failed to give %s challenge name. host: %s", challenge.Type, identifier))
	return validationRecords, probs.Unauthorized(errText)
}

func (va *ValidationAuthorityImpl) getTLSSNICerts(hostPort string, identifier core.AcmeIdentifier, challenge core.Challenge, zName string) ([]*x509.Certificate, *probs.ProblemDetails) {
	va.log.Info(fmt.Sprintf("%s [%s] Attempting to validate for %s %s", challenge.Type, identifier, hostPort, zName))
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: singleDialTimeout}, "tcp", hostPort, &tls.Config{
		ServerName:         zName,
		InsecureSkipVerify: true,
	})

	if err != nil {
		va.log.Info(fmt.Sprintf("%s connection failure for %s. err=[%#v] errStr=[%s]", challenge.Type, identifier, err, err))
		return nil, detailedError(err)
	}
	// close errors are not important here
	defer func() {
		_ = conn.Close()
	}()

	// Check that zName is a dNSName SAN in the server's certificate
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		va.log.Info(fmt.Sprintf("%s challenge for %s resulted in no certificates", challenge.Type, identifier.Value))
		return nil, probs.Unauthorized(fmt.Sprintf("No certs presented for %s challenge", challenge.Type))
	}
	for i, cert := range certs {
		va.log.AuditInfo(fmt.Sprintf("%s challenge for %s received certificate (%d of %d): cert=[%s]",
			challenge.Type, identifier.Value, i+1, len(certs), hex.EncodeToString(cert.Raw)))
	}
	return certs, nil
}

func (va *ValidationAuthorityImpl) validateHTTP01(ctx context.Context, identifier core.AcmeIdentifier, challenge core.Challenge) ([]core.ValidationRecord, *probs.ProblemDetails) {
	if identifier.Type != core.IdentifierDNS {
		va.log.Info(fmt.Sprintf("Got non-DNS identifier for HTTP validation: %s", identifier))
		return nil, probs.Malformed("Identifier type for HTTP validation was not DNS")
	}

	// Perform the fetch
	path := fmt.Sprintf(".well-known/acme-challenge/%s", challenge.Token)
	body, validationRecords, prob := va.fetchHTTP(ctx, identifier, path, false, challenge)
	if prob != nil {
		return validationRecords, prob
	}

	payload := strings.TrimRight(string(body), whitespaceCutset)

	if payload != challenge.ProvidedKeyAuthorization {
		errString := fmt.Sprintf("The key authorization file from the server did not match this challenge [%v] != [%v]",
			challenge.ProvidedKeyAuthorization, payload)
		va.log.Info(fmt.Sprintf("%s for %s", errString, identifier))
		return validationRecords, probs.Unauthorized(errString)
	}

	return validationRecords, nil
}

func (va *ValidationAuthorityImpl) validateTLSSNI01(ctx context.Context, identifier core.AcmeIdentifier, challenge core.Challenge) ([]core.ValidationRecord, *probs.ProblemDetails) {
	if identifier.Type != "dns" {
		va.log.Info(fmt.Sprintf("Identifier type for TLS-SNI-01 was not DNS: %s", identifier))
		return nil, probs.Malformed("Identifier type for TLS-SNI-01 was not DNS")
	}

	// Compute the digest that will appear in the certificate
	h := sha256.Sum256([]byte(challenge.ProvidedKeyAuthorization))
	Z := hex.EncodeToString(h[:])
	ZName := fmt.Sprintf("%s.%s.%s", Z[:32], Z[32:], core.TLSSNISuffix)

	return va.validateTLSSNI01WithZName(ctx, identifier, challenge, ZName)
}

// badTLSHeader contains the string 'HTTP /' which is returned when
// we try to talk TLS to a server that only talks HTTP
var badTLSHeader = []byte{0x48, 0x54, 0x54, 0x50, 0x2f}

// detailedError returns a ProblemDetails corresponding to an error
// that occurred during HTTP-01 or TLS-SNI domain validation. Specifically it
// tries to unwrap known Go error types and present something a little more
// meaningful. It additionally handles `berrors.ConnectionFailure` errors by
// passing through the detailed message.
func detailedError(err error) *probs.ProblemDetails {
	// net/http wraps net.OpError in a url.Error. Unwrap them.
	if urlErr, ok := err.(*url.Error); ok {
		prob := detailedError(urlErr.Err)
		prob.Detail = fmt.Sprintf("Fetching %s: %s", urlErr.URL, prob.Detail)
		return prob
	}

	if tlsErr, ok := err.(tls.RecordHeaderError); ok && bytes.Compare(tlsErr.RecordHeader[:], badTLSHeader) == 0 {
		return probs.Malformed(fmt.Sprintf("Server only speaks HTTP, not TLS"))
	}

	if netErr, ok := err.(*net.OpError); ok {
		if fmt.Sprintf("%T", netErr.Err) == "tls.alert" {
			// All the tls.alert error strings are reasonable to hand back to a
			// user. Confirmed against Go 1.8.
			return probs.TLSError(netErr.Error())
		} else if syscallErr, ok := netErr.Err.(*os.SyscallError); ok &&
			syscallErr.Err == syscall.ECONNREFUSED {
			return probs.ConnectionFailure("Connection refused")
		} else if syscallErr, ok := netErr.Err.(*os.SyscallError); ok &&
			syscallErr.Err == syscall.ECONNRESET {
			return probs.ConnectionFailure("Connection reset by peer")
		}
	}
	if err, ok := err.(net.Error); ok && err.Timeout() {
		return probs.ConnectionFailure("Timeout")
	}
	if berrors.Is(err, berrors.ConnectionFailure) {
		return probs.ConnectionFailure(err.Error())
	}

	return probs.ConnectionFailure("Error getting validation data")
}

func (va *ValidationAuthorityImpl) validateDNS01(ctx context.Context, identifier core.AcmeIdentifier, challenge core.Challenge) ([]core.ValidationRecord, *probs.ProblemDetails) {
	if identifier.Type != core.IdentifierDNS {
		va.log.Info(fmt.Sprintf("Identifier type for DNS challenge was not DNS: %s", identifier))
		return nil, probs.Malformed("Identifier type for DNS was not itself DNS")
	}

	// Compute the digest of the key authorization file
	h := sha256.New()
	h.Write([]byte(challenge.ProvidedKeyAuthorization))
	authorizedKeysDigest := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	// Look for the required record in the DNS
	challengeSubdomain := fmt.Sprintf("%s.%s", core.DNSPrefix, identifier.Value)
	txts, authorities, err := va.dnsClient.LookupTXT(ctx, challengeSubdomain)

	if err != nil {
		va.log.Info(fmt.Sprintf("Failed to lookup TXT records for %s. err=[%#v] errStr=[%s]", identifier, err, err))

		return nil, probs.ConnectionFailure(err.Error())
	}

	// If there weren't any TXT records return a distinct error message to allow
	// troubleshooters to differentiate between no TXT records and
	// invalid/incorrect TXT records.
	if len(txts) == 0 {
		return nil, probs.Unauthorized(fmt.Sprintf(
			"No TXT record found at %s", challengeSubdomain))
	}

	for _, element := range txts {
		if subtle.ConstantTimeCompare([]byte(element), []byte(authorizedKeysDigest)) == 1 {
			// Successful challenge validation
			return []core.ValidationRecord{{
				Authorities: authorities,
				Hostname:    identifier.Value,
			}}, nil
		}
	}

	invalidRecord := txts[0]
	if len(invalidRecord) > 100 {
		invalidRecord = invalidRecord[0:100] + "..."
	}
	var andMore string
	if len(txts) > 1 {
		andMore = fmt.Sprintf(" (and %d more)", len(txts)-1)
	}
	return nil, probs.Unauthorized(fmt.Sprintf(
		"Incorrect TXT record %q%s found at %s",
		invalidRecord, andMore, challengeSubdomain))
}

// validateChallengeAndCAA performs a challenge validation and CAA validation
// for the provided identifier and a corresponding challenge. If the validation
// or CAA lookup fail a problem is returned along with the validation records
// created during the validation attempt.
func (va *ValidationAuthorityImpl) validateChallengeAndCAA(
	ctx context.Context,
	identifier core.AcmeIdentifier,
	challenge core.Challenge) ([]core.ValidationRecord, *probs.ProblemDetails) {

	// If the identifier is a wildcard domain we need to validate the base
	// domain by removing the "*." wildcard prefix. We create a separate
	// `baseIdentifier` here before starting the `va.checkCAA` goroutine with the
	// `identifier` to avoid a data race.
	baseIdentifier := identifier
	if strings.HasPrefix(identifier.Value, "*.") {
		baseIdentifier.Value = strings.TrimPrefix(identifier.Value, "*.")
	}

	// va.checkCAA accepts wildcard identifiers and handles them appropriately so
	// we can dispatch `checkCAA` with the provided `identifier` instead of
	// `baseIdentifier`
	ch := make(chan *probs.ProblemDetails, 1)
	go func() {
		ch <- va.checkCAA(ctx, identifier)
	}()

	// TODO(#1292): send into another goroutine
	validationRecords, err := va.validateChallenge(ctx, baseIdentifier, challenge)
	if err != nil {
		return validationRecords, err
	}

	caaProblem := <-ch
	if caaProblem != nil {
		return validationRecords, caaProblem
	}
	return validationRecords, nil
}

func (va *ValidationAuthorityImpl) validateChallenge(ctx context.Context, identifier core.AcmeIdentifier, challenge core.Challenge) ([]core.ValidationRecord, *probs.ProblemDetails) {
	if err := challenge.CheckConsistencyForValidation(); err != nil {
		return nil, probs.Malformed("Challenge failed consistency check: %s", err)
	}
	switch challenge.Type {
	case core.ChallengeTypeHTTP01:
		return va.validateHTTP01(ctx, identifier, challenge)
	case core.ChallengeTypeTLSSNI01:
		return va.validateTLSSNI01(ctx, identifier, challenge)
	case core.ChallengeTypeDNS01:
		return va.validateDNS01(ctx, identifier, challenge)
	}
	return nil, probs.Malformed(fmt.Sprintf("invalid challenge type %s", challenge.Type))
}

func (va *ValidationAuthorityImpl) performRemoteValidation(ctx context.Context, domain string, challenge core.Challenge, authz core.Authorization, result chan *probs.ProblemDetails) {
	s := va.clk.Now()
	errors := make(chan error, len(va.remoteVAs))
	for _, remoteVA := range va.remoteVAs {
		go func(rva RemoteVA) {
			_, err := rva.PerformValidation(ctx, domain, challenge, authz)
			if err != nil {
				// returned error can be a nil *probs.ProblemDetails which breaks the
				// err != nil check so do a slightly more complicated unwrap check to
				// make sure we don't choke on that.
				if p, ok := err.(*probs.ProblemDetails); !ok || p != nil {
					va.log.Info(fmt.Sprintf("Remote VA %q.PerformValidation failed: %s", rva.Addresses, err))
				} else if ok && p == nil {
					err = nil
				}
			}
			errors <- err
		}(remoteVA)
	}

	required := len(va.remoteVAs) - va.maxRemoteFailures
	good := 0
	bad := 0
	state := "failure"
	// Due to channel behavior this could block indefinitely and we rely on gRPC
	// honoring the context deadline used in client calls to prevent that from
	// happening.
	for err := range errors {
		if err == nil {
			good++
		} else {
			bad++
		}
		if good >= required {
			result <- nil
			state = "success"
			break
		} else if bad > va.maxRemoteFailures {
			if prob, ok := err.(*probs.ProblemDetails); ok {
				// The overall error returned is whichever error
				// happened to tip the threshold. This is fine
				// since we expect that any remote validation
				// failures will typically be the same across
				// instances.
				result <- prob
			} else {
				result <- probs.ServerInternal("Remote PerformValidation RPCs failed")
			}
			break
		}
	}

	va.metrics.remoteValidationTime.With(prometheus.Labels{
		"type":   string(challenge.Type),
		"result": state,
	}).Observe(va.clk.Since(s).Seconds())
}

// PerformValidation validates the given challenge. It always returns a list of
// validation records, even when it also returns an error.
//
// TODO(#1626): remove authz parameter
func (va *ValidationAuthorityImpl) PerformValidation(ctx context.Context, domain string, challenge core.Challenge, authz core.Authorization) ([]core.ValidationRecord, error) {
	logEvent := verificationRequestEvent{
		ID:          authz.ID,
		Requester:   authz.RegistrationID,
		Hostname:    domain,
		RequestTime: va.clk.Now(),
	}
	vStart := va.clk.Now()

	var remoteError chan *probs.ProblemDetails
	if len(va.remoteVAs) > 0 {
		remoteError = make(chan *probs.ProblemDetails, 1)
		go va.performRemoteValidation(ctx, domain, challenge, authz, remoteError)
	}

	records, prob := va.validateChallengeAndCAA(
		ctx,
		core.AcmeIdentifier{Type: "dns", Value: domain},
		challenge)

	logEvent.ValidationRecords = records
	challenge.ValidationRecord = records

	// Check for malformed ValidationRecords
	if !challenge.RecordsSane() && prob == nil {
		prob = probs.ServerInternal("Records for validation failed sanity check")
	}

	if prob != nil {
		challenge.Status = core.StatusInvalid
		challenge.Error = prob
		logEvent.Error = prob.Error()
	} else if remoteError != nil {
		prob = <-remoteError
		if prob != nil {
			challenge.Status = core.StatusInvalid
			challenge.Error = prob
			logEvent.Error = prob.Error()
			va.log.Info(fmt.Sprintf(
				"Validation failed due to remote failures: identifier=%v err=%s",
				authz.Identifier, prob))
			va.metrics.remoteValidationFailures.Inc()
		} else {
			challenge.Status = core.StatusValid
		}
	} else {
		challenge.Status = core.StatusValid
	}

	logEvent.Challenge = challenge

	va.metrics.validationTime.With(prometheus.Labels{
		"type":   string(challenge.Type),
		"result": string(challenge.Status),
	}).Observe(time.Since(vStart).Seconds())

	va.log.AuditObject("Validation result", logEvent)
	va.log.Info(fmt.Sprintf("Validations: %+v", authz))
	if prob == nil {
		// This is necessary because if we just naively returned prob, it would be a
		// non-nil interface value containing a nil pointer, rather than a nil
		// interface value. See, e.g.
		// https://stackoverflow.com/questions/29138591/hiding-nil-values-understanding-why-golang-fails-here
		return records, nil
	}

	return records, prob
}
