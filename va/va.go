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
	"sync"
	"syscall"
	"time"

	"github.com/jmhodges/clock"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/context"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
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

var validationTimeout = time.Second * 5

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
	remoteValidationFailures *prometheus.HistogramVec
}

func initMetrics(stats metrics.Scope) *vaMetrics {
	validationTime := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "validation_time",
			Help: "Time taken to validate a challenge",
		},
		[]string{"type", "result"})
	stats.MustRegister(validationTime)
	remoteValidationTime := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "remote_validation_time",
			Help: "Time taken to remotely validate a challenge",
		},
		[]string{"type", "result"})
	stats.MustRegister(remoteValidationTime)
	remoteValidationFailures := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "remote_validation_failures",
			Help: "Number of remote VAs that failed during challenge validation",
		}, nil)
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
	dnsResolver       bdns.DNSResolver
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
	resolver bdns.DNSResolver,
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
		dnsResolver:       resolver,
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
	addrs, err := va.dnsResolver.LookupHost(ctx, hostname)
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

type dialer struct {
	record core.ValidationRecord
	stats  metrics.Scope
}

func (d *dialer) Dial(_, _ string) (net.Conn, error) {
	realDialer := net.Dialer{Timeout: validationTimeout}

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
		return realDialer.Dial("tcp", address)
	}

	// If the IPv6 first feature is enabled and there is at least one IPv6 address
	// then try it first
	if features.Enabled(features.IPv6First) && len(v6) > 0 {
		address := net.JoinHostPort(v6[0].String(), d.record.Port)
		d.record.AddressUsed = v6[0]
		conn, err := realDialer.Dial("tcp", address)

		// If there is no error, return immediately
		if err == nil {
			return conn, err
		}

		// Otherwise, we note that we tried an address and fall back to trying IPv4
		d.record.AddressesTried = append(d.record.AddressesTried, d.record.AddressUsed)
		d.stats.Inc("IPv4Fallback", 1)
	}

	// This shouldn't happen, but be defensive about it anyway
	if len(v4) < 1 {
		return nil, fmt.Errorf("No available addresses for dialer to dial")
	}

	// Otherwise if there are no IPv6 addresses, or there was an error
	// talking to the first IPv6 address, try the first IPv4 address
	address := net.JoinHostPort(v4[0].String(), d.record.Port)
	d.record.AddressUsed = v4[0]
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
func (va *ValidationAuthorityImpl) resolveAndConstructDialer(ctx context.Context, name string, port int) (dialer, *probs.ProblemDetails) {
	d := dialer{
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
			if reqPort <= 0 || reqPort > 65535 {
				return fmt.Errorf("Invalid port number %d in redirect", reqPort)
			}
		} else if strings.ToLower(req.URL.Scheme) == "https" {
			reqPort = 443
		} else {
			reqPort = 80
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
		Timeout:       validationTimeout,
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

	// If there are no v4 addresses then return an error about there being no
	// usable addresses found. We don't say "no IP addresses found" here because
	// we may have tried an IPv6 address before this point, had it fail, and then
	// found no fallbacks.
	if len(v4) < 1 {
		return nil, validationRecords, probs.Malformed(
			fmt.Sprintf("no working IP addresses found for %q", identifier.Value))
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

func (va *ValidationAuthorityImpl) validateTLSSNI02WithZNames(ctx context.Context, identifier core.AcmeIdentifier, challenge core.Challenge, sanAName, sanBName string) ([]core.ValidationRecord, *probs.ProblemDetails) {
	certs, validationRecords, problem := va.tryGetTLSSNICerts(ctx, identifier, challenge, sanAName)
	if problem != nil {
		return validationRecords, problem
	}

	leafCert := certs[0]
	if len(leafCert.DNSNames) != 2 {
		names := strings.Join(certNames(leafCert), ", ")
		msg := fmt.Sprintf("%s challenge certificate doesn't include exactly 2 DNSName entries. Received %d certificate(s), first certificate had names %q", challenge.Type, len(certs), names)
		return validationRecords, probs.Malformed(msg)
	}

	var validSanAName, validSanBName bool
	for _, name := range leafCert.DNSNames {
		// Note: ConstantTimeCompare is not strictly necessary here, but can't hurt.
		if subtle.ConstantTimeCompare([]byte(name), []byte(sanAName)) == 1 {
			validSanAName = true
		}

		if subtle.ConstantTimeCompare([]byte(name), []byte(sanBName)) == 1 {
			validSanBName = true
		}
	}

	if validSanAName && validSanBName {
		return validationRecords, nil
	}

	hostPort := net.JoinHostPort(validationRecords[0].AddressUsed.String(), validationRecords[0].Port)
	names := certNames(leafCert)
	errText := fmt.Sprintf(
		"Incorrect validation certificate for %s challenge. "+
			"Requested %s from %s. Received %d certificate(s), "+
			"first certificate had names %q",
		challenge.Type, sanAName, hostPort, len(certs), strings.Join(names, ", "))
	va.log.Info(fmt.Sprintf("Remote host failed to give %s challenge name. host: %s", challenge.Type, identifier))
	return validationRecords, probs.Unauthorized(errText)
}

func (va *ValidationAuthorityImpl) getTLSSNICerts(hostPort string, identifier core.AcmeIdentifier, challenge core.Challenge, zName string) ([]*x509.Certificate, *probs.ProblemDetails) {
	va.log.Info(fmt.Sprintf("%s [%s] Attempting to validate for %s %s", challenge.Type, identifier, hostPort, zName))
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: validationTimeout}, "tcp", hostPort, &tls.Config{
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

func (va *ValidationAuthorityImpl) validateTLSSNI02(ctx context.Context, identifier core.AcmeIdentifier, challenge core.Challenge) ([]core.ValidationRecord, *probs.ProblemDetails) {
	if identifier.Type != "dns" {
		va.log.Info(fmt.Sprintf("Identifier type for TLS-SNI-02 was not DNS: %s", identifier))
		return nil, probs.Malformed("Identifier type for TLS-SNI-02 was not DNS")
	}

	const tlsSNITokenID = "token"
	const tlsSNIKaID = "ka"

	// Compute the digest for the SAN b that will appear in the certificate
	ha := sha256.Sum256([]byte(challenge.Token))
	za := hex.EncodeToString(ha[:])
	sanAName := fmt.Sprintf("%s.%s.%s.%s", za[:32], za[32:], tlsSNITokenID, core.TLSSNISuffix)

	// Compute the digest for the SAN B that will appear in the certificate
	hb := sha256.Sum256([]byte(challenge.ProvidedKeyAuthorization))
	zb := hex.EncodeToString(hb[:])
	sanBName := fmt.Sprintf("%s.%s.%s.%s", zb[:32], zb[32:], tlsSNIKaID, core.TLSSNISuffix)

	return va.validateTLSSNI02WithZNames(ctx, identifier, challenge, sanAName, sanBName)
}

// badTLSHeader contains the string 'HTTP /' which is returned when
// we try to talk TLS to a server that only talks HTTP
var badTLSHeader = []byte{0x48, 0x54, 0x54, 0x50, 0x2f}

// detailedError returns a ProblemDetails corresponding to an error
// that occurred during HTTP-01 or TLS-SNI domain validation. Specifically it
// tries to unwrap known Go error types and present something a little more
// meaningful.
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
		}
	}
	if err, ok := err.(net.Error); ok && err.Timeout() {
		return probs.ConnectionFailure("Timeout")
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
	txts, authorities, err := va.dnsResolver.LookupTXT(ctx, challengeSubdomain)

	if err != nil {
		va.log.Info(fmt.Sprintf("Failed to lookup txt records for %s. err=[%#v] errStr=[%s]", identifier, err, err))

		return nil, probs.ConnectionFailure(err.Error())
	}

	// If there weren't any TXT records return a distinct error message to allow
	// troubleshooters to differentiate between no TXT records and
	// invalid/incorrect TXT records.
	if len(txts) == 0 {
		return nil, probs.Unauthorized("No TXT records found for DNS challenge")
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

	return nil, probs.Unauthorized("Correct value not found for DNS challenge")
}

func (va *ValidationAuthorityImpl) checkCAA(ctx context.Context, identifier core.AcmeIdentifier) *probs.ProblemDetails {
	present, valid, err := va.checkCAARecords(ctx, identifier)
	if err != nil {
		return probs.ConnectionFailure(err.Error())
	}
	va.log.AuditInfo(fmt.Sprintf(
		"Checked CAA records for %s, [Present: %t, Valid for issuance: %t]",
		identifier.Value,
		present,
		valid,
	))
	if !valid {
		return probs.ConnectionFailure(fmt.Sprintf("CAA record for %s prevents issuance", identifier.Value))
	}
	return nil
}

func (va *ValidationAuthorityImpl) validateChallengeAndCAA(ctx context.Context, identifier core.AcmeIdentifier, challenge core.Challenge) ([]core.ValidationRecord, *probs.ProblemDetails) {
	ch := make(chan *probs.ProblemDetails, 1)
	go func() {
		ch <- va.checkCAA(ctx, identifier)
	}()

	// TODO(#1292): send into another goroutine
	validationRecords, err := va.validateChallenge(ctx, identifier, challenge)
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
	case core.ChallengeTypeTLSSNI02:
		return va.validateTLSSNI02(ctx, identifier, challenge)
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
	va.metrics.remoteValidationFailures.With(prometheus.Labels{}).Observe(float64(bad))
}

// PerformValidation validates the given challenge. It always returns a list of
// validation records, even when it also returns an error.
//
// TODO(#1626): remove authz parameter
func (va *ValidationAuthorityImpl) PerformValidation(ctx context.Context, domain string, challenge core.Challenge, authz core.Authorization) ([]core.ValidationRecord, error) {
	logEvent := verificationRequestEvent{
		ID:          authz.ID,
		Requester:   authz.RegistrationID,
		Hostname:    authz.Identifier.Value,
		RequestTime: va.clk.Now(),
	}
	vStart := va.clk.Now()

	var remoteError chan *probs.ProblemDetails
	if len(va.remoteVAs) > 0 {
		remoteError = make(chan *probs.ProblemDetails, 1)
		go va.performRemoteValidation(ctx, domain, challenge, authz, remoteError)
	}

	records, prob := va.validateChallengeAndCAA(ctx, core.AcmeIdentifier{Type: "dns", Value: domain}, challenge)

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
	va.stats.TimingDuration(fmt.Sprintf("Validations.%s.%s", challenge.Type, challenge.Status), time.Since(vStart))

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

// CAASet consists of filtered CAA records
type CAASet struct {
	Issue     []*dns.CAA
	Issuewild []*dns.CAA
	Iodef     []*dns.CAA
	Unknown   []*dns.CAA
}

// returns true if any CAA records have unknown tag properties and are flagged critical.
func (caaSet CAASet) criticalUnknown() bool {
	if len(caaSet.Unknown) > 0 {
		for _, caaRecord := range caaSet.Unknown {
			// The critical flag is the bit with significance 128. However, many CAA
			// record users have misinterpreted the RFC and concluded that the bit
			// with significance 1 is the critical bit. This is sufficiently
			// widespread that that bit must reasonably be considered an alias for
			// the critical bit. The remaining bits are 0/ignore as proscribed by the
			// RFC.
			if (caaRecord.Flag & (128 | 1)) != 0 {
				return true
			}
		}
	}

	return false
}

// Filter CAA records by property
func newCAASet(CAAs []*dns.CAA) *CAASet {
	var filtered CAASet

	for _, caaRecord := range CAAs {
		switch caaRecord.Tag {
		case "issue":
			filtered.Issue = append(filtered.Issue, caaRecord)
		case "issuewild":
			filtered.Issuewild = append(filtered.Issuewild, caaRecord)
		case "iodef":
			filtered.Iodef = append(filtered.Iodef, caaRecord)
		default:
			filtered.Unknown = append(filtered.Unknown, caaRecord)
		}
	}

	return &filtered
}

type caaResult struct {
	records []*dns.CAA
	err     error
}

func parseResults(results []caaResult) (*CAASet, error) {
	// Return first result
	for _, res := range results {
		if res.err != nil {
			return nil, res.err
		}
		if len(res.records) > 0 {
			return newCAASet(res.records), nil
		}
	}
	return nil, nil
}

func (va *ValidationAuthorityImpl) parallelCAALookup(ctx context.Context, name string, lookuper func(context.Context, string) ([]*dns.CAA, error)) []caaResult {
	labels := strings.Split(name, ".")
	results := make([]caaResult, len(labels))
	var wg sync.WaitGroup

	for i := 0; i < len(labels); i++ {
		// Start the concurrent DNS lookup.
		wg.Add(1)
		go func(name string, r *caaResult) {
			r.records, r.err = lookuper(ctx, name)
			wg.Done()
		}(strings.Join(labels[i:], "."), &results[i])
	}

	wg.Wait()
	return results
}

func (va *ValidationAuthorityImpl) getCAASet(ctx context.Context, hostname string) (*CAASet, error) {
	hostname = strings.TrimRight(hostname, ".")

	// See RFC 6844 "Certification Authority Processing" for pseudocode.
	// Essentially: check CAA records for the FDQN to be issued, and all
	// parent domains.
	//
	// The lookups are performed in parallel in order to avoid timing out
	// the RPC call.
	//
	// We depend on our resolver to snap CNAME and DNAME records.
	results := va.parallelCAALookup(ctx, hostname, va.dnsResolver.LookupCAA)
	return parseResults(results)
}

func (va *ValidationAuthorityImpl) checkCAARecords(ctx context.Context, identifier core.AcmeIdentifier) (present, valid bool, err error) {
	hostname := strings.ToLower(identifier.Value)
	caaSet, err := va.getCAASet(ctx, hostname)
	if err != nil {
		return false, false, err
	}
	present, valid = va.validateCAASet(caaSet)
	return present, valid, nil
}

func (va *ValidationAuthorityImpl) validateCAASet(caaSet *CAASet) (present, valid bool) {
	if caaSet == nil {
		// No CAA records found, can issue
		va.stats.Inc("CAA.None", 1)
		return false, true
	}

	// Record stats on directives not currently processed.
	if len(caaSet.Iodef) > 0 {
		va.stats.Inc("CAA.WithIodef", 1)
	}

	if caaSet.criticalUnknown() {
		// Contains unknown critical directives.
		va.stats.Inc("CAA.UnknownCritical", 1)
		return true, false
	}

	if len(caaSet.Unknown) > 0 {
		va.stats.Inc("CAA.WithUnknownNoncritical", 1)
	}

	if len(caaSet.Issue) == 0 {
		// Although CAA records exist, none of them pertain to issuance in this case.
		// (e.g. there is only an issuewild directive, but we are checking for a
		// non-wildcard identifier, or there is only an iodef or non-critical unknown
		// directive.)
		va.stats.Inc("CAA.NoneRelevant", 1)
		return true, true
	}

	// There are CAA records pertaining to issuance in our case. Note that this
	// includes the case of the unsatisfiable CAA record value ";", used to
	// prevent issuance by any CA under any circumstance.
	//
	// Our CAA identity must be found in the chosen checkSet.
	for _, caa := range caaSet.Issue {
		if extractIssuerDomain(caa) == va.issuerDomain {
			va.stats.Inc("CAA.Authorized", 1)
			return true, true
		}
	}

	// The list of authorized issuers is non-empty, but we are not in it. Fail.
	va.stats.Inc("CAA.Unauthorized", 1)
	return true, false
}

// Given a CAA record, assume that the Value is in the issue/issuewild format,
// that is, a domain name with zero or more additional key-value parameters.
// Returns the domain name, which may be "" (unsatisfiable).
func extractIssuerDomain(caa *dns.CAA) string {
	v := caa.Value
	v = strings.Trim(v, " \t") // Value can start and end with whitespace.
	idx := strings.IndexByte(v, ';')
	if idx < 0 {
		return v // no parameters; domain only
	}

	// Currently, ignore parameters. Unfortunately, the RFC makes no statement on
	// whether any parameters are critical. Treat unknown parameters as
	// non-critical.
	return strings.Trim(v[0:idx], " \t")
}
