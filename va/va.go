package va

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jmhodges/clock"
	"github.com/miekg/dns"
	"golang.org/x/net/context"

	_ "github.com/google/safebrowsing/"
	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/cdr"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
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

// ValidationAuthorityImpl represents a VA
type ValidationAuthorityImpl struct {
	log          blog.Logger
	dnsResolver  bdns.DNSResolver
	issuerDomain string
	safeBrowsing SafeBrowsing
	httpPort     int
	httpsPort    int
	tlsPort      int
	userAgent    string
	stats        metrics.Scope
	clk          clock.Clock
	caaDR        *cdr.CAADistributedResolver
}

// NewValidationAuthorityImpl constructs a new VA
func NewValidationAuthorityImpl(
	pc *cmd.PortConfig,
	sbc SafeBrowsing,
	cdrClient *cdr.CAADistributedResolver,
	resolver bdns.DNSResolver,
	userAgent string,
	issuerDomain string,
	stats metrics.Scope,
	clk clock.Clock,
	logger blog.Logger,
) *ValidationAuthorityImpl {
	return &ValidationAuthorityImpl{
		log:          logger,
		dnsResolver:  resolver,
		issuerDomain: issuerDomain,
		safeBrowsing: sbc,
		httpPort:     pc.HTTPPort,
		httpsPort:    pc.HTTPSPort,
		tlsPort:      pc.TLSPort,
		userAgent:    userAgent,
		stats:        stats,
		clk:          clk,
		caaDR:        cdrClient,
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

// getAddr will query for all A records associated with hostname and return the
// preferred address, the first net.IP in the addrs slice, and all addresses resolved.
// This is the same choice made by the Go internal resolution library used by
// net/http, except we only send A queries and accept IPv4 addresses.
// TODO(#593): Add IPv6 support
func (va ValidationAuthorityImpl) getAddr(ctx context.Context, hostname string) (net.IP, []net.IP, *probs.ProblemDetails) {
	addrs, err := va.dnsResolver.LookupHost(ctx, hostname)
	if err != nil {
		va.log.Debug(fmt.Sprintf("%s DNS failure: %s", hostname, err))
		problem := bdns.ProblemDetailsFromDNSError(err)
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
}

func (d *dialer) Dial(_, _ string) (net.Conn, error) {
	realDialer := net.Dialer{Timeout: validationTimeout}
	return realDialer.Dial("tcp", net.JoinHostPort(d.record.AddressUsed.String(), d.record.Port))
}

// resolveAndConstructDialer gets the preferred address using va.getAddr and returns
// the chosen address and dialer for that address and correct port.
func (va *ValidationAuthorityImpl) resolveAndConstructDialer(ctx context.Context, name string, port int) (dialer, *probs.ProblemDetails) {
	d := dialer{
		record: core.ValidationRecord{
			Hostname: name,
			Port:     strconv.Itoa(port),
		},
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
	validationRecords := []core.ValidationRecord{dialer.record}
	if prob != nil {
		return nil, validationRecords, prob
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
	if err != nil {
		va.log.Info(fmt.Sprintf("HTTP request to %s failed. err=[%#v] errStr=[%s]", url, err, err))
		return nil, validationRecords,
			parseHTTPConnError(fmt.Sprintf("Could not connect to %s", urlHost), err)
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

func (va *ValidationAuthorityImpl) validateTLSWithZName(ctx context.Context, identifier core.AcmeIdentifier, challenge core.Challenge, zName string) ([]core.ValidationRecord, *probs.ProblemDetails) {
	addr, allAddrs, problem := va.getAddr(ctx, identifier.Value)
	validationRecords := []core.ValidationRecord{
		{
			Hostname:          identifier.Value,
			AddressesResolved: allAddrs,
			AddressUsed:       addr,
		},
	}
	if problem != nil {
		return validationRecords, problem
	}

	// Make a connection with SNI = nonceName
	portString := strconv.Itoa(va.tlsPort)
	hostPort := net.JoinHostPort(addr.String(), portString)
	validationRecords[0].Port = portString
	va.log.Info(fmt.Sprintf("%s [%s] Attempting to validate for %s %s", challenge.Type, identifier, hostPort, zName))
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: validationTimeout}, "tcp", hostPort, &tls.Config{
		ServerName:         zName,
		InsecureSkipVerify: true,
	})

	if err != nil {
		va.log.Info(fmt.Sprintf("TLS-01 connection failure for %s. err=[%#v] errStr=[%s]", identifier, err, err))
		return validationRecords,
			parseHTTPConnError(fmt.Sprintf("Failed to connect to %s for TLS-SNI-01 challenge", hostPort), err)
	}
	// close errors are not important here
	defer func() {
		_ = conn.Close()
	}()

	// Check that zName is a dNSName SAN in the server's certificate
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		va.log.Info(fmt.Sprintf("TLS-SNI-01 challenge for %s resulted in no certificates", identifier.Value))
		return validationRecords, probs.Unauthorized("No certs presented for TLS SNI challenge")
	}
	for i, cert := range certs {
		va.log.AuditInfo(fmt.Sprintf("TLS-SNI-01 challenge for %s received certificate (%d of %d): cert=[%s]",
			identifier.Value, i+1, len(certs), hex.EncodeToString(cert.Raw)))
	}
	for _, name := range certs[0].DNSNames {
		if subtle.ConstantTimeCompare([]byte(name), []byte(zName)) == 1 {
			return validationRecords, nil
		}
	}

	va.log.Info(fmt.Sprintf("Remote host failed to give TLS-01 challenge name. host: %s", identifier))
	return validationRecords, probs.Unauthorized(
		fmt.Sprintf("Incorrect validation certificate for TLS-SNI-01 challenge. "+
			"Requested %s from %s. Received certificate containing '%s'",
			zName, hostPort, strings.Join(certs[0].DNSNames, ", ")))
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
		va.log.Info(fmt.Sprintf("Identifier type for TLS-SNI was not DNS: %s", identifier))
		return nil, probs.Malformed("Identifier type for TLS-SNI was not DNS")
	}

	// Compute the digest that will appear in the certificate
	h := sha256.New()
	h.Write([]byte(challenge.ProvidedKeyAuthorization))
	Z := hex.EncodeToString(h.Sum(nil))
	ZName := fmt.Sprintf("%s.%s.%s", Z[:32], Z[32:], core.TLSSNISuffix)

	return va.validateTLSWithZName(ctx, identifier, challenge, ZName)
}

// parseHTTPConnError returns a ProblemDetails corresponding to an error
// that occurred during domain validation.
func parseHTTPConnError(detail string, err error) *probs.ProblemDetails {
	if urlErr, ok := err.(*url.Error); ok {
		err = urlErr.Err
	}

	// XXX: On all of the resolvers I tested that validate DNSSEC, there is
	// no differentation between a DNSSEC failure and an unknown host. If we
	// do not verify DNSSEC ourselves, this function should be modified.
	if netErr, ok := err.(*net.OpError); ok {
		dnsErr, ok := netErr.Err.(*net.DNSError)
		if ok && !dnsErr.Timeout() && !dnsErr.Temporary() {
			return probs.UnknownHost(detail)
		} else if fmt.Sprintf("%T", netErr.Err) == "tls.alert" {
			return probs.TLSError(detail)
		}
	}

	return probs.ConnectionFailure(detail)
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

		return nil, bdns.ProblemDetailsFromDNSError(err)
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
	prob := va.checkCAAInternal(ctx, identifier)
	if va.caaDR != nil && prob != nil && prob.Type == probs.ConnectionProblem {
		return va.checkGPDNS(ctx, identifier)
	}
	return prob
}

func (va *ValidationAuthorityImpl) checkCAAInternal(ctx context.Context, ident core.AcmeIdentifier) *probs.ProblemDetails {
	present, valid, err := va.checkCAARecords(ctx, ident)
	if err != nil {
		return bdns.ProblemDetailsFromDNSError(err)
	}
	va.log.AuditInfo(fmt.Sprintf(
		"Checked CAA records for %s, [Present: %t, Valid for issuance: %t]",
		ident.Value,
		present,
		valid,
	))
	if !valid {
		return probs.ConnectionFailure(fmt.Sprintf("CAA record for %s prevents issuance", ident.Value))
	}
	return nil
}

func (va *ValidationAuthorityImpl) checkGPDNS(ctx context.Context, identifier core.AcmeIdentifier) *probs.ProblemDetails {
	results := va.parallelCAALookup(ctx, identifier.Value, va.caaDR.LookupCAA)
	set, err := parseResults(results)
	if err != nil {
		return probs.ConnectionFailure(err.Error())
	}
	present, valid := va.validateCAASet(set)
	va.log.AuditInfo(fmt.Sprintf(
		"Checked CAA records for %s using GPDNS, [Present: %t, Valid for issuance: %t]",
		identifier.Value,
		present,
		valid,
	))
	if !valid {
		return &probs.ProblemDetails{
			Type:   probs.ConnectionProblem,
			Detail: fmt.Sprintf("CAA records prevents issuance for %s", identifier.Value),
		}
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
	if !challenge.IsSaneForValidation() {
		return nil, probs.Malformed("Challenge failed sanity check.")
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
	} else {
		challenge.Status = core.StatusValid
	}

	logEvent.Challenge = challenge

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
