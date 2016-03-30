// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package va

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/golang.org/x/net/context"
	"github.com/letsencrypt/boulder/probs"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

const maxRedirect = 10
const whitespaceCutset = "\n\r\t "

var validationTimeout = time.Second * 5

// ValidationAuthorityImpl represents a VA
type ValidationAuthorityImpl struct {
	RA           core.RegistrationAuthority
	log          *blog.AuditLogger
	DNSResolver  bdns.DNSResolver
	IssuerDomain string
	SafeBrowsing SafeBrowsing
	httpPort     int
	httpsPort    int
	tlsPort      int
	UserAgent    string
	stats        statsd.Statter
	clk          clock.Clock
}

// PortConfig specifies what ports the VA should call to on the remote
// host when performing its checks.
type PortConfig struct {
	HTTPPort  int
	HTTPSPort int
	TLSPort   int
}

// NewValidationAuthorityImpl constructs a new VA
func NewValidationAuthorityImpl(pc *PortConfig, sbc SafeBrowsing, stats statsd.Statter, clk clock.Clock) *ValidationAuthorityImpl {
	logger := blog.GetAuditLogger()
	logger.Notice("Validation Authority Starting")
	return &ValidationAuthorityImpl{
		SafeBrowsing: sbc,
		log:          logger,
		httpPort:     pc.HTTPPort,
		httpsPort:    pc.HTTPSPort,
		tlsPort:      pc.TLSPort,
		stats:        stats,
		clk:          clk,
	}
}

// Used for audit logging
type verificationRequestEvent struct {
	ID                string                  `json:",omitempty"`
	Requester         int64                   `json:",omitempty"`
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
	addrs, err := va.DNSResolver.LookupHost(ctx, hostname)
	if err != nil {
		va.log.Debug(fmt.Sprintf("%s DNS failure: %s", hostname, err))
		problem := bdns.ProblemDetailsFromDNSError(err)
		return net.IP{}, nil, problem
	}

	if len(addrs) == 0 {
		problem := &probs.ProblemDetails{
			Type:   probs.UnknownHostProblem,
			Detail: fmt.Sprintf("No IPv4 addresses found for %s", hostname),
		}
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

	// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
	va.log.AuditNotice(fmt.Sprintf("Attempting to validate %s for %s", challenge.Type, url))
	httpRequest, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		va.log.Info(fmt.Sprintf("Failed to parse URL '%s'. err=[%#v] errStr=[%s]", identifier, err, err))
		return nil, nil, &probs.ProblemDetails{
			Type:   probs.MalformedProblem,
			Detail: "URL provided for HTTP was invalid",
		}
	}

	if va.UserAgent != "" {
		httpRequest.Header["User-Agent"] = []string{va.UserAgent}
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
		if va.UserAgent != "" {
			req.Header["User-Agent"] = []string{va.UserAgent}
		}

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
		return nil, validationRecords, &probs.ProblemDetails{
			Type:   parseHTTPConnError(err),
			Detail: fmt.Sprintf("Could not connect to %s", url),
		}
	}
	defer httpResponse.Body.Close()

	if httpResponse.StatusCode != 200 {
		va.log.Info(fmt.Sprintf("Non-200 status code from HTTP: %s returned %d", url.String(), httpResponse.StatusCode))
		return nil, validationRecords, &probs.ProblemDetails{
			Type: probs.UnauthorizedProblem,
			Detail: fmt.Sprintf("Invalid response from %s [%s]: %d",
				url.String(), dialer.record.AddressUsed, httpResponse.StatusCode),
		}
	}

	body, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		va.log.Info(fmt.Sprintf("Error reading HTTP response body from %s. err=[%#v] errStr=[%s]", url.String(), err, err))
		return nil, validationRecords, &probs.ProblemDetails{
			Type:   probs.UnauthorizedProblem,
			Detail: fmt.Sprintf("Error reading HTTP response body: %v", err),
		}
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
	va.log.Notice(fmt.Sprintf("%s [%s] Attempting to validate for %s %s", challenge.Type, identifier, hostPort, zName))
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: validationTimeout}, "tcp", hostPort, &tls.Config{
		ServerName:         zName,
		InsecureSkipVerify: true,
	})

	if err != nil {
		va.log.Info(fmt.Sprintf("TLS-01 connection failure for %s. err=[%#v] errStr=[%s]", identifier, err, err))
		return validationRecords, &probs.ProblemDetails{
			Type:   parseHTTPConnError(err),
			Detail: "Failed to connect to host for DVSNI challenge",
		}
	}
	defer conn.Close()

	// Check that zName is a dNSName SAN in the server's certificate
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		va.log.Info(fmt.Sprintf("TLS-01 challenge for %s resulted in no certificates", identifier))
		return validationRecords, &probs.ProblemDetails{
			Type:   probs.UnauthorizedProblem,
			Detail: "No certs presented for TLS SNI challenge",
		}
	}
	for _, name := range certs[0].DNSNames {
		if subtle.ConstantTimeCompare([]byte(name), []byte(zName)) == 1 {
			return validationRecords, nil
		}
	}

	va.log.Info(fmt.Sprintf("Remote host failed to give TLS-01 challenge name. host: %s", identifier))
	return validationRecords, &probs.ProblemDetails{
		Type: probs.UnauthorizedProblem,
		Detail: fmt.Sprintf("Correct zName not found for TLS SNI challenge. Found '%v'",
			strings.Join(certs[0].DNSNames, ", ")),
	}
}

func (va *ValidationAuthorityImpl) validateHTTP01(ctx context.Context, identifier core.AcmeIdentifier, challenge core.Challenge) ([]core.ValidationRecord, *probs.ProblemDetails) {
	if identifier.Type != core.IdentifierDNS {
		va.log.Info(fmt.Sprintf("Got non-DNS identifier for HTTP validation: %s", identifier))
		return nil, &probs.ProblemDetails{
			Type:   probs.MalformedProblem,
			Detail: "Identifier type for HTTP validation was not DNS",
		}
	}

	// Perform the fetch
	path := fmt.Sprintf(".well-known/acme-challenge/%s", challenge.Token)
	body, validationRecords, err := va.fetchHTTP(ctx, identifier, path, false, challenge)
	if err != nil {
		return validationRecords, err
	}

	payload := strings.TrimRight(string(body), whitespaceCutset)

	// Parse body as a key authorization object
	serverKeyAuthorization, authErr := core.NewKeyAuthorizationFromString(payload)
	if authErr != nil {
		va.log.Info(fmt.Sprintf("Couldn't parse KeyAuthorization from response from %s. err=[%#v] errStr=[%s]", identifier, authErr, authErr))
		return validationRecords, &probs.ProblemDetails{
			Type:   probs.UnauthorizedProblem,
			Detail: fmt.Sprintf("Error parsing key authorization file: %s", authErr.Error()),
		}
	}

	// Check that the account key for this challenge is authorized by this object
	if !serverKeyAuthorization.Match(challenge.Token, challenge.AccountKey) {
		errString := fmt.Sprintf("The key authorization file from the server did not match this challenge [%v] != [%v]",
			challenge.KeyAuthorization.String(), string(body))
		va.log.Info(fmt.Sprintf("%s for %s", errString, identifier))
		return validationRecords, &probs.ProblemDetails{
			Type:   probs.UnauthorizedProblem,
			Detail: errString,
		}
	}

	return validationRecords, nil
}

func (va *ValidationAuthorityImpl) validateTLSSNI01(ctx context.Context, identifier core.AcmeIdentifier, challenge core.Challenge) ([]core.ValidationRecord, *probs.ProblemDetails) {
	if identifier.Type != "dns" {
		va.log.Info(fmt.Sprintf("Identifier type for TLS-SNI was not DNS: %s", identifier))
		return nil, &probs.ProblemDetails{
			Type:   probs.MalformedProblem,
			Detail: "Identifier type for TLS-SNI was not DNS",
		}
	}

	// Compute the digest that will appear in the certificate
	h := sha256.New()
	h.Write([]byte(challenge.KeyAuthorization.String()))
	Z := hex.EncodeToString(h.Sum(nil))
	ZName := fmt.Sprintf("%s.%s.%s", Z[:32], Z[32:], core.TLSSNISuffix)

	return va.validateTLSWithZName(ctx, identifier, challenge, ZName)
}

// parseHTTPConnError returns the ACME ProblemType corresponding to an error
// that occurred during domain validation.
func parseHTTPConnError(err error) probs.ProblemType {
	if urlErr, ok := err.(*url.Error); ok {
		err = urlErr.Err
	}

	// XXX: On all of the resolvers I tested that validate DNSSEC, there is
	// no differentation between a DNSSEC failure and an unknown host. If we
	// do not verify DNSSEC ourselves, this function should be modified.
	if netErr, ok := err.(*net.OpError); ok {
		dnsErr, ok := netErr.Err.(*net.DNSError)
		if ok && !dnsErr.Timeout() && !dnsErr.Temporary() {
			return probs.UnknownHostProblem
		} else if fmt.Sprintf("%T", netErr.Err) == "tls.alert" {
			return probs.TLSProblem
		}
	}

	return probs.ConnectionProblem
}

func (va *ValidationAuthorityImpl) validateDNS01(ctx context.Context, identifier core.AcmeIdentifier, challenge core.Challenge) ([]core.ValidationRecord, *probs.ProblemDetails) {
	if identifier.Type != core.IdentifierDNS {
		va.log.Info(fmt.Sprintf("Identifier type for DNS challenge was not DNS: %s", identifier))
		return nil, &probs.ProblemDetails{
			Type:   probs.MalformedProblem,
			Detail: "Identifier type for DNS was not itself DNS",
		}
	}

	// Compute the digest of the key authorization file
	h := sha256.New()
	h.Write([]byte(challenge.KeyAuthorization.String()))
	authorizedKeysDigest := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	// Look for the required record in the DNS
	challengeSubdomain := fmt.Sprintf("%s.%s", core.DNSPrefix, identifier.Value)
	txts, authorities, err := va.DNSResolver.LookupTXT(ctx, challengeSubdomain)

	if err != nil {
		va.log.Info(fmt.Sprintf("Failed to lookup txt records for %s. err=[%#v] errStr=[%s]", identifier, err, err))

		return nil, bdns.ProblemDetailsFromDNSError(err)
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

	return nil, &probs.ProblemDetails{
		Type:   probs.UnauthorizedProblem,
		Detail: "Correct value not found for DNS challenge",
	}
}

func (va *ValidationAuthorityImpl) checkCAA(ctx context.Context, identifier core.AcmeIdentifier) *probs.ProblemDetails {
	// Check CAA records for the requested identifier
	present, valid, err := va.checkCAARecords(ctx, identifier)
	if err != nil {
		va.log.Warning(fmt.Sprintf("Problem checking CAA: %s", err))
		return bdns.ProblemDetailsFromDNSError(err)
	}
	// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
	va.log.AuditNotice(fmt.Sprintf("Checked CAA records for %s, [Present: %t, Valid for issuance: %t]", identifier.Value, present, valid))
	if !valid {
		return &probs.ProblemDetails{
			Type:   probs.ConnectionProblem,
			Detail: fmt.Sprintf("CAA record for %s prevents issuance", identifier.Value),
		}
	}
	return nil
}

// Overall validation process

func (va *ValidationAuthorityImpl) validate(ctx context.Context, authz core.Authorization, challengeIndex int) {
	logEvent := verificationRequestEvent{
		ID:          authz.ID,
		Requester:   authz.RegistrationID,
		RequestTime: va.clk.Now(),
	}
	challenge := &authz.Challenges[challengeIndex]
	vStart := va.clk.Now()
	validationRecords, prob := va.validateChallengeAndCAA(ctx, authz.Identifier, *challenge)

	challenge.ValidationRecord = validationRecords
	if prob != nil {
		challenge.Status = core.StatusInvalid
		challenge.Error = prob
		logEvent.Error = prob.Error()
	} else if !authz.Challenges[challengeIndex].RecordsSane() {
		challenge.Status = core.StatusInvalid
		challenge.Error = &probs.ProblemDetails{Type: probs.ServerInternalProblem,
			Detail: "Records for validation failed sanity check"}
		logEvent.Error = challenge.Error.Error()
	} else {
		challenge.Status = core.StatusValid
	}
	logEvent.Challenge = *challenge

	va.stats.TimingDuration(fmt.Sprintf("VA.Validations.%s.%s", challenge.Type, challenge.Status), time.Since(vStart), 1.0)

	// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
	va.log.AuditObject("Validation result", logEvent)

	va.log.Notice(fmt.Sprintf("Validations: %+v", authz))

	va.RA.OnValidationUpdate(authz)
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
	if !challenge.IsSane(true) {
		return nil, &probs.ProblemDetails{
			Type:   probs.MalformedProblem,
			Detail: fmt.Sprintf("Challenge failed sanity check."),
		}
	}
	switch challenge.Type {
	case core.ChallengeTypeHTTP01:
		return va.validateHTTP01(ctx, identifier, challenge)
	case core.ChallengeTypeTLSSNI01:
		return va.validateTLSSNI01(ctx, identifier, challenge)
	case core.ChallengeTypeDNS01:
		return va.validateDNS01(ctx, identifier, challenge)
	}
	return nil, &probs.ProblemDetails{
		Type:   probs.MalformedProblem,
		Detail: fmt.Sprintf("invalid challenge type %s", challenge.Type),
	}
}

// UpdateValidations runs the validate() method asynchronously using
// goroutines.
//
// TODO(#1167): remove this method
func (va *ValidationAuthorityImpl) UpdateValidations(authz core.Authorization, challengeIndex int) error {
	// TODO(#1292): add a proper deadline here
	go va.validate(context.TODO(), authz, challengeIndex)
	return nil
}

// PerformValidation runs the validate() method synchronously and returns the
// updated Challenge.
//
// TODO(#1626): remove authz parameter
func (va *ValidationAuthorityImpl) PerformValidation(domain string, challenge core.Challenge, authz core.Authorization) ([]core.ValidationRecord, error) {
	logEvent := verificationRequestEvent{
		ID:          authz.ID,
		Requester:   authz.RegistrationID,
		RequestTime: va.clk.Now(),
		Challenge:   challenge,
	}
	vStart := va.clk.Now()

	records, prob := va.validateChallengeAndCAA(context.TODO(), core.AcmeIdentifier{Type: "dns", Value: domain}, challenge)

	logEvent.ValidationRecords = records
	resultStatus := core.StatusInvalid
	if prob != nil {
		logEvent.Error = prob.Error()
	} else if !challenge.RecordsSane() {
		logEvent.Error = (&probs.ProblemDetails{
			Type:   probs.ServerInternalProblem,
			Detail: "Records for validation failed sanity check",
		}).Error()
	} else {
		resultStatus = core.StatusValid
	}

	va.stats.TimingDuration(fmt.Sprintf("VA.Validations.%s.%s", challenge.Type, resultStatus), time.Since(vStart), 1.0)

	// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
	va.log.AuditObject("Validation result", logEvent)
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

func (va *ValidationAuthorityImpl) getCAASet(ctx context.Context, hostname string) (*CAASet, error) {
	hostname = strings.TrimRight(hostname, ".")
	labels := strings.Split(hostname, ".")

	// See RFC 6844 "Certification Authority Processing" for pseudocode.
	// Essentially: check CAA records for the FDQN to be issued, and all
	// parent domains.
	//
	// The lookups are performed in parallel in order to avoid timing out
	// the RPC call.
	//
	// We depend on our resolver to snap CNAME and DNAME records.

	type result struct {
		records []*dns.CAA
		err     error
	}
	results := make([]result, len(labels))

	var wg sync.WaitGroup

	for i := 0; i < len(labels); i++ {
		// Start the concurrent DNS lookup.
		wg.Add(1)
		go func(name string, r *result) {
			r.records, r.err = va.DNSResolver.LookupCAA(ctx, name)
			wg.Done()
		}(strings.Join(labels[i:], "."), &results[i])
	}

	wg.Wait()

	// Return the first result
	for _, res := range results {
		if res.err != nil {
			return nil, res.err
		}
		if len(res.records) > 0 {
			return newCAASet(res.records), nil
		}
	}

	// no CAA records found
	return nil, nil
}

func (va *ValidationAuthorityImpl) checkCAARecords(ctx context.Context, identifier core.AcmeIdentifier) (present, valid bool, err error) {
	hostname := strings.ToLower(identifier.Value)
	caaSet, err := va.getCAASet(ctx, hostname)
	if err != nil {
		return false, false, err
	}

	if caaSet == nil {
		// No CAA records found, can issue
		va.stats.Inc("VA.CAA.None", 1, 1.0)
		return false, true, nil
	}

	// Record stats on directives not currently processed.
	if len(caaSet.Iodef) > 0 {
		va.stats.Inc("VA.CAA.WithIodef", 1, 1.0)
	}

	if caaSet.criticalUnknown() {
		// Contains unknown critical directives.
		va.stats.Inc("VA.CAA.UnknownCritical", 1, 1.0)
		return true, false, nil
	}

	if len(caaSet.Unknown) > 0 {
		va.stats.Inc("VA.CAA.WithUnknownNoncritical", 1, 1.0)
	}

	if len(caaSet.Issue) == 0 {
		// Although CAA records exist, none of them pertain to issuance in this case.
		// (e.g. there is only an issuewild directive, but we are checking for a
		// non-wildcard identifier, or there is only an iodef or non-critical unknown
		// directive.)
		va.stats.Inc("VA.CAA.NoneRelevant", 1, 1.0)
		return true, true, nil
	}

	// There are CAA records pertaining to issuance in our case. Note that this
	// includes the case of the unsatisfiable CAA record value ";", used to
	// prevent issuance by any CA under any circumstance.
	//
	// Our CAA identity must be found in the chosen checkSet.
	for _, caa := range caaSet.Issue {
		if extractIssuerDomain(caa) == va.IssuerDomain {
			va.stats.Inc("VA.CAA.Authorized", 1, 1.0)
			return true, true, nil
		}
	}

	// The list of authorized issuers is non-empty, but we are not in it. Fail.
	va.stats.Inc("VA.CAA.Unauthorized", 1, 1.0)
	return true, false, nil
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
