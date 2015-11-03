// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package va

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/net/publicsuffix"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

const maxCNAME = 16 // Prevents infinite loops. Same limit as BIND.
const maxRedirect = 10

var validationTimeout = time.Second * 5

// ErrTooManyCNAME is returned by CheckCAARecords if it has to follow too many
// consecutive CNAME lookups.
var ErrTooManyCNAME = errors.New("too many CNAME/DNAME lookups")

// ValidationAuthorityImpl represents a VA
type ValidationAuthorityImpl struct {
	RA           core.RegistrationAuthority
	log          *blog.AuditLogger
	DNSResolver  core.DNSResolver
	IssuerDomain string
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
func NewValidationAuthorityImpl(pc *PortConfig, stats statsd.Statter, clk clock.Clock) *ValidationAuthorityImpl {
	logger := blog.GetAuditLogger()
	logger.Notice("Validation Authority Starting")
	return &ValidationAuthorityImpl{
		log:       logger,
		httpPort:  pc.HTTPPort,
		httpsPort: pc.HTTPSPort,
		tlsPort:   pc.TLSPort,
		stats:     stats,
		clk:       clk,
	}
}

// Used for audit logging
type verificationRequestEvent struct {
	ID           string         `json:",omitempty"`
	Requester    int64          `json:",omitempty"`
	Challenge    core.Challenge `json:",omitempty"`
	RequestTime  time.Time      `json:",omitempty"`
	ResponseTime time.Time      `json:",omitempty"`
	Error        string         `json:",omitempty"`
}

// TODO(https://github.com/letsencrypt/boulder/issues/894): Delete this method
func verifyValidationJWS(validation *jose.JsonWebSignature, accountKey *jose.JsonWebKey, target map[string]interface{}) error {
	if len(validation.Signatures) > 1 {
		return fmt.Errorf("Too many signatures on validation JWS")
	}
	if len(validation.Signatures) == 0 {
		return fmt.Errorf("Validation JWS not signed")
	}

	payload, _, err := validation.Verify(accountKey)
	if err != nil {
		return fmt.Errorf("Validation JWS failed to verify: %s", err.Error())
	}

	var parsedResponse map[string]interface{}
	err = json.Unmarshal(payload, &parsedResponse)
	if err != nil {
		return fmt.Errorf("Validation payload failed to parse as JSON: %s", err.Error())
	}

	if len(parsedResponse) != len(target) {
		return fmt.Errorf("Validation payload had an improper number of fields")
	}

	for key, targetValue := range target {
		parsedValue, ok := parsedResponse[key]
		if !ok {
			return fmt.Errorf("Validation payload missing a field %s", key)
		} else if parsedValue != targetValue {
			return fmt.Errorf("Validation payload has improper value for field %s", key)
		}
	}

	return nil
}

// problemDetailsFromDNSError checks the error returned from Lookup...
// methods and tests if the error was an underlying net.OpError or an error
// caused by resolver returning SERVFAIL or other invalid Rcodes and returns
// the relevant core.ProblemDetails.
func problemDetailsFromDNSError(err error) *core.ProblemDetails {
	problem := &core.ProblemDetails{Type: core.ConnectionProblem}
	if netErr, ok := err.(*net.OpError); ok {
		if netErr.Timeout() {
			problem.Detail = "DNS query timed out"
		} else if netErr.Temporary() {
			problem.Detail = "Temporary network connectivity error"
		}
	} else {
		problem.Detail = "Server failure at resolver"
	}
	return problem
}

// getAddr will query for all A records associated with hostname and return the
// prefered address, the first net.IP in the addrs slice, and all addresses resolved.
// This is the same choice made by the Go internal resolution library used by
// net/http, except we only send A queries and accept IPv4 addresses.
// TODO(#593): Add IPv6 support
func (va ValidationAuthorityImpl) getAddr(hostname string) (addr net.IP, addrs []net.IP, problem *core.ProblemDetails) {
	addrs, rtt, err := va.DNSResolver.LookupHost(hostname)
	if err != nil {
		problem = problemDetailsFromDNSError(err)
		va.log.Debug(fmt.Sprintf("%s DNS failure: %s", hostname, err))
		return
	}
	va.stats.TimingDuration("VA.DNS.RTT.A", rtt, 1.0)
	va.stats.Inc("VA.DNS.Rate", 1, 1.0)

	if len(addrs) == 0 {
		problem = &core.ProblemDetails{
			Type:   core.UnknownHostProblem,
			Detail: fmt.Sprintf("No IPv4 addresses found for %s", hostname),
		}
		return
	}
	addr = addrs[0]
	va.log.Info(fmt.Sprintf("Resolved addresses for %s [using %s]: %s", hostname, addr, addrs))
	return
}

type dialer struct {
	record core.ValidationRecord
}

func (d *dialer) Dial(_, _ string) (net.Conn, error) {
	realDialer := net.Dialer{Timeout: validationTimeout}
	return realDialer.Dial("tcp", net.JoinHostPort(d.record.AddressUsed.String(), d.record.Port))
}

// resolveAndConstructDialer gets the prefered address using va.getAddr and returns
// the chosen address and dialer for that address and correct port.
func (va *ValidationAuthorityImpl) resolveAndConstructDialer(name string, port int) (dialer, *core.ProblemDetails) {
	d := dialer{
		record: core.ValidationRecord{
			Hostname: name,
			Port:     strconv.Itoa(port),
		},
	}

	addr, allAddrs, err := va.getAddr(name)
	if err != nil {
		return d, err
	}
	d.record.AddressesResolved = allAddrs
	d.record.AddressUsed = addr
	return d, nil
}

// Validation methods

func (va *ValidationAuthorityImpl) fetchHTTP(identifier core.AcmeIdentifier, path string, useTLS bool, input core.Challenge) ([]byte, core.Challenge, error) {
	emptyBody := []byte{}
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
	va.log.Audit(fmt.Sprintf("Attempting to validate %s for %s", challenge.Type, url))
	httpRequest, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		challenge.Error = &core.ProblemDetails{
			Type:   core.MalformedProblem,
			Detail: "URL provided for HTTP was invalid",
		}
		va.log.Debug(fmt.Sprintf("%s [%s] HTTP failure: %s", challenge.Type, identifier, err))
		challenge.Status = core.StatusInvalid
		return emptyBody, challenge, err
	}

	if va.UserAgent != "" {
		httpRequest.Header["User-Agent"] = []string{va.UserAgent}
	}

	dialer, prob := va.resolveAndConstructDialer(host, port)
	dialer.record.URL = url.String()
	challenge.ValidationRecord = append(challenge.ValidationRecord, dialer.record)
	if prob != nil {
		challenge.Status = core.StatusInvalid
		challenge.Error = prob
		return emptyBody, challenge, prob
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

	logRedirect := func(req *http.Request, via []*http.Request) error {
		if len(challenge.ValidationRecord) >= maxRedirect {
			return fmt.Errorf("Too many redirects")
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

		dialer, err := va.resolveAndConstructDialer(reqHost, reqPort)
		dialer.record.URL = req.URL.String()
		challenge.ValidationRecord = append(challenge.ValidationRecord, dialer.record)
		if err != nil {
			return err
		}
		tr.Dial = dialer.Dial
		va.log.Info(fmt.Sprintf("%s [%s] redirect from %q to %q [%s]", challenge.Type, identifier, via[len(via)-1].URL.String(), req.URL.String(), dialer.record.AddressUsed))
		return nil
	}
	client := http.Client{
		Transport:     tr,
		CheckRedirect: logRedirect,
		Timeout:       validationTimeout,
	}
	httpResponse, err := client.Do(httpRequest)
	if err != nil {
		challenge.Status = core.StatusInvalid
		challenge.Error = &core.ProblemDetails{
			Type:   parseHTTPConnError(err),
			Detail: fmt.Sprintf("Could not connect to %s", url),
		}
		va.log.Debug(strings.Join([]string{challenge.Error.Error(), err.Error()}, ": "))
		return emptyBody, challenge, err
	}

	if httpResponse.StatusCode != 200 {
		challenge.Status = core.StatusInvalid
		challenge.Error = &core.ProblemDetails{
			Type: core.UnauthorizedProblem,
			Detail: fmt.Sprintf("Invalid response from %s [%s]: %d",
				url.String(), dialer.record.AddressUsed, httpResponse.StatusCode),
		}
		err = challenge.Error
		return emptyBody, challenge, err
	}

	// Read body & test
	body, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		challenge.Status = core.StatusInvalid
		challenge.Error = &core.ProblemDetails{
			Type:   core.UnauthorizedProblem,
			Detail: fmt.Sprintf("Error reading HTTP response body: %v", err),
		}
		return emptyBody, challenge, err
	}

	return body, challenge, nil
}

func (va *ValidationAuthorityImpl) validateTLSWithZName(identifier core.AcmeIdentifier, input core.Challenge, zName string) (core.Challenge, error) {
	challenge := input

	addr, allAddrs, problem := va.getAddr(identifier.Value)
	challenge.ValidationRecord = []core.ValidationRecord{
		core.ValidationRecord{
			Hostname:          identifier.Value,
			AddressesResolved: allAddrs,
			AddressUsed:       addr,
		},
	}
	if problem != nil {
		challenge.Status = core.StatusInvalid
		challenge.Error = problem
		return challenge, challenge.Error
	}

	// Make a connection with SNI = nonceName
	portString := strconv.Itoa(va.tlsPort)
	hostPort := net.JoinHostPort(addr.String(), portString)
	challenge.ValidationRecord[0].Port = portString
	va.log.Notice(fmt.Sprintf("%s [%s] Attempting to validate for %s %s", challenge.Type, identifier, hostPort, zName))
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: validationTimeout}, "tcp", hostPort, &tls.Config{
		ServerName:         zName,
		InsecureSkipVerify: true,
	})

	if err != nil {
		challenge.Status = core.StatusInvalid
		challenge.Error = &core.ProblemDetails{
			Type:   parseHTTPConnError(err),
			Detail: "Failed to connect to host for DVSNI challenge",
		}
		va.log.Debug(fmt.Sprintf("%s [%s] TLS Connection failure: %s", challenge.Type, identifier, err))
		return challenge, err
	}
	defer conn.Close()

	// Check that zName is a dNSName SAN in the server's certificate
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		challenge.Error = &core.ProblemDetails{
			Type:   core.UnauthorizedProblem,
			Detail: "No certs presented for TLS SNI challenge",
		}
		challenge.Status = core.StatusInvalid
		return challenge, challenge.Error
	}
	for _, name := range certs[0].DNSNames {
		if subtle.ConstantTimeCompare([]byte(name), []byte(zName)) == 1 {
			challenge.Status = core.StatusValid
			return challenge, nil
		}
	}

	challenge.Error = &core.ProblemDetails{
		Type:   core.UnauthorizedProblem,
		Detail: "Correct zName not found for TLS SNI challenge",
	}
	challenge.Status = core.StatusInvalid
	return challenge, challenge.Error
}

// TODO(https://github.com/letsencrypt/boulder/issues/894): Delete this method
func (va *ValidationAuthorityImpl) validateSimpleHTTP(identifier core.AcmeIdentifier, input core.Challenge) (core.Challenge, error) {
	challenge := input

	if identifier.Type != core.IdentifierDNS {
		challenge.Status = core.StatusInvalid
		challenge.Error = &core.ProblemDetails{
			Type:   core.MalformedProblem,
			Detail: "Identifier type for SimpleHTTP was not DNS",
		}

		va.log.Debug(fmt.Sprintf("SimpleHTTP [%s] Identifier failure", identifier))
		return challenge, challenge.Error
	}

	// Perform the fetch
	path := fmt.Sprintf(".well-known/acme-challenge/%s", challenge.Token)
	useTLS := (challenge.TLS == nil) || *challenge.TLS
	body, challenge, err := va.fetchHTTP(identifier, path, useTLS, challenge)
	if err != nil {
		return challenge, err
	}

	// Parse and verify JWS
	parsedJws, err := jose.ParseSigned(string(body))
	if err != nil {
		err = fmt.Errorf("Validation response failed to parse as JWS: %s", err.Error())
		va.log.Debug(err.Error())
		challenge.Status = core.StatusInvalid
		challenge.Error = &core.ProblemDetails{
			Type:   core.UnauthorizedProblem,
			Detail: err.Error(),
		}
		return challenge, err
	}

	// Check that JWS body is as expected
	// * "type" == "simpleHttp"
	// * "token" == challenge.token
	// * "tls" == challenge.tls || true
	target := map[string]interface{}{
		"type":  core.ChallengeTypeSimpleHTTP,
		"token": challenge.Token,
		"tls":   (challenge.TLS == nil) || *challenge.TLS,
	}
	err = verifyValidationJWS(parsedJws, challenge.AccountKey, target)
	if err != nil {
		va.log.Debug(err.Error())
		challenge.Status = core.StatusInvalid
		challenge.Error = &core.ProblemDetails{
			Type:   core.UnauthorizedProblem,
			Detail: err.Error(),
		}
		return challenge, err
	}

	challenge.Status = core.StatusValid
	return challenge, nil
}

// TODO(https://github.com/letsencrypt/boulder/issues/894): Delete this method
func (va *ValidationAuthorityImpl) validateDvsni(identifier core.AcmeIdentifier, input core.Challenge) (core.Challenge, error) {
	challenge := input

	if identifier.Type != "dns" {
		challenge.Error = &core.ProblemDetails{
			Type:   core.MalformedProblem,
			Detail: "Identifier type for DVSNI was not DNS",
		}
		challenge.Status = core.StatusInvalid
		va.log.Debug(fmt.Sprintf("DVSNI [%s] Identifier failure", identifier))
		return challenge, challenge.Error
	}

	// Check that JWS body is as expected
	// * "type" == "dvsni"
	// * "token" == challenge.token
	target := map[string]interface{}{
		"type":  core.ChallengeTypeDVSNI,
		"token": challenge.Token,
	}
	err := verifyValidationJWS(challenge.Validation, challenge.AccountKey, target)
	if err != nil {
		va.log.Debug(err.Error())
		challenge.Status = core.StatusInvalid
		challenge.Error = &core.ProblemDetails{
			Type:   core.UnauthorizedProblem,
			Detail: err.Error(),
		}
		return challenge, err
	}

	// Compute the digest that will appear in the certificate
	encodedSignature := core.B64enc(challenge.Validation.Signatures[0].Signature)
	h := sha256.New()
	h.Write([]byte(encodedSignature))
	Z := hex.EncodeToString(h.Sum(nil))
	ZName := fmt.Sprintf("%s.%s.%s", Z[:32], Z[32:], core.TLSSNISuffix)

	return va.validateTLSWithZName(identifier, challenge, ZName)
}

func (va *ValidationAuthorityImpl) validateHTTP01(identifier core.AcmeIdentifier, input core.Challenge) (core.Challenge, error) {
	challenge := input

	if identifier.Type != core.IdentifierDNS {
		challenge.Status = core.StatusInvalid
		challenge.Error = &core.ProblemDetails{
			Type:   core.MalformedProblem,
			Detail: "Identifier type for HTTP validation was not DNS",
		}

		va.log.Debug(fmt.Sprintf("%s [%s] Identifier failure", challenge.Type, identifier))
		return challenge, challenge.Error
	}

	// Perform the fetch
	path := fmt.Sprintf(".well-known/acme-challenge/%s", challenge.Token)
	body, challenge, err := va.fetchHTTP(identifier, path, false, challenge)
	if err != nil {
		return challenge, err
	}

	// Parse body as a key authorization object
	serverKeyAuthorization, err := core.NewKeyAuthorizationFromString(string(body))
	if err != nil {
		err = fmt.Errorf("Error parsing key authorization file: %s", err.Error())
		va.log.Debug(err.Error())
		challenge.Status = core.StatusInvalid
		challenge.Error = &core.ProblemDetails{
			Type:   core.UnauthorizedProblem,
			Detail: err.Error(),
		}
		return challenge, err
	}

	// Check that the account key for this challenge is authorized by this object
	if !serverKeyAuthorization.Match(challenge.Token, challenge.AccountKey) {
		err = fmt.Errorf("The key authorization file from the server did not match this challenge [%v] != [%v]",
			challenge.KeyAuthorization.String(), string(body))
		va.log.Debug(err.Error())
		challenge.Status = core.StatusInvalid
		challenge.Error = &core.ProblemDetails{
			Type:   core.UnauthorizedProblem,
			Detail: err.Error(),
		}
		return challenge, err
	}

	challenge.Status = core.StatusValid
	return challenge, nil
}

func (va *ValidationAuthorityImpl) validateTLSSNI01(identifier core.AcmeIdentifier, input core.Challenge) (core.Challenge, error) {
	challenge := input

	if identifier.Type != "dns" {
		challenge.Error = &core.ProblemDetails{
			Type:   core.MalformedProblem,
			Detail: "Identifier type for TLS-SNI was not DNS",
		}
		challenge.Status = core.StatusInvalid
		va.log.Debug(fmt.Sprintf("TLS-SNI [%s] Identifier failure", identifier))
		return challenge, challenge.Error
	}

	// Compute the digest that will appear in the certificate
	h := sha256.New()
	h.Write([]byte(challenge.KeyAuthorization.String()))
	Z := hex.EncodeToString(h.Sum(nil))
	ZName := fmt.Sprintf("%s.%s.%s", Z[:32], Z[32:], core.TLSSNISuffix)

	return va.validateTLSWithZName(identifier, challenge, ZName)
}

// parseHTTPConnError returns the ACME ProblemType corresponding to an error
// that occurred during domain validation.
func parseHTTPConnError(err error) core.ProblemType {
	if urlErr, ok := err.(*url.Error); ok {
		err = urlErr.Err
	}

	// XXX: On all of the resolvers I tested that validate DNSSEC, there is
	// no differentation between a DNSSEC failure and an unknown host. If we
	// do not verify DNSSEC ourselves, this function should be modified.
	if netErr, ok := err.(*net.OpError); ok {
		dnsErr, ok := netErr.Err.(*net.DNSError)
		if ok && !dnsErr.Timeout() && !dnsErr.Temporary() {
			return core.UnknownHostProblem
		} else if fmt.Sprintf("%T", netErr.Err) == "tls.alert" {
			return core.TLSProblem
		}
	}

	return core.ConnectionProblem
}

func (va *ValidationAuthorityImpl) validateDNS01(identifier core.AcmeIdentifier, input core.Challenge) (core.Challenge, error) {
	challenge := input

	if identifier.Type != core.IdentifierDNS {
		challenge.Error = &core.ProblemDetails{
			Type:   core.MalformedProblem,
			Detail: "Identifier type for DNS was not itself DNS",
		}
		va.log.Debug(fmt.Sprintf("DNS [%s] Identifier failure", identifier))
		challenge.Status = core.StatusInvalid
		return challenge, challenge.Error
	}

	// Compute the digest of the key authorization file
	h := sha256.New()
	h.Write([]byte(challenge.KeyAuthorization.String()))
	authorizedKeysDigest := hex.EncodeToString(h.Sum(nil))

	// Look for the required record in the DNS
	challengeSubdomain := fmt.Sprintf("%s.%s", core.DNSPrefix, identifier.Value)
	txts, rtt, err := va.DNSResolver.LookupTXT(challengeSubdomain)
	va.stats.TimingDuration("VA.DNS.RTT.TXT", rtt, 1.0)
	va.stats.Inc("VA.DNS.Rate", 1, 1.0)

	if err != nil {
		challenge.Status = core.StatusInvalid
		challenge.Error = problemDetailsFromDNSError(err)
		va.log.Debug(fmt.Sprintf("%s [%s] DNS failure: %s", challenge.Type, identifier, err))
		return challenge, challenge.Error
	}

	for _, element := range txts {
		if subtle.ConstantTimeCompare([]byte(element), []byte(authorizedKeysDigest)) == 1 {
			challenge.Status = core.StatusValid
			return challenge, nil
		}
	}

	challenge.Error = &core.ProblemDetails{
		Type:   core.UnauthorizedProblem,
		Detail: "Correct value not found for DNS challenge",
	}
	challenge.Status = core.StatusInvalid
	return challenge, challenge.Error
}

// Overall validation process

func (va *ValidationAuthorityImpl) validate(authz core.Authorization, challengeIndex int) {
	logEvent := verificationRequestEvent{
		ID:          authz.ID,
		Requester:   authz.RegistrationID,
		RequestTime: va.clk.Now(),
	}
	if !authz.Challenges[challengeIndex].IsSane(true) {
		chall := &authz.Challenges[challengeIndex]
		chall.Status = core.StatusInvalid
		chall.Error = &core.ProblemDetails{Type: core.MalformedProblem,
			Detail: fmt.Sprintf("Challenge failed sanity check.")}
		logEvent.Challenge = *chall
		logEvent.Error = chall.Error.Detail
	} else {
		var err error

		vStart := va.clk.Now()
		switch authz.Challenges[challengeIndex].Type {
		case core.ChallengeTypeSimpleHTTP:
			// TODO(https://github.com/letsencrypt/boulder/issues/894): Delete this case
			authz.Challenges[challengeIndex], err = va.validateSimpleHTTP(authz.Identifier, authz.Challenges[challengeIndex])
		case core.ChallengeTypeDVSNI:
			// TODO(https://github.com/letsencrypt/boulder/issues/894): Delete this case
			authz.Challenges[challengeIndex], err = va.validateDvsni(authz.Identifier, authz.Challenges[challengeIndex])
		case core.ChallengeTypeHTTP01:
			authz.Challenges[challengeIndex], err = va.validateHTTP01(authz.Identifier, authz.Challenges[challengeIndex])
		case core.ChallengeTypeTLSSNI01:
			authz.Challenges[challengeIndex], err = va.validateTLSSNI01(authz.Identifier, authz.Challenges[challengeIndex])
		case core.ChallengeTypeDNS01:
			authz.Challenges[challengeIndex], err = va.validateDNS01(authz.Identifier, authz.Challenges[challengeIndex])
		}
		va.stats.TimingDuration(fmt.Sprintf("VA.Validations.%s.%s", authz.Challenges[challengeIndex].Type, authz.Challenges[challengeIndex].Status), time.Since(vStart), 1.0)

		if err != nil {
			logEvent.Error = err.Error()
		} else if !authz.Challenges[challengeIndex].RecordsSane() {
			chall := &authz.Challenges[challengeIndex]
			chall.Status = core.StatusInvalid
			chall.Error = &core.ProblemDetails{Type: core.ServerInternalProblem,
				Detail: "Records for validation failed sanity check"}
			logEvent.Error = chall.Error.Detail
		}
		logEvent.Challenge = authz.Challenges[challengeIndex]
	}

	// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
	va.log.AuditObject("Validation result", logEvent)

	va.log.Notice(fmt.Sprintf("Validations: %+v", authz))

	va.RA.OnValidationUpdate(authz)
}

// UpdateValidations runs the validate() method asynchronously using goroutines.
func (va *ValidationAuthorityImpl) UpdateValidations(authz core.Authorization, challengeIndex int) error {
	go va.validate(authz, challengeIndex)
	return nil
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
			// Critical flag is 1, but according to RFC 6844 any flag other than
			// 0 should currently be interpreted as critical.
			if caaRecord.Flag > 0 {
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

func (va *ValidationAuthorityImpl) getCAASet(hostname string) (*CAASet, error) {
	hostname = strings.TrimRight(hostname, ".")
	labels := strings.Split(hostname, ".")
	// See RFC 6844 "Certification Authority Processing" for pseudocode.
	// Essentially: check CAA records for the FDQN to be issued, and all parent
	// domains.
	// We depend on our resolver to snap CNAME and DNAME records.
	for i := 0; i < len(labels); i++ {
		name := strings.Join(labels[i:len(labels)], ".")
		// Break if we've reached an ICANN TLD.
		if tld, err := publicsuffix.ICANNTLD(name); err != nil || tld == name {
			break
		}
		CAAs, caaRtt, err := va.DNSResolver.LookupCAA(name)
		if err != nil {
			return nil, err
		}
		va.stats.TimingDuration("VA.DNS.RTT.CAA", caaRtt, 1.0)
		va.stats.Inc("VA.DNS.Rate", 1, 1.0)
		if len(CAAs) > 0 {
			return newCAASet(CAAs), nil
		}
	}
	// no CAA records found
	return nil, nil
}

// CheckCAARecords verifies that, if the indicated subscriber domain has any CAA
// records, they authorize the configured CA domain to issue a certificate
func (va *ValidationAuthorityImpl) CheckCAARecords(identifier core.AcmeIdentifier) (present, valid bool, err error) {
	hostname := strings.ToLower(identifier.Value)
	caaSet, err := va.getCAASet(hostname)
	if err != nil {
		return
	}
	if caaSet == nil {
		// No CAA records found, can issue
		present = false
		valid = true
		return
	} else if caaSet.criticalUnknown() {
		present = true
		valid = false
		return
	} else if len(caaSet.Issue) > 0 || len(caaSet.Issuewild) > 0 {
		present = true
		var checkSet []*dns.CAA
		if strings.SplitN(hostname, ".", 2)[0] == "*" {
			checkSet = caaSet.Issuewild
		} else {
			checkSet = caaSet.Issue
		}
		for _, caa := range checkSet {
			if caa.Value == va.IssuerDomain {
				valid = true
				return
			} else if caa.Flag > 0 {
				valid = false
				return
			}
		}

		valid = false
		return
	}

	return
}
