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

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/policy"
)

const maxCNAME = 16 // Prevents infinite loops. Same limit as BIND.
const maxRedirect = 10

var validationTimeout = time.Second * 5

// Returned by CheckCAARecords if it has to follow too many
// consecutive CNAME lookups.
var ErrTooManyCNAME = errors.New("too many CNAME/DNAME lookups")

// ValidationAuthorityImpl represents a VA
type ValidationAuthorityImpl struct {
	RA              core.RegistrationAuthority
	log             *blog.AuditLogger
	DNSResolver     core.DNSResolver
	IssuerDomain    string
	simpleHTTPPort  int
	simpleHTTPSPort int
	dvsniPort       int
	UserAgent       string
}

// PortConfig specifies what ports the VA should call to on the remote
// host when performing its checks.
type PortConfig struct {
	SimpleHTTPPort  int
	SimpleHTTPSPort int
	DVSNIPort       int
}

// NewValidationAuthorityImpl constructs a new VA
func NewValidationAuthorityImpl(pc *PortConfig) *ValidationAuthorityImpl {
	logger := blog.GetAuditLogger()
	logger.Notice("Validation Authority Starting")
	return &ValidationAuthorityImpl{
		log:             logger,
		simpleHTTPPort:  pc.SimpleHTTPPort,
		simpleHTTPSPort: pc.SimpleHTTPSPort,
		dvsniPort:       pc.DVSNIPort,
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
func (va *ValidationAuthorityImpl) getAddr(hostname string) (addr net.IP, addrs []net.IP, problem *core.ProblemDetails) {
	addrs, _, err := va.DNSResolver.LookupHost(hostname)
	if err != nil {
		problem = problemDetailsFromDNSError(err)
		va.log.Debug(fmt.Sprintf("%s DNS failure: %s", hostname, err))
		return
	}
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
func (va *ValidationAuthorityImpl) resolveAndConstructDialer(name, defaultPort string) (dialer, *core.ProblemDetails) {
	port := fmt.Sprintf("%d", va.simpleHTTPPort)
	if defaultPort != "" {
		port = defaultPort
	}
	d := dialer{
		record: core.ValidationRecord{
			Hostname: name,
			Port:     port,
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

	host := identifier.Value
	var scheme string
	var port int
	if input.TLS == nil || (input.TLS != nil && *input.TLS) {
		scheme = "https"
		port = va.simpleHTTPSPort
	} else {
		scheme = "http"
		port = va.simpleHTTPPort
	}
	portString := fmt.Sprintf("%d", port)
	hostPort := net.JoinHostPort(host, portString)

	url := &url.URL{
		Scheme: scheme,
		Host:   hostPort,
		Path:   fmt.Sprintf(".well-known/acme-challenge/%s", challenge.Token),
	}

	// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
	va.log.Audit(fmt.Sprintf("Attempting to validate Simple%s for %s", strings.ToUpper(scheme), url))
	httpRequest, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		challenge.Error = &core.ProblemDetails{
			Type:   core.MalformedProblem,
			Detail: "URL provided for SimpleHTTP was invalid",
		}
		va.log.Debug(fmt.Sprintf("SimpleHTTP [%s] HTTP failure: %s", identifier, err))
		challenge.Status = core.StatusInvalid
		return challenge, err
	}

	if va.UserAgent != "" {
		httpRequest.Header["User-Agent"] = []string{va.UserAgent}
	}

	httpRequest.Host = hostPort
	dialer, prob := va.resolveAndConstructDialer(host, portString)
	dialer.record.URL = url.String()
	challenge.ValidationRecord = append(challenge.ValidationRecord, dialer.record)
	if prob != nil {
		challenge.Status = core.StatusInvalid
		challenge.Error = prob
		return challenge, prob
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
		reqPort := ""
		if strings.Contains(reqHost, ":") {
			splitHost := strings.SplitN(reqHost, ":", 2)
			if len(splitHost) <= 1 {
				return fmt.Errorf("Malformed host")
			}
			reqHost, reqPort = splitHost[0], splitHost[1]
			portNum, err := strconv.Atoi(reqPort)
			if err != nil {
				return err
			}
			if portNum < 0 || portNum > 65535 {
				return fmt.Errorf("Invalid port number in redirect")
			}
		} else if strings.ToLower(req.URL.Scheme) == "https" {
			reqPort = "443"
		}

		dialer, err := va.resolveAndConstructDialer(reqHost, reqPort)
		dialer.record.URL = req.URL.String()
		challenge.ValidationRecord = append(challenge.ValidationRecord, dialer.record)
		if err != nil {
			return err
		}
		tr.Dial = dialer.Dial
		va.log.Info(fmt.Sprintf("validateSimpleHTTP [%s] redirect from %q to %q [%s]", identifier, via[len(via)-1].URL.String(), req.URL.String(), dialer.record.AddressUsed))
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
		return challenge, err
	}

	if httpResponse.StatusCode != 200 {
		challenge.Status = core.StatusInvalid
		challenge.Error = &core.ProblemDetails{
			Type: core.UnauthorizedProblem,
			Detail: fmt.Sprintf("Invalid response from %s [%s]: %d",
				url.String(), dialer.record.AddressUsed, httpResponse.StatusCode),
		}
		err = challenge.Error
		return challenge, err
	}

	// Read body & test
	body, readErr := ioutil.ReadAll(httpResponse.Body)
	if readErr != nil {
		challenge.Status = core.StatusInvalid
		challenge.Error = &core.ProblemDetails{
			Type:   core.UnauthorizedProblem,
			Detail: fmt.Sprintf("Error reading HTTP response body"),
		}
		return challenge, readErr
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
	ZName := fmt.Sprintf("%s.%s.%s", Z[:32], Z[32:], core.DVSNISuffix)

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
	portString := fmt.Sprintf("%d", va.dvsniPort)
	hostPort := net.JoinHostPort(addr.String(), portString)
	challenge.ValidationRecord[0].Port = portString
	va.log.Notice(fmt.Sprintf("DVSNI [%s] Attempting to validate DVSNI for %s %s",
		identifier, hostPort, ZName))
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: validationTimeout}, "tcp", hostPort, &tls.Config{
		ServerName:         ZName,
		InsecureSkipVerify: true,
	})

	if err != nil {
		challenge.Status = core.StatusInvalid
		challenge.Error = &core.ProblemDetails{
			Type:   parseHTTPConnError(err),
			Detail: "Failed to connect to host for DVSNI challenge",
		}
		va.log.Debug(fmt.Sprintf("DVSNI [%s] TLS Connection failure: %s", identifier, err))
		return challenge, err
	}
	defer conn.Close()

	// Check that ZName is a dNSName SAN in the server's certificate
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		challenge.Error = &core.ProblemDetails{
			Type:   core.UnauthorizedProblem,
			Detail: "No certs presented for DVSNI challenge",
		}
		challenge.Status = core.StatusInvalid
		return challenge, challenge.Error
	}
	for _, name := range certs[0].DNSNames {
		if subtle.ConstantTimeCompare([]byte(name), []byte(ZName)) == 1 {
			challenge.Status = core.StatusValid
			return challenge, nil
		}
	}

	challenge.Error = &core.ProblemDetails{
		Type:   core.UnauthorizedProblem,
		Detail: "Correct ZName not found for DVSNI challenge",
	}
	challenge.Status = core.StatusInvalid
	return challenge, challenge.Error
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

func (va *ValidationAuthorityImpl) validateDNS(identifier core.AcmeIdentifier, input core.Challenge) (core.Challenge, error) {
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

	// Check that JWS body is as expected
	// * "type" == "dvsni"
	// * "token" == challenge.token
	target := map[string]interface{}{
		"type":  core.ChallengeTypeDNS,
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
	encodedSignature := core.B64enc(challenge.Validation.Signatures[0].Signature)

	// Look for the required record in the DNS
	challengeSubdomain := fmt.Sprintf("%s.%s", core.DNSPrefix, identifier.Value)
	txts, _, err := va.DNSResolver.LookupTXT(challengeSubdomain)

	if err != nil {
		challenge.Status = core.StatusInvalid
		challenge.Error = problemDetailsFromDNSError(err)
		va.log.Debug(fmt.Sprintf("%s [%s] DNS failure: %s", challenge.Type, identifier, err))
		return challenge, challenge.Error
	}

	for _, element := range txts {
		if subtle.ConstantTimeCompare([]byte(element), []byte(encodedSignature)) == 1 {
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
		RequestTime: time.Now(),
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

		switch authz.Challenges[challengeIndex].Type {
		case core.ChallengeTypeSimpleHTTP:
			authz.Challenges[challengeIndex], err = va.validateSimpleHTTP(authz.Identifier, authz.Challenges[challengeIndex])
		case core.ChallengeTypeDVSNI:
			authz.Challenges[challengeIndex], err = va.validateDvsni(authz.Identifier, authz.Challenges[challengeIndex])
		case core.ChallengeTypeDNS:
			authz.Challenges[challengeIndex], err = va.validateDNS(authz.Identifier, authz.Challenges[challengeIndex])
		}

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
	label := strings.TrimRight(hostname, ".")
	cnames := 0
	// See RFC 6844 "Certification Authority Processing" for pseudocode.
	for {
		if strings.IndexRune(label, '.') == -1 {
			// Reached TLD
			break
		}
		if _, present := policy.PublicSuffixList[label]; present {
			break
		}
		CAAs, _, err := va.DNSResolver.LookupCAA(label)
		if err != nil {
			return nil, err
		}
		if len(CAAs) > 0 {
			return newCAASet(CAAs), nil
		}
		cname, _, err := va.DNSResolver.LookupCNAME(label)
		if err != nil {
			return nil, err
		}
		dname, _, err := va.DNSResolver.LookupDNAME(label)
		if err != nil {
			return nil, err
		}
		if cname == "" && dname == "" {
			// Try parent domain (note we confirmed
			// earlier that label contains '.')
			label = label[strings.IndexRune(label, '.')+1:]
			continue
		}
		if cname != "" && dname != "" && cname != dname {
			return nil, errors.New("both CNAME and DNAME exist for " + label)
		}
		if cname != "" {
			label = cname
		} else {
			label = dname
		}
		if cnames++; cnames > maxCNAME {
			return nil, ErrTooManyCNAME
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
