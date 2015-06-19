// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package va

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

// ValidationAuthorityImpl represents a VA
type ValidationAuthorityImpl struct {
	RA           core.RegistrationAuthority
	log          *blog.AuditLogger
	DNSResolver  *core.DNSResolver
	IssuerDomain string
	TestMode     bool
}

// NewValidationAuthorityImpl constructs a new VA, and may place it
// into Test Mode (tm)
func NewValidationAuthorityImpl(tm bool) ValidationAuthorityImpl {
	logger := blog.GetAuditLogger()
	logger.Notice("Validation Authority Starting")
	return ValidationAuthorityImpl{log: logger, TestMode: tm}
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

// Validation methods

func (va ValidationAuthorityImpl) validateSimpleHTTP(identifier core.AcmeIdentifier, input core.Challenge) (core.Challenge, error) {
	challenge := input

	if len(challenge.Path) == 0 {
		challenge.Status = core.StatusInvalid
		challenge.Error = &core.ProblemDetails{
			Type:   core.MalformedProblem,
			Detail: "No path provided for SimpleHTTP challenge.",
		}
		return challenge, challenge.Error
	}

	if identifier.Type != core.IdentifierDNS {
		challenge.Status = core.StatusInvalid
		challenge.Error = &core.ProblemDetails{
			Type:   core.MalformedProblem,
			Detail: "Identifier type for SimpleHTTP was not DNS",
		}
		return challenge, challenge.Error
	}
	hostName := identifier.Value

	// Check for DNSSEC failures for A/AAAA records
	_, _, err := va.DNSResolver.LookupHost(hostName)
	if dnssecErr, ok := err.(core.DNSSECError); ok {
		challenge.Error = &core.ProblemDetails{
			Type:   core.DNSSECProblem,
			Detail: dnssecErr.Error(),
		}
	} else {
		challenge.Error = &core.ProblemDetails{
			Type:   core.ServerInternalProblem,
			Detail: "Unable to communicate with DNS server",
		}
	}

	var scheme string
	if input.TLS == nil || (input.TLS != nil && *input.TLS) {
		scheme = "https"
	} else {
		scheme = "http"
	}
	if va.TestMode {
		hostName = "localhost:5001"
		scheme = "http"
	}

	url := fmt.Sprintf("%s://%s/.well-known/acme-challenge/%s", scheme, hostName, challenge.Path)


	// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
	va.log.Audit(fmt.Sprintf("Attempting to validate Simple%s for %s", strings.ToUpper(scheme), url))
	httpRequest, err := http.NewRequest("GET", url, nil)
	if err != nil {
		challenge.Error = &core.ProblemDetails{
			Type:   core.MalformedProblem,
			Detail: "URL provided for SimpleHTTP was invalid",
		}
		challenge.Status = core.StatusInvalid
		return challenge, err
	}

	httpRequest.Host = hostName
	tr := &http.Transport{
		// We are talking to a client that does not yet have a certificate,
		// so we accept a temporary, invalid one.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		// We don't expect to make multiple requests to a client, so close
		// connection immediately.
		DisableKeepAlives: true,
	}
	client := http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
	}
	httpResponse, err := client.Do(httpRequest)

	if err == nil && httpResponse.StatusCode == 200 {
		// Read body & test
		body, readErr := ioutil.ReadAll(httpResponse.Body)
		if readErr != nil {
			challenge.Error = &core.ProblemDetails{
				Type: core.ServerInternalProblem,
			}
			challenge.Status = core.StatusInvalid
			return challenge, readErr
		}

		if subtle.ConstantTimeCompare(body, []byte(challenge.Token)) == 1 {
			challenge.Status = core.StatusValid
		} else {
			challenge.Status = core.StatusInvalid
			challenge.Error = &core.ProblemDetails{
				Type: core.UnauthorizedProblem,
				Detail: fmt.Sprintf("Incorrect token validating Simple%s for %s",
					strings.ToUpper(scheme), url),
			}
			err = challenge.Error
		}
	} else if err != nil {
		challenge.Status = core.StatusInvalid
		challenge.Error = &core.ProblemDetails{
			Type:   parseHTTPConnError(err),
			Detail: fmt.Sprintf("Could not connect to %s", url),
		}
		va.log.Debug(strings.Join([]string{challenge.Error.Error(), err.Error()}, ": "))
	} else {
		challenge.Status = core.StatusInvalid
		challenge.Error = &core.ProblemDetails{
			Type: core.UnauthorizedProblem,
			Detail: fmt.Sprintf("Invalid response from %s: %d",
				url, httpResponse.StatusCode),
		}
		err = challenge.Error
	}

	return challenge, err
}

func (va ValidationAuthorityImpl) validateDvsni(identifier core.AcmeIdentifier, input core.Challenge) (core.Challenge, error) {
	challenge := input

	if identifier.Type != "dns" {
		challenge.Error = &core.ProblemDetails{
			Type:   core.MalformedProblem,
			Detail: "Identifier type for DVSNI was not DNS",
		}
		challenge.Status = core.StatusInvalid
		return challenge, challenge.Error
	}

	const DVSNIsuffix = ".acme.invalid"
	nonceName := challenge.Nonce + DVSNIsuffix

	R, err := core.B64dec(challenge.R)
	if err != nil {
		challenge.Status = core.StatusInvalid
		challenge.Error = &core.ProblemDetails{
			Type:   core.MalformedProblem,
			Detail: "Failed to decode R value from DVSNI challenge",
		}
		va.log.Debug(challenge.Error.Detail)
		return challenge, err
	}
	S, err := core.B64dec(challenge.S)
	if err != nil {
		challenge.Status = core.StatusInvalid
		challenge.Error = &core.ProblemDetails{
			Type:   core.MalformedProblem,
			Detail: "Failed to decode S value from DVSNI challenge",
		}
		va.log.Debug(challenge.Error.Detail)
		return challenge, err
	}
	RS := append(R, S...)

	z := sha256.Sum256(RS)
	zName := fmt.Sprintf("%064x.acme.invalid", z)

	// Check for DNSSEC failures for A/AAAA records
	_, _, err = va.DNSResolver.LookupHost(identifier.Value)
	if dnssecErr, ok := err.(core.DNSSECError); ok {
		challenge.Error = &core.ProblemDetails{
			Type:   core.DNSSECProblem,
			Detail: dnssecErr.Error(),
		}
	} else {
		challenge.Error = &core.ProblemDetails{
			Type:   core.ServerInternalProblem,
			Detail: "Unable to communicate with DNS server",
		}
	}

	// Make a connection with SNI = nonceName
	hostPort := identifier.Value + ":443"
	if va.TestMode {
		hostPort = "localhost:5001"
	}
	va.log.Notice(fmt.Sprintf("Attempting to validate DVSNI for %s %s %s",
		identifier, hostPort, zName))
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", hostPort, &tls.Config{
		ServerName:         nonceName,
		InsecureSkipVerify: true,
	})

	if err != nil {
		challenge.Status = core.StatusInvalid
		challenge.Error = &core.ProblemDetails{
			Type:   parseHTTPConnError(err),
			Detail: "Failed to connect to host for DVSNI challenge",
		}
		va.log.Debug(challenge.Error.Detail)
		return challenge, err
	}
	defer conn.Close()

	// Check that zName is a dNSName SAN in the server's certificate
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
		if subtle.ConstantTimeCompare([]byte(name), []byte(zName)) == 1 {
			challenge.Status = core.StatusValid
			return challenge, nil
		}
	}

	challenge.Error = &core.ProblemDetails{
		Type:   core.UnauthorizedProblem,
		Detail: "Correct zName not found for DVSNI challenge",
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

func (va ValidationAuthorityImpl) validateDNS(identifier core.AcmeIdentifier, input core.Challenge) (core.Challenge, error) {
	challenge := input

	if identifier.Type != core.IdentifierDNS {
		challenge.Error = &core.ProblemDetails{
			Type:   core.MalformedProblem,
			Detail: "Identifier type for DNS was not itself DNS",
		}
		challenge.Status = core.StatusInvalid
		return challenge, challenge.Error
	}

	const DNSPrefix = "_acme-challenge"

	challengeSubdomain := fmt.Sprintf("%s.%s", DNSPrefix, identifier.Value)
	txts, _, err := va.DNSResolver.LookupTXT(challengeSubdomain)

	if err != nil {
		if dnssecErr, ok := err.(core.DNSSECError); ok {
			challenge.Error = &core.ProblemDetails{
				Type:   core.DNSSECProblem,
				Detail: dnssecErr.Error(),
			}
		} else {
			challenge.Error = &core.ProblemDetails{
				Type:   core.ServerInternalProblem,
				Detail: "Unable to communicate with DNS server",
			}
		}
		challenge.Status = core.StatusInvalid
		return challenge, err
	}

	byteToken := []byte(challenge.Token)
	for _, element := range txts {
		if subtle.ConstantTimeCompare([]byte(element), byteToken) == 1 {
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

func (va ValidationAuthorityImpl) validate(authz core.Authorization, challengeIndex int) {

	// Select the first supported validation method
	// XXX: Remove the "break" lines to process all supported validations
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
			break
		case core.ChallengeTypeDVSNI:
			authz.Challenges[challengeIndex], err = va.validateDvsni(authz.Identifier, authz.Challenges[challengeIndex])
			break
		case core.ChallengeTypeDNS:
			authz.Challenges[challengeIndex], err = va.validateDNS(authz.Identifier, authz.Challenges[challengeIndex])
			break
		}

		logEvent.Challenge = authz.Challenges[challengeIndex]
		if err != nil {
			logEvent.Error = err.Error()
		}
	}

	// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
	va.log.AuditObject("Validation result", logEvent)

	va.log.Notice(fmt.Sprintf("Validations: %+v", authz))

	va.RA.OnValidationUpdate(authz)
}

// UpdateValidations runs the validate() method asynchronously using goroutines.
func (va ValidationAuthorityImpl) UpdateValidations(authz core.Authorization, challengeIndex int) error {
	go va.validate(authz, challengeIndex)
	return nil
}

// CheckCAARecords verifies that, if the indicated subscriber domain has any CAA
// records, they authorize the configured CA domain to issue a certificate
func (va *ValidationAuthorityImpl) CheckCAARecords(identifier core.AcmeIdentifier) (present, valid bool, err error) {
	domain := strings.ToLower(identifier.Value)
	caaSet, err := getCaaSet(domain, va.DNSResolver)
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
	} else if len(caaSet.issue) > 0 || len(caaSet.issuewild) > 0 {
		present = true
		var checkSet []*CAA
		if strings.SplitN(domain, ".", 2)[0] == "*" {
			checkSet = caaSet.issuewild
		} else {
			checkSet = caaSet.issue
		}
		for _, caa := range checkSet {
			if caa.value == va.IssuerDomain {
				valid = true
				return
			}
		}

		valid = false
		return
	}

	return
}
