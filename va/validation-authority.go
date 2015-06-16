// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package va

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/square/go-jose"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

type ValidationAuthorityImpl struct {
	RA           core.RegistrationAuthority
	log          *blog.AuditLogger
	DNSResolver  string
	DNSTimeout   time.Duration
	IssuerDomain string
	TestMode     bool
}

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

func (va ValidationAuthorityImpl) validateSimpleHTTP(identifier core.AcmeIdentifier, input core.Challenge, accountKey jose.JsonWebKey) (core.Challenge, error) {
	challenge := input

	if len(challenge.Path) == 0 {
		challenge.Status = core.StatusInvalid
		err := fmt.Errorf("No path provided for SimpleHTTP challenge.")
		return challenge, err
	}

	if identifier.Type != core.IdentifierDNS {
		challenge.Status = core.StatusInvalid
		err := fmt.Errorf("Identifier type for SimpleHTTP was not DNS")
		return challenge, err
	}
	hostName := identifier.Value
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

	if err != nil {
		va.log.Debug(fmt.Sprintf("Could not connect to %s: %s", url, err.Error()))
		challenge.Status = core.StatusInvalid
		return challenge, err
	}

	if httpResponse.StatusCode != 200 {
		err = fmt.Errorf("Invalid response from %s: %d", url, httpResponse.StatusCode)
		challenge.Status = core.StatusInvalid
		return challenge, err
	}

	// Read body & test
	body, readErr := ioutil.ReadAll(httpResponse.Body)
	if readErr != nil {
		challenge.Status = core.StatusInvalid
		return challenge, readErr
	}

	// Parse and verify JWS
	parsedJws, err := jose.ParseSigned(string(body))
	if err != nil {
		err = fmt.Errorf("Validation response failed to parse as JWS: %s", err.Error())
		va.log.Debug(err.Error())
		challenge.Status = core.StatusInvalid
		return challenge, err
	}

	if len(parsedJws.Signatures) > 1 {
		err = fmt.Errorf("Too many signatures on validation JWS")
		va.log.Debug(err.Error())
		challenge.Status = core.StatusInvalid
		return challenge, err
	}
	if len(parsedJws.Signatures) == 0 {
		err = fmt.Errorf("Validation JWS not signed")
		va.log.Debug(err.Error())
		challenge.Status = core.StatusInvalid
		return challenge, err
	}

	key := parsedJws.Signatures[0].Header.JsonWebKey
	if !core.KeyDigestEquals(key, accountKey) {
		err = fmt.Errorf("Response JWS signed with improper key: %s", err.Error())
		va.log.Debug(err.Error())
		challenge.Status = core.StatusInvalid
		return challenge, err
	}

	payload, _, err := parsedJws.Verify(key)
	if err != nil {
		err = fmt.Errorf("Validation response failed to verify: %s", err.Error())
		va.log.Debug(err.Error())
		challenge.Status = core.StatusInvalid
		return challenge, err
	}

	// Check that JWS body is as expected
	// * "type" == "simpleHttp"
	// * "token" == challenge.token
	// * "path" == challenge.path
	// * "tls" == challenge.tls
	va.log.Debug(fmt.Sprintf("Validation response payload: %s", string(payload)))
	var parsedResponse map[string]interface{}
	err = json.Unmarshal(payload, &parsedResponse)
	if err != nil {
		err = fmt.Errorf("Validation payload failed to parse as JSON: %s", err.Error())
		va.log.Debug(err.Error())
		challenge.Status = core.StatusInvalid
		return challenge, err
	}
	if len(parsedResponse) != 4 {
		err = fmt.Errorf("Validation payload did not have all fields")
		va.log.Debug(err.Error())
		challenge.Status = core.StatusInvalid
		return challenge, err
	}
	typePassed := false
	tokenPassed := false
	pathPassed := false
	tlsPassed := false
	for key, value := range parsedResponse {
		switch key {
		case "type":
			castValue, ok := value.(string)
			typePassed = ok && castValue == core.ChallengeTypeSimpleHTTP
		case "token":
			castValue, ok := value.(string)
			tokenPassed = ok && castValue == challenge.Token
		case "path":
			castValue, ok := value.(string)
			pathPassed = ok && castValue == challenge.Path
		case "tls":
			castValue, ok := value.(bool)
			tlsValue := challenge.TLS != nil && *challenge.TLS
			tlsPassed = ok && castValue == tlsValue
		default:
			err = fmt.Errorf("Validation payload did not have all fields")
			challenge.Status = core.StatusInvalid
			return challenge, err
		}
	}
	if !typePassed || !tokenPassed || !pathPassed || !tlsPassed {
		err = fmt.Errorf("Validation contents were not correct: type=%v token=%v path=%v tls=%v",
			typePassed, tokenPassed, pathPassed, tlsPassed)
		va.log.Debug(err.Error())
		challenge.Status = core.StatusInvalid
		return challenge, err
	}

	challenge.Status = core.StatusValid
	return challenge, nil
}

func (va ValidationAuthorityImpl) validateDvsni(identifier core.AcmeIdentifier, input core.Challenge, accountKey jose.JsonWebKey) (core.Challenge, error) {
	challenge := input

	if identifier.Type != "dns" {
		err := fmt.Errorf("Identifier type for DVSNI was not DNS")
		challenge.Status = core.StatusInvalid
		return challenge, err
	}

	const DVSNI_SUFFIX = ".acme.invalid"
	nonceName := challenge.Nonce + DVSNI_SUFFIX

	R, err := core.B64dec(challenge.R)
	if err != nil {
		va.log.Debug("Failed to decode R value from DVSNI challenge")
		challenge.Status = core.StatusInvalid
		return challenge, err
	}
	S, err := core.B64dec(challenge.S)
	if err != nil {
		va.log.Debug("Failed to decode S value from DVSNI challenge")
		challenge.Status = core.StatusInvalid
		return challenge, err
	}
	RS := append(R, S...)

	z := sha256.Sum256(RS)
	zName := fmt.Sprintf("%064x.acme.invalid", z)

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
		va.log.Debug("Failed to connect to host for DVSNI challenge")
		challenge.Status = core.StatusInvalid
		return challenge, err
	}
	defer conn.Close()

	// Check that zName is a dNSName SAN in the server's certificate
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		err = fmt.Errorf("No certs presented for DVSNI challenge")
		challenge.Status = core.StatusInvalid
		return challenge, err
	}
	if !core.KeyDigestEquals(certs[0].PublicKey, accountKey) {
		err = fmt.Errorf("DVSNI server presented improper public key")
		challenge.Status = core.StatusInvalid
		return challenge, err
	}
	for _, name := range certs[0].DNSNames {
		if subtle.ConstantTimeCompare([]byte(name), []byte(zName)) == 1 {
			challenge.Status = core.StatusValid
			return challenge, nil
		}
	}

	err = fmt.Errorf("Correct zName not found for DVSNI challenge")
	challenge.Status = core.StatusInvalid
	return challenge, err
}

// Overall validation process

func (va ValidationAuthorityImpl) validate(authz core.Authorization, challengeIndex int, accountKey jose.JsonWebKey) {

	// Select the first supported validation method
	// XXX: Remove the "break" lines to process all supported validations
	logEvent := verificationRequestEvent{
		ID:          authz.ID,
		Requester:   authz.RegistrationID,
		RequestTime: time.Now(),
	}
	if !authz.Challenges[challengeIndex].IsSane(true) {
		authz.Challenges[challengeIndex].Status = core.StatusInvalid
		logEvent.Error = fmt.Sprintf("Challenge failed sanity check.")
		logEvent.Challenge = authz.Challenges[challengeIndex]
	} else {
		var err error

		switch authz.Challenges[challengeIndex].Type {
		case core.ChallengeTypeSimpleHTTP:
			authz.Challenges[challengeIndex], err = va.validateSimpleHTTP(authz.Identifier, authz.Challenges[challengeIndex], accountKey)
			break
		case core.ChallengeTypeDVSNI:
			authz.Challenges[challengeIndex], err = va.validateDvsni(authz.Identifier, authz.Challenges[challengeIndex], accountKey)
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

func (va ValidationAuthorityImpl) UpdateValidations(authz core.Authorization, challengeIndex int, accountKey jose.JsonWebKey) error {
	go va.validate(authz, challengeIndex, accountKey)
	return nil
}

// CheckCAA verifies that, if the indicated subscriber domain has any CAA
// records, they authorize the configured CA domain to issue a certificate
func (va *ValidationAuthorityImpl) CheckCAARecords(identifier core.AcmeIdentifier) (present, valid bool, err error) {
	domain := strings.ToLower(identifier.Value)
	caaSet, err := getCaaSet(domain, va.DNSResolver, va.DNSTimeout)
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
