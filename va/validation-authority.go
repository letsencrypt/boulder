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
	"net/http"
	"time"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

type ValidationAuthorityImpl struct {
	RA       core.RegistrationAuthority
	log      *blog.AuditLogger
	TestMode bool
}

func NewValidationAuthorityImpl(tm bool) ValidationAuthorityImpl {
	logger := blog.GetAuditLogger()
	logger.Notice("Validation Authority Starting")
	return ValidationAuthorityImpl{log: logger, TestMode: tm}
}

// Validation methods

func (va ValidationAuthorityImpl) validateSimpleHTTPS(identifier core.AcmeIdentifier, input core.Challenge) (challenge core.Challenge) {
	challenge = input

	if len(challenge.Path) == 0 {
		challenge.Status = core.StatusInvalid
		return
	}

	if identifier.Type != core.IdentifierDNS {
		challenge.Status = core.StatusInvalid
		return
	}
	hostName := identifier.Value
	protocol := "https"
	if va.TestMode {
		hostName = "localhost:5001"
		protocol = "http"
	}

	url := fmt.Sprintf("%s://%s/.well-known/acme-challenge/%s", protocol, hostName, challenge.Path)

	va.log.Notice(fmt.Sprintf("Attempting to validate SimpleHTTPS for %s %s", hostName, url))
	httpRequest, err := http.NewRequest("GET", url, nil)
	if err != nil {
		va.log.Notice(fmt.Sprintf("Error validating SimpleHTTPS for %s %s: %s", hostName, url, err))
		challenge.Status = core.StatusInvalid
		return
	}

	httpRequest.Host = hostName
	tr := &http.Transport{
		// We are talking to a client that does not yet have a certificate,
		// so we accept a temporary, invalid one. TODO: We may want to change this
		// to just be over HTTP.
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
		body, err := ioutil.ReadAll(httpResponse.Body)
		if err != nil {
			va.log.Notice(fmt.Sprintf("Error validating SimpleHTTPS for %s %s: %s", hostName, url, err))
			challenge.Status = core.StatusInvalid
			return
		}

		if subtle.ConstantTimeCompare(body, []byte(challenge.Token)) == 1 {
			challenge.Status = core.StatusValid
			return
		} else {
			va.log.Notice(fmt.Sprintf("Incorrect token validating SimpleHTTPS for %s %s", hostName, url))
		}
	} else if err != nil {
		va.log.Notice(fmt.Sprintf("Error validating SimpleHTTPS for %s %s: %s", hostName, url, err))
		challenge.Status = core.StatusInvalid
	} else {
		va.log.Notice(fmt.Sprintf("Error validating SimpleHTTPS for %s %s: %d", hostName, url, httpResponse.StatusCode))
		challenge.Status = core.StatusInvalid
	}
	return
}

func (va ValidationAuthorityImpl) validateDvsni(identifier core.AcmeIdentifier, input core.Challenge) (challenge core.Challenge) {
	if identifier.Type != "dns" {
		challenge.Status = core.StatusInvalid
		return
	}

	challenge = input

	const DVSNI_SUFFIX = ".acme.invalid"
	nonceName := challenge.Nonce + DVSNI_SUFFIX

	R, err := core.B64dec(challenge.R)
	if err != nil {
		challenge.Status = core.StatusInvalid
		return
	}
	S, err := core.B64dec(challenge.S)
	if err != nil {
		challenge.Status = core.StatusInvalid
		return
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
	conn, err := tls.Dial("tcp", hostPort, &tls.Config{
		ServerName:         nonceName,
		InsecureSkipVerify: true,
	})

	if err != nil {
		challenge.Status = core.StatusInvalid
		return
	}
	defer conn.Close()

	// Check that zName is a dNSName SAN in the server's certificate
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		challenge.Status = core.StatusInvalid
		return
	}
	for _, name := range certs[0].DNSNames {
		if subtle.ConstantTimeCompare([]byte(name), []byte(zName)) == 1 {
			challenge.Status = core.StatusValid
			return
		}
	}

	challenge.Status = core.StatusInvalid
	return
}

// Overall validation process

func (va ValidationAuthorityImpl) validate(authz core.Authorization) {
	// Select the first supported validation method
	// XXX: Remove the "break" lines to process all supported validations
	for i, challenge := range authz.Challenges {
		switch challenge.Type {
		case core.ChallengeTypeSimpleHTTPS:
			authz.Challenges[i] = va.validateSimpleHTTPS(authz.Identifier, challenge)
			break
		case core.ChallengeTypeDVSNI:
			authz.Challenges[i] = va.validateDvsni(authz.Identifier, challenge)
			break
		}
	}

	va.log.Notice(fmt.Sprintf("Validations: %v", authz))

	va.RA.OnValidationUpdate(authz)
}

func (va ValidationAuthorityImpl) UpdateValidations(authz core.Authorization) error {
	go va.validate(authz)
	return nil
}
