// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package boulder

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
	"log"
)

// Set this to true when testing locally, false otherwise.
const UseLocalhost = true

type ValidationAuthorityImpl struct {
	RA RegistrationAuthority
}

func NewValidationAuthorityImpl() ValidationAuthorityImpl {
	return ValidationAuthorityImpl{}
}

// Challenge factories

func SimpleHTTPSChallenge() Challenge {
	return Challenge{
		Status: StatusPending,
		Token:  newToken(),
	}
}

func DvsniChallenge() Challenge {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	return Challenge{
		Status: StatusPending,
		R:      randomString(32),
		Nonce:  hex.EncodeToString(nonce),
	}
}

// Validation methods

func (va ValidationAuthorityImpl) validateSimpleHTTPS(authz Authorization) (challenge Challenge) {
	log.Println("SimpleHTTPS validation requested for", authz.Identifier)
	if authz.Identifier.Type != IdentifierDNS {
		log.Println("Invalid identifier type", authz.Identifier.Type)
		challenge.Status = StatusInvalid
		return
	}
	identifier := authz.Identifier.Value


	challenge, ok := authz.Challenges[ChallengeTypeSimpleHTTPS]
	if !ok {
		challenge.Status = StatusInvalid
		return
	}

	if len(challenge.Path) == 0 {
		challenge.Status = StatusInvalid
		return
	}

	// Make a connection with SNI = nonceName
	url := fmt.Sprintf("https://%s/.well-known/acme-challenge/%s",
											 identifier, challenge.Path)
	if (UseLocalhost) {
		url = fmt.Sprintf("http://localhost:5001/.well-known/acme-challenge/%s", challenge.Path)
	}
	log.Println("Fetching url", url)
	httpRequest, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Println("Error fetching", url, err)
		challenge.Status = StatusInvalid
		return
	}

	httpRequest.Host = identifier
	tr := &http.Transport{
		// We are talking to a client that does not yet have a certificate,
		// so we accept a temporary, invalid one.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		// We don't expect to make multiple requests to a client, so close
		// connection immediately.
		DisableKeepAlives: true,
	}
	client := http.Client{
		Timeout: 5 * time.Second,
		Transport: tr,
	}
	httpResponse, err := client.Do(httpRequest)

	if err == nil && httpResponse.StatusCode == 200 {
		// Read body & test
		body, err := ioutil.ReadAll(httpResponse.Body)
		if err != nil {
			challenge.Status = StatusInvalid
			return
		}

		if subtle.ConstantTimeCompare(body, []byte(challenge.Token)) == 1 {
			challenge.Status = StatusValid
			return
		}
	} else if err != nil {
		log.Println("Error fetching", url, err)
	} else if httpResponse.StatusCode != 200 {
		log.Println("Bad status code for", url, httpResponse.StatusCode)
	}

	challenge.Status = StatusInvalid
	return
}

func (va ValidationAuthorityImpl) validateDvsni(authz Authorization) (challenge Challenge) {
	log.Println("DVSNI validation requested for", authz.Identifier)
	challenge, ok := authz.Challenges[ChallengeTypeDVSNI]
	if authz.Identifier.Type != IdentifierDNS {
		log.Println("Invalid identifier type", authz.Identifier.Type)
		challenge.Status = StatusInvalid
		return
	}
	identifier := authz.Identifier.Value

	if !ok {
		challenge.Status = StatusInvalid
		return
	}

	const DVSNI_SUFFIX = ".acme.invalid"
	nonceName := challenge.Nonce + DVSNI_SUFFIX

	R, err := b64dec(challenge.R)
	if err != nil {
		challenge.Status = StatusInvalid
		return
	}
	S, err := b64dec(challenge.S)
	if err != nil {
		challenge.Status = StatusInvalid
		return
	}
	RS := append(R, S...)

	sha := sha256.New()
	sha.Write(RS)
	z := make([]byte, sha.Size())
	sha.Sum(z)
	zName := hex.EncodeToString(z)

	// Make a connection with SNI = nonceName
	hostPort := identifier + ":443"
	if (UseLocalhost) {
		hostPort = "localhost:5001"
	}
	conn, err := tls.Dial("tcp", hostPort, &tls.Config{
		ServerName:         nonceName,
		InsecureSkipVerify: true,
	})

	if err != nil {
		challenge.Status = StatusInvalid
		return
	}

	// Check that zName is a dNSName SAN in the server's certificate
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		challenge.Status = StatusInvalid
		return
	}
	for _, name := range certs[0].DNSNames {
		if name == zName {
			challenge.Status = StatusValid
			return
		}
	}

	challenge.Status = StatusInvalid
	return
}

// Overall validation process

func (va ValidationAuthorityImpl) validate(authz Authorization) {
	// Select the first supported validation method
	// XXX: Remove the "break" lines to process all supported validations
	for i := range authz.Challenges {
		switch i {
		case "simpleHttps":
			authz.Challenges[i] = va.validateSimpleHTTPS(authz)
			break
		case "dvsni":
			authz.Challenges[i] = va.validateDvsni(authz)
			break
		}
	}

	va.RA.OnValidationUpdate(authz)
}

func (va ValidationAuthorityImpl) UpdateValidations(authz Authorization) error {
	go va.validate(authz)
	return nil
}
